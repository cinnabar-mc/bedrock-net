// Command bench-compare joins Go `testing.B` results with criterion estimates
// and fails when a Rust path is slower than its Go counterpart beyond a margin.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	var goFiles, criterionDirs listFlag
	flag.Var(&goFiles, "go", "`go test -bench -benchmem` output file, or - for stdin (repeatable)")
	flag.Var(&criterionDirs, "criterion", "criterion output directory (repeatable; default target/criterion)")
	margin := flag.Float64("margin", 5, "percent by which Rust may be slower than Go before failing")
	strictPairs := flag.Bool("strict-pairs", false, "also fail when a benchmark has no counterpart")
	flag.Parse()
	if len(goFiles) == 0 {
		fmt.Fprintln(os.Stderr, "bench-compare: at least one --go input is required")
		os.Exit(2)
	}
	if len(criterionDirs) == 0 {
		criterionDirs = listFlag{filepath.Join("target", "criterion")}
	}

	goResults := map[string]*goResult{}
	for _, path := range goFiles {
		if err := readGoFile(path, goResults); err != nil {
			fmt.Fprintln(os.Stderr, "bench-compare:", err)
			os.Exit(2)
		}
	}
	rustResults := map[string]rustResult{}
	for _, dir := range criterionDirs {
		if err := readCriterion(dir, rustResults); err != nil {
			fmt.Fprintln(os.Stderr, "bench-compare:", err)
			os.Exit(2)
		}
	}

	rows := join(goResults, rustResults, *margin)
	writeTable(os.Stdout, rows, *margin)
	if failed(rows, *strictPairs) {
		os.Exit(1)
	}
}

// goResult accumulates repeated runs (`-count`) of one benchmark.
type goResult struct {
	ns, bytes, allocs, mbps []float64
}

type rustResult struct {
	ns    float64
	bytes float64 // throughput bytes per iteration; 0 when not declared
}

// benchLine matches one result line; the metric list is parsed separately.
var benchLine = regexp.MustCompile(`^Benchmark(\S+)\s+\d+\s+(.*)$`)

// readGoFile parses `go test -bench` text, stripping the shared `-N` GOMAXPROCS suffix.
func readGoFile(path string, out map[string]*goResult) error {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}
	return parseGo(r, out)
}

var procsSuffix = regexp.MustCompile(`-(\d+)$`)

func parseGo(r io.Reader, out map[string]*goResult) error {
	type parsed struct {
		name    string
		metrics map[string]float64
	}
	var lines []parsed
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		m := benchLine.FindStringSubmatch(strings.TrimSpace(scanner.Text()))
		if m == nil {
			continue
		}
		fields := strings.Fields(m[2])
		metrics := map[string]float64{}
		for i := 0; i+1 < len(fields); i += 2 {
			v, err := strconv.ParseFloat(fields[i], 64)
			if err != nil {
				break
			}
			metrics[fields[i+1]] = v
		}
		if _, ok := metrics["ns/op"]; !ok {
			continue
		}
		lines = append(lines, parsed{m[1], metrics})
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	// Go appends the same -GOMAXPROCS suffix to every name in a run and none
	// when GOMAXPROCS is 1, so strip a suffix only when every line shares it.
	suffix := ""
	for i, l := range lines {
		m := procsSuffix.FindString(l.name)
		if i == 0 {
			suffix = m
		} else if m != suffix {
			suffix = ""
			break
		}
	}
	for _, l := range lines {
		name := strings.TrimSuffix(l.name, suffix)
		res := out[key(name)]
		if res == nil {
			res = &goResult{}
			out[key(name)] = res
		}
		res.ns = append(res.ns, l.metrics["ns/op"])
		if v, ok := l.metrics["B/op"]; ok {
			res.bytes = append(res.bytes, v)
		}
		if v, ok := l.metrics["allocs/op"]; ok {
			res.allocs = append(res.allocs, v)
		}
		if v, ok := l.metrics["MB/s"]; ok {
			res.mbps = append(res.mbps, v)
		}
	}
	return nil
}

type criterionBenchmark struct {
	FullID     string `json:"full_id"`
	Throughput *struct {
		Bytes        *float64 `json:"Bytes"`
		BytesDecimal *float64 `json:"BytesDecimal"`
	} `json:"throughput"`
}

type estimate struct {
	PointEstimate float64 `json:"point_estimate"`
}

type criterionEstimates struct {
	Mean  estimate  `json:"mean"`
	Slope *estimate `json:"slope"`
}

// readCriterion loads every `new/benchmark.json` + `new/estimates.json` pair under dir.
func readCriterion(dir string, out map[string]rustResult) error {
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != "benchmark.json" || filepath.Base(filepath.Dir(path)) != "new" {
			return nil
		}
		var bench criterionBenchmark
		if err := readJSON(path, &bench); err != nil {
			return err
		}
		var est criterionEstimates
		if err := readJSON(filepath.Join(filepath.Dir(path), "estimates.json"), &est); err != nil {
			return err
		}
		ns := est.Mean.PointEstimate
		if est.Slope != nil {
			ns = est.Slope.PointEstimate
		}
		res := rustResult{ns: ns}
		if t := bench.Throughput; t != nil {
			if t.Bytes != nil {
				res.bytes = *t.Bytes
			} else if t.BytesDecimal != nil {
				res.bytes = *t.BytesDecimal
			}
		}
		out[key(bench.FullID)] = res
		return nil
	})
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// key compares names case-insensitively, so criterion group `batch` matches `BenchmarkBatch`.
func key(name string) string { return strings.ToLower(name) }

type row struct {
	path              string
	goNs, rustNs      float64 // NaN when absent
	goBytes, goAllocs float64
	goMBps, rustMBps  float64
	status            string
}

const (
	statusOK       = "ok"
	statusFaster   = "faster"
	statusSlower   = "slower"
	statusGoOnly   = "go only"
	statusRustOnly = "rust only"
)

func join(goResults map[string]*goResult, rustResults map[string]rustResult, margin float64) []row {
	names := map[string]bool{}
	for k := range goResults {
		names[k] = true
	}
	for k := range rustResults {
		names[k] = true
	}
	var rows []row
	for name := range names {
		r := row{path: name, goNs: math.NaN(), rustNs: math.NaN(), goBytes: math.NaN(), goAllocs: math.NaN(), goMBps: math.NaN(), rustMBps: math.NaN()}
		g, hasGo := goResults[name]
		rr, hasRust := rustResults[name]
		if hasGo {
			r.goNs = median(g.ns)
			r.goBytes = median(g.bytes)
			r.goAllocs = median(g.allocs)
			r.goMBps = median(g.mbps)
		}
		if hasRust {
			r.rustNs = rr.ns
			if rr.bytes > 0 && rr.ns > 0 {
				r.rustMBps = rr.bytes / rr.ns * 1e3 // bytes/ns -> MB/s (10^6 bytes, as Go reports)
			}
		}
		switch {
		case !hasRust:
			r.status = statusGoOnly
		case !hasGo:
			r.status = statusRustOnly
		case r.rustNs > r.goNs*(1+margin/100):
			r.status = statusSlower
		case r.rustNs < r.goNs*(1-margin/100):
			r.status = statusFaster
		default:
			r.status = statusOK
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].path < rows[j].path })
	return rows
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return math.NaN()
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

func writeTable(w io.Writer, rows []row, margin float64) {
	fmt.Fprintf(w, "| Path | Go ns/op | Rust ns/op | Rust/Go | Go MB/s | Rust MB/s | Go B/op | Go allocs/op | Status (±%g%%) |\n", margin)
	fmt.Fprintln(w, "|---|---:|---:|---:|---:|---:|---:|---:|---|")
	for _, r := range rows {
		ratio := math.NaN()
		if !math.IsNaN(r.goNs) && !math.IsNaN(r.rustNs) && r.goNs > 0 {
			ratio = r.rustNs / r.goNs
		}
		status := r.status
		if status == statusSlower {
			status = "**slower**"
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			r.path, num(r.goNs), num(r.rustNs), fixed(ratio, 2), fixed(r.goMBps, 1), fixed(r.rustMBps, 1),
			fixed(r.goBytes, 0), fixed(r.goAllocs, 0), status)
	}
}

func num(v float64) string {
	switch {
	case math.IsNaN(v):
		return "—"
	case v >= 100:
		return strconv.FormatFloat(math.Round(v), 'f', 0, 64)
	default:
		return strconv.FormatFloat(v, 'f', 2, 64)
	}
}

func fixed(v float64, prec int) string {
	if math.IsNaN(v) {
		return "—"
	}
	return strconv.FormatFloat(v, 'f', prec, 64)
}

func failed(rows []row, strictPairs bool) bool {
	for _, r := range rows {
		if r.status == statusSlower || (strictPairs && (r.status == statusGoOnly || r.status == statusRustOnly)) {
			return true
		}
	}
	return false
}
