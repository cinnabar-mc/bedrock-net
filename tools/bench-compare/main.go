// Command bench-compare joins Go `testing.B` results with criterion estimates
// and checks both timing and compression wire-size parity.
//
// Exit status: 2 unreadable or malformed input, 3 missing or unpaired measurements,
// 1 a timing or wire-size regression, 0 otherwise. Inputs are validated before
// comparison, so a 1 always means a complete, paired measurement.
package main

import (
	"bufio"
	"crypto/sha256"
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

const (
	exitSlower    = 1
	exitBadInput  = 2
	exitUnmatched = 3
)

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	var goFiles, criterionDirs, oneSided listFlag
	flag.Var(&goFiles, "go", "`go test -bench -benchmem` output file, or - for stdin (repeatable)")
	flag.Var(&criterionDirs, "criterion", "criterion output directory (repeatable; default CRITERION_HOME, CARGO_TARGET_DIR/criterion, or target/criterion)")
	flag.Var(&oneSided, "one-sided", "`path` expected on only one side (repeatable); any other unpaired path fails")
	procs := flag.Int("go-procs", 0, "the -cpu value the Go benchmarks ran with (required)")
	margin := flag.Float64("margin", 5, "percent by which Rust may be slower than Go before failing")
	flag.Parse()
	code, report := run(goFiles, criterionDirs, oneSided, *procs, *margin)
	fmt.Print(report.table)
	for _, problem := range report.problems {
		fmt.Fprintln(os.Stderr, "bench-compare:", problem)
	}
	os.Exit(code)
}

type report struct {
	table    string
	problems []string
}

// run validates every input before comparing timing and compression sizes.
func run(goFiles, criterionDirs, oneSided []string, procs int, margin float64) (int, report) {
	if len(goFiles) == 0 {
		return exitBadInput, report{problems: []string{"at least one --go input is required"}}
	}
	if procs < 1 {
		return exitBadInput, report{problems: []string{"--go-procs must be the Go benchmarks' -cpu value"}}
	}
	if len(criterionDirs) == 0 {
		criterionDirs = []string{defaultCriterionDir()}
	}
	goResults := map[string]*goResult{}
	for _, path := range goFiles {
		if err := readGoFile(path, procs, goResults); err != nil {
			return exitBadInput, report{problems: []string{err.Error()}}
		}
	}
	rustResults := map[string]rustResult{}
	for _, dir := range criterionDirs {
		if err := readCriterion(dir, rustResults); err != nil {
			return exitBadInput, report{problems: []string{err.Error()}}
		}
	}
	if err := consistentWireSizes(goResults, rustResults); err != nil {
		return exitBadInput, report{problems: []string{err.Error()}}
	}
	rows := join(goResults, rustResults, margin)
	table := renderTable(rows, margin) + renderSizes(rows)
	if problems := validate(rows, goResults, rustResults, oneSided); len(problems) != 0 {
		return exitUnmatched, report{table, problems}
	}
	problems := append(slower(rows), larger(rows)...)
	if len(problems) != 0 {
		return exitSlower, report{table, problems}
	}
	return 0, report{table: table}
}

// goResult accumulates repeated runs (`-count`) of one benchmark.
type goResult struct {
	ns, bytes, allocs, mbps []float64
	wire                    float64 // identical full-frame bytes across all repeats
}

type rustResult struct {
	ns    float64
	bytes float64 // throughput bytes per iteration; 0 when not declared
	wire  float64 // full-frame bytes for compression paths
}

// defaultCriterionDir follows the explicit output root used by the batch benchmark.
func defaultCriterionDir() string {
	if dir, ok := os.LookupEnv("CRITERION_HOME"); ok {
		return filepath.Clean(dir)
	}
	if dir, ok := os.LookupEnv("CARGO_TARGET_DIR"); ok {
		return filepath.Join(dir, "criterion")
	}
	return filepath.Join("target", "criterion")
}

// compressionPath identifies both encoder outputs and decoder inputs requiring size parity.
func compressionPath(name string) bool {
	group, _, _ := strings.Cut(key(name), "/")
	return group == "flate" || group == "snappy"
}

// validWireSize accepts positive, exactly representable integer byte counts only.
func validWireSize(size float64) bool {
	return size > 0 && size <= 1<<53 && math.Trunc(size) == size
}

// consistentWireSizes requires encoder and decoder rows to describe the same input on each side.
func consistentWireSizes(goResults map[string]*goResult, rustResults map[string]rustResult) error {
	for name, g := range goResults {
		if compressionPath(name) {
			decode := strings.Replace(name, "/compress_", "/decompress_", 1)
			if d := goResults[decode]; d != nil && d.wire != g.wire {
				return fmt.Errorf("%s: Go encoder and decoder wire sizes differ", name)
			}
		}
	}
	for name, r := range rustResults {
		if compressionPath(name) {
			decode := strings.Replace(name, "/compress_", "/decompress_", 1)
			if d, ok := rustResults[decode]; ok && d.wire != r.wire {
				return fmt.Errorf("%s: Rust encoder and decoder wire sizes differ", name)
			}
		}
	}
	return nil
}

// exceedsWireAllowance compares integer bytes with a fixed 1/200 allowance, including its boundary.
func exceedsWireAllowance(goWire, rustWire float64) bool {
	return rustWire-goWire > goWire/200
}

// benchLine matches one result line; the metric list is parsed separately.
var benchLine = regexp.MustCompile(`^Benchmark(\S+)\s+\d+\s+(.*)$`)

func readGoFile(path string, procs int, out map[string]*goResult) error {
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
	if err := parseGo(r, procs, out); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// parseGo reads `go test -bench` text. Go appends `-N` to every name when GOMAXPROCS is N > 1
// and nothing when it is 1, so the caller states N and every name must carry exactly that suffix.
func parseGo(r io.Reader, procs int, out map[string]*goResult) error {
	suffix := ""
	if procs > 1 {
		suffix = "-" + strconv.Itoa(procs)
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		m := benchLine.FindStringSubmatch(strings.TrimSpace(scanner.Text()))
		if m == nil {
			continue
		}
		metrics := map[string]float64{}
		fields := strings.Fields(m[2])
		if compressionPath(m[1]) && len(fields)%2 != 0 {
			return fmt.Errorf("benchmark %q has incomplete metrics", m[1])
		}
		for i := 0; i+1 < len(fields); i += 2 {
			v, err := strconv.ParseFloat(fields[i], 64)
			if err != nil {
				if compressionPath(m[1]) {
					return fmt.Errorf("benchmark %q has invalid metrics: %w", m[1], err)
				}
				break
			}
			unit := fields[i+1]
			if _, duplicate := metrics[unit]; duplicate && unit == "wire-B/op" {
				return fmt.Errorf("benchmark %q repeats wire-B/op", m[1])
			}
			metrics[unit] = v
		}
		ns, ok := metrics["ns/op"]
		if !ok && !compressionPath(m[1]) {
			continue
		}
		if compressionPath(m[1]) && (ns <= 0 || math.IsNaN(ns) || math.IsInf(ns, 0)) {
			return fmt.Errorf("benchmark %q has missing or invalid ns/op", m[1])
		}
		name, ok := strings.CutSuffix(m[1], suffix)
		if !ok {
			return fmt.Errorf("benchmark %q lacks the -cpu suffix %q", m[1], suffix)
		}
		name = key(name)
		wire := metrics["wire-B/op"]
		if compressionPath(name) && !validWireSize(wire) {
			return fmt.Errorf("%s: missing or invalid Go wire-B/op", name)
		}
		res := out[name]
		if res == nil {
			res = &goResult{wire: wire}
			out[name] = res
		} else if compressionPath(name) && res.wire != wire {
			return fmt.Errorf("%s: Go wire-B/op changed between runs", name)
		}
		res.ns = append(res.ns, ns)
		for unit, list := range map[string]*[]float64{"B/op": &res.bytes, "allocs/op": &res.allocs, "MB/s": &res.mbps} {
			if v, ok := metrics[unit]; ok {
				*list = append(*list, v)
			}
		}
	}
	return scanner.Err()
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
// A missing directory reads as no results, which validation reports.
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
		res := rustResult{ns: est.Mean.PointEstimate}
		if est.Slope != nil {
			res.ns = est.Slope.PointEstimate
		}
		if t := bench.Throughput; t != nil {
			if t.Bytes != nil {
				res.bytes = *t.Bytes
			} else if t.BytesDecimal != nil {
				res.bytes = *t.BytesDecimal
			}
		}
		name := key(bench.FullID)
		if compressionPath(name) {
			if res.ns <= 0 || math.IsNaN(res.ns) || math.IsInf(res.ns, 0) {
				return fmt.Errorf("%s: invalid Criterion timing", name)
			}
			if _, duplicate := out[name]; duplicate {
				return fmt.Errorf("%s: duplicate Criterion compression result", name)
			}
			var size struct {
				FullID          string  `json:"full_id"`
				Wire            float64 `json:"wire_bytes"`
				EstimatesSHA256 string  `json:"estimates_sha256"`
			}
			if err := readJSON(filepath.Join(filepath.Dir(path), "wire-size.json"), &size); err != nil {
				return err
			}
			estimates, err := os.ReadFile(filepath.Join(filepath.Dir(path), "estimates.json"))
			if err != nil {
				return err
			}
			if size.FullID != bench.FullID || !validWireSize(size.Wire) || size.EstimatesSHA256 != fmt.Sprintf("%x", sha256.Sum256(estimates)) {
				return fmt.Errorf("%s: invalid or stale Criterion wire-size.json", name)
			}
			res.wire = size.Wire
		}
		out[name] = res
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
	goWire, rustWire  float64
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
			r.goNs, r.goBytes, r.goAllocs, r.goMBps = median(g.ns), median(g.bytes), median(g.allocs), median(g.mbps)
			r.goWire = g.wire
		}
		if hasRust {
			r.rustNs = rr.ns
			r.rustWire = rr.wire
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

// validate reports missing measurements: an empty side, an undeclared unpaired path, or a
// --one-sided declaration that is unknown or now has both sides. It ignores timings.
func validate(rows []row, goResults map[string]*goResult, rustResults map[string]rustResult, oneSided []string) []string {
	var problems []string
	if len(goResults) == 0 {
		problems = append(problems, "no Go benchmark results were read")
	}
	if len(rustResults) == 0 {
		problems = append(problems, "no criterion results were read")
	}
	declared := map[string]bool{}
	for _, name := range oneSided {
		declared[key(name)] = true
	}
	for _, r := range rows {
		unpaired := r.status == statusGoOnly || r.status == statusRustOnly
		switch {
		case unpaired && !declared[r.path]:
			problems = append(problems, fmt.Sprintf("%s: %s, and not declared --one-sided", r.path, r.status))
		case !unpaired && declared[r.path]:
			problems = append(problems, fmt.Sprintf("%s: declared --one-sided but has both sides", r.path))
		}
		delete(declared, r.path)
	}
	for name := range declared {
		problems = append(problems, fmt.Sprintf("%s: declared --one-sided but has no result", name))
	}
	sort.Strings(problems)
	return problems
}

// slower lists paired paths where Rust exceeds the margin; it runs only on validated input.
func slower(rows []row) []string {
	var problems []string
	for _, r := range rows {
		if r.status == statusSlower {
			problems = append(problems, r.path+": Rust is slower than Go beyond the margin")
		}
	}
	return problems
}

// larger enforces a fixed bandwidth allowance independently of the timing margin.
func larger(rows []row) []string {
	var problems []string
	for _, r := range rows {
		if compressionPath(r.path) && r.goWire > 0 && exceedsWireAllowance(r.goWire, r.rustWire) {
			problems = append(problems, r.path+": Rust wire bytes exceed Go by more than 0.5%")
		}
	}
	return problems
}

// renderSizes shows complete frame sizes separately from allocation bytes per operation.
func renderSizes(rows []row) string {
	var b strings.Builder
	for _, r := range rows {
		if !compressionPath(r.path) {
			continue
		}
		if b.Len() == 0 {
			fmt.Fprintln(&b, "\n| Compression path | Go wire B/op | Rust wire B/op | Rust/Go | Size (≤ +0.5%) |")
			fmt.Fprintln(&b, "|---|---:|---:|---:|---|")
		}
		ratio, status := math.NaN(), "missing"
		if r.goWire > 0 && r.rustWire > 0 {
			ratio, status = r.rustWire/r.goWire, "ok"
			if exceedsWireAllowance(r.goWire, r.rustWire) {
				status = "**larger**"
			}
		}
		fmt.Fprintf(&b, "| %s | %.0f | %.0f | %s | %s |\n", r.path, r.goWire, r.rustWire, fixed(ratio, 4), status)
	}
	return b.String()
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

func renderTable(rows []row, margin float64) string {
	var b strings.Builder
	fmt.Fprintf(&b, "| Path | Go ns/op | Rust ns/op | Rust/Go | Go MB/s | Rust MB/s | Go B/op | Go allocs/op | Status (±%g%%) |\n", margin)
	fmt.Fprintln(&b, "|---|---:|---:|---:|---:|---:|---:|---:|---|")
	for _, r := range rows {
		ratio := math.NaN()
		if !math.IsNaN(r.goNs) && !math.IsNaN(r.rustNs) && r.goNs > 0 {
			ratio = r.rustNs / r.goNs
		}
		status := r.status
		if status == statusSlower {
			status = "**slower**"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			r.path, num(r.goNs), num(r.rustNs), fixed(ratio, 2), fixed(r.goMBps, 1), fixed(r.rustMBps, 1),
			fixed(r.goBytes, 0), fixed(r.goAllocs, 0), status)
	}
	return b.String()
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
