package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture writes Go benchmark text and criterion results; rust maps full_id to ns.
func fixture(t *testing.T, goText string, rust map[string]float64) (string, string) {
	t.Helper()
	dir := t.TempDir()
	goFile := filepath.Join(dir, "go.txt")
	if err := os.WriteFile(goFile, []byte(goText), 0o644); err != nil {
		t.Fatal(err)
	}
	criterion := filepath.Join(dir, "criterion")
	i := 0
	for id, ns := range rust {
		out := filepath.Join(criterion, fmt.Sprint(i), "new")
		i++
		if err := os.MkdirAll(out, 0o755); err != nil {
			t.Fatal(err)
		}
		bench, _ := json.Marshal(map[string]any{"full_id": id, "throughput": map[string]float64{"Bytes": 64}})
		est, _ := json.Marshal(map[string]any{"mean": map[string]float64{"point_estimate": ns}, "slope": nil})
		if err := os.WriteFile(filepath.Join(out, "benchmark.json"), bench, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, "estimates.json"), est, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return goFile, criterion
}

// compressionFixture adds a size record bound to the fixture's current estimates.
func compressionFixture(t *testing.T, goText, id string, size any) (string, string, string) {
	t.Helper()
	goFile, criterion := fixture(t, goText, map[string]float64{id: 1})
	out := filepath.Join(criterion, "0", "new")
	if size != nil {
		estimates, err := os.ReadFile(filepath.Join(out, "estimates.json"))
		if err != nil {
			t.Fatal(err)
		}
		record, err := json.Marshal(map[string]any{
			"full_id": id, "wire_bytes": size,
			"estimates_sha256": fmt.Sprintf("%x", sha256.Sum256(estimates)),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, "wire-size.json"), record, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return goFile, criterion, out
}

func TestCompressionSizeGuard(t *testing.T) {
	for group, allowance := range map[string]int{"Flate": 5, "Snappy": 50} {
		for _, op := range []string{"compress", "decompress"} {
			id := group + "/" + op + "_small64"
			for _, tc := range []struct {
				name string
				size int
				want int
			}{
				{"smaller", 900, 0},
				{"equal", 1000, 0},
				{"exact allowance", 1000 + allowance, 0},
				{"one byte beyond", 1001 + allowance, exitSlower},
				{"bandwidth regression despite faster timing", 1100, exitSlower},
			} {
				t.Run(id+"/"+tc.name, func(t *testing.T) {
					goText := fmt.Sprintf("Benchmark%s-4 10 100 ns/op 1000 wire-B/op\n", id)
					goFile, criterion, _ := compressionFixture(t, goText, id, tc.size)
					code, report := run([]string{goFile}, []string{criterion}, nil, 4, 1000)
					if code != tc.want {
						t.Fatalf("exit %d, want %d: %v", code, tc.want, report.problems)
					}
					want := fmt.Sprintf("| %s | 1000 | %d |", key(id), tc.size)
					if !strings.Contains(report.table, want) {
						t.Fatalf("size table lacks %q: %s", want, report.table)
					}
					if tc.want != 0 && !strings.Contains(strings.Join(report.problems, " "), "wire bytes") {
						t.Fatalf("missing size failure: %v", report.problems)
					}
				})
			}
		}
	}
}

func TestCompressionSizesFailClosed(t *testing.T) {
	const id = "Flate/compress_small64"
	for _, tc := range []struct {
		name   string
		metric string
		rust   any
		repeat string
	}{
		{"Go missing", "", 1000, ""},
		{"Go zero", "0 wire-B/op", 1000, ""},
		{"Go negative", "-1 wire-B/op", 1000, ""},
		{"Go fractional", "1.5 wire-B/op", 1000, ""},
		{"Go nonfinite", "NaN wire-B/op", 1000, ""},
		{"Go infinity", "+Inf wire-B/op", 1000, ""},
		{"Go malformed", "bad wire-B/op", 1000, ""},
		{"Go duplicate", "1000 wire-B/op 1000 wire-B/op", 1000, ""},
		{"Go changed repeat", "1000 wire-B/op", 1000, "1001 wire-B/op"},
		{"Go missing repeat", "1000 wire-B/op", 1000, " "},
		{"Rust missing", "1000 wire-B/op", nil, ""},
		{"Rust zero", "1000 wire-B/op", 0, ""},
		{"Rust negative", "1000 wire-B/op", -1, ""},
		{"Rust fractional", "1000 wire-B/op", 1.5, ""},
		{"Rust nonnumeric", "1000 wire-B/op", "NaN", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			goText := fmt.Sprintf("Benchmark%s-4 10 100 ns/op %s\n", id, tc.metric)
			if tc.repeat != "" {
				goText += fmt.Sprintf("Benchmark%s-4 10 50 ns/op %s\n", id, tc.repeat)
			}
			goFile, criterion, _ := compressionFixture(t, goText, id, tc.rust)
			code, report := run([]string{goFile}, []string{criterion}, nil, 4, 1000)
			if code != exitBadInput {
				t.Fatalf("exit %d, want malformed input: %v", code, report.problems)
			}
		})
	}
}

func TestCompressionSidecarBinding(t *testing.T) {
	const id = "Snappy/decompress_chunk50k"
	for _, name := range []string{"stale estimates", "wrong full_id", "invalid JSON", "nonfinite JSON", "old base only", "duplicate result"} {
		t.Run(name, func(t *testing.T) {
			goFile, criterion, out := compressionFixture(t, "Benchmark"+id+"-4 10 100 ns/op 1000 wire-B/op\n", id, 1000)
			path := filepath.Join(out, "wire-size.json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			dirs := []string{criterion}
			switch name {
			case "stale estimates":
				path = filepath.Join(out, "estimates.json")
				data = []byte(`{"mean":{"point_estimate":2}}`)
			case "wrong full_id":
				data = []byte(strings.ReplaceAll(string(data), id, "Flate/compress_other"))
			case "invalid JSON":
				data = []byte("{")
			case "nonfinite JSON":
				data = []byte(strings.ReplaceAll(string(data), `"wire_bytes":1000`, `"wire_bytes":NaN`))
			case "old base only":
				if err := os.Mkdir(filepath.Join(out, "..", "base"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path, filepath.Join(out, "..", "base", "wire-size.json")); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(out, "..", "base", "wire-size.json")
			case "duplicate result":
				dirs = append(dirs, criterion)
			}
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatal(err)
			}
			code, report := run([]string{goFile}, dirs, nil, 4, 1000)
			if code != exitBadInput {
				t.Fatalf("exit %d, want malformed input: %v", code, report.problems)
			}
		})
	}
}

func TestValidWireSize(t *testing.T) {
	for _, size := range []float64{0, -1, 0.5, math.NaN(), math.Inf(1), math.Inf(-1), 1 << 54} {
		if validWireSize(size) {
			t.Fatalf("accepted invalid wire size %v", size)
		}
	}
}

func TestGoWireRepeats(t *testing.T) {
	const line = "BenchmarkSnappy/compress_small64-4 10 100 ns/op 1000 wire-B/op\n"
	goFile, criterion, _ := compressionFixture(t, line+line, "Snappy/compress_small64", 1000)
	code, report := run([]string{goFile}, []string{criterion}, nil, 4, 5)
	if code != 0 {
		t.Fatalf("consistent repeats rejected: %v", report.problems)
	}
}

func TestEncoderDecoderSizeConsistency(t *testing.T) {
	for _, side := range []string{"Go", "Rust"} {
		t.Run(side, func(t *testing.T) {
			goResults := map[string]*goResult{
				"flate/compress_small64": {wire: 1000}, "flate/decompress_small64": {wire: 1000},
			}
			rustResults := map[string]rustResult{
				"flate/compress_small64": {wire: 999}, "flate/decompress_small64": {wire: 999},
			}
			if err := consistentWireSizes(goResults, rustResults); err != nil {
				t.Fatal(err)
			}
			if side == "Go" {
				goResults["flate/decompress_small64"].wire++
			} else {
				rustResults["flate/decompress_small64"] = rustResult{wire: 1000}
			}
			if err := consistentWireSizes(goResults, rustResults); err == nil || !strings.Contains(err.Error(), side) {
				t.Fatalf("inconsistent %s sizes: %v", side, err)
			}
		})
	}
}

func TestCriterionOutputRoot(t *testing.T) {
	t.Setenv("CARGO_TARGET_DIR", "custom-target")
	t.Setenv("CRITERION_HOME", "custom-criterion")
	if got := defaultCriterionDir(); got != "custom-criterion" {
		t.Fatalf("CRITERION_HOME root = %s", got)
	}
	if err := os.Unsetenv("CRITERION_HOME"); err != nil {
		t.Fatal(err)
	}
	if got := defaultCriterionDir(); got != filepath.Join("custom-target", "criterion") {
		t.Fatalf("CARGO_TARGET_DIR root = %s", got)
	}
	goFile, criterion, _ := compressionFixture(t, "BenchmarkFlate/compress_small64-4 10 100 ns/op 1000 wire-B/op\n", "Flate/compress_small64", 1000)
	t.Setenv("CRITERION_HOME", criterion)
	code, report := run([]string{goFile}, nil, nil, 4, 5)
	if code != 0 {
		t.Fatalf("default output root rejected: %v", report.problems)
	}
}

func TestExitCodes(t *testing.T) {
	cases := []struct {
		name     string
		goText   string
		rust     map[string]float64
		procs    int
		oneSided []string
		want     int
	}{
		{
			name:   "paired and within margin",
			goText: "BenchmarkBatch/encode-4 \t 10 \t 100 ns/op\n",
			rust:   map[string]float64{"batch/encode": 104},
			procs:  4, want: 0,
		},
		{
			name:   "slower beyond margin",
			goText: "BenchmarkBatch/encode-4 \t 10 \t 100 ns/op\n",
			rust:   map[string]float64{"batch/encode": 106},
			procs:  4, want: exitSlower,
		},
		{
			// With GOMAXPROCS=1 Go adds no suffix, so a name ending in -digits stays intact.
			name:   "procs 1 keeps a numeric case name",
			goText: "BenchmarkChunk/size-1024 \t 10 \t 100 ns/op\n",
			rust:   map[string]float64{"chunk/size-1024": 100},
			procs:  1, want: 0,
		},
		{
			name:   "procs 4 strips only -4",
			goText: "BenchmarkChunk/size-1024-4 \t 10 \t 100 ns/op\n",
			rust:   map[string]float64{"chunk/size-1024": 100},
			procs:  4, want: 0,
		},
		{
			name:   "name without the stated suffix is malformed",
			goText: "BenchmarkChunk/size-1024-4 \t 10 \t 100 ns/op\n",
			rust:   map[string]float64{"chunk/size-1024": 100},
			procs:  8, want: exitBadInput,
		},
		{
			name:   "missing procs is malformed",
			goText: "BenchmarkBatch/encode \t 10 \t 100 ns/op\n",
			rust:   map[string]float64{"batch/encode": 100},
			procs:  0, want: exitBadInput,
		},
		{
			name:   "undeclared unpaired path",
			goText: "BenchmarkBatch/encode-4 \t 10 \t 100 ns/op\nBenchmarkBatch/go_only-4 \t 10 \t 5 ns/op\n",
			rust:   map[string]float64{"batch/encode": 100, "batch/rust_only": 5},
			procs:  4, want: exitUnmatched,
		},
		{
			name:     "declared one-sided paths",
			goText:   "BenchmarkBatch/encode-4 \t 10 \t 100 ns/op\nBenchmarkBatch/go_only-4 \t 10 \t 5 ns/op\n",
			rust:     map[string]float64{"batch/encode": 100, "batch/rust_only": 5},
			procs:    4,
			oneSided: []string{"Batch/go_only", "batch/rust_only"},
			want:     0,
		},
		{
			// Validation runs before timings, so a slower path cannot mask a stale declaration.
			name:     "stale declaration on a slower paired path",
			goText:   "BenchmarkBatch/encode-4 \t 10 \t 100 ns/op\n",
			rust:     map[string]float64{"batch/encode": 200},
			procs:    4,
			oneSided: []string{"batch/encode"},
			want:     exitUnmatched,
		},
		{
			name:     "declaration with no result",
			goText:   "BenchmarkBatch/encode-4 \t 10 \t 100 ns/op\n",
			rust:     map[string]float64{"batch/encode": 100},
			procs:    4,
			oneSided: []string{"batch/gone"},
			want:     exitUnmatched,
		},
		{
			name:   "empty sides",
			goText: "PASS\n",
			rust:   nil,
			procs:  4, want: exitUnmatched,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			goFile, criterion := fixture(t, tc.goText, tc.rust)
			got, report := run([]string{goFile}, []string{criterion}, tc.oneSided, tc.procs, 5)
			if got != tc.want {
				t.Fatalf("exit %d, want %d: %v", got, tc.want, report.problems)
			}
		})
	}
}

// Repeated Go runs use the median, criterion uses slope over mean, and base/ estimates are ignored.
func TestCommittedFixture(t *testing.T) {
	code, report := run([]string{filepath.Join("testdata", "go.txt")}, []string{filepath.Join("testdata", "criterion")},
		[]string{"batch/go_only", "batch/rust_only"}, 4, 5)
	if code != 0 {
		t.Fatalf("exit %d: %v", code, report.problems)
	}
	for _, want := range []string{
		"| batch/encode_flate | 1100 | 1155 | 1.05 | 58.2 | 55.4 | 512 | 2 | ok |",
		"| batch/go_only | 10.50 | — |",
		"| batch/rust_only | — | 5.00 |",
	} {
		if !strings.Contains(report.table, want) {
			t.Fatalf("table lacks %q:\n%s", want, report.table)
		}
	}
}
