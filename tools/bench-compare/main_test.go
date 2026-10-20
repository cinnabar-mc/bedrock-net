package main

import (
	"encoding/json"
	"fmt"
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
