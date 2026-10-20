package main

import (
	"bytes"
	"math"
	"path/filepath"
	"strings"
	"testing"
)

func loadMaps(t *testing.T) (map[string]*goResult, map[string]rustResult) {
	t.Helper()
	goResults := map[string]*goResult{}
	if err := readGoFile(filepath.Join("testdata", "go.txt"), goResults); err != nil {
		t.Fatal(err)
	}
	rustResults := map[string]rustResult{}
	if err := readCriterion(filepath.Join("testdata", "criterion"), rustResults); err != nil {
		t.Fatal(err)
	}
	return goResults, rustResults
}

func load(t *testing.T) []row {
	t.Helper()
	goResults, rustResults := loadMaps(t)
	return join(goResults, rustResults, 5)
}

// Repeated Go runs use the median, criterion uses slope over mean, and base/ estimates are ignored.
func TestJoinPairsMedianAndSlope(t *testing.T) {
	rows := load(t)
	if len(rows) != 3 {
		t.Fatalf("rows = %+v", rows)
	}
	r := rows[0]
	if r.path != "batch/encode_flate" || r.goNs != 1100 || r.rustNs != 1155 || r.status != statusOK {
		t.Fatalf("paired row = %+v", r)
	}
	if r.goBytes != 512 || r.goAllocs != 2 || math.Abs(r.rustMBps-64/1155.0*1e3) > 1e-6 {
		t.Fatalf("paired metrics = %+v", r)
	}
	if rows[1].path != "batch/go_only" || rows[1].status != statusGoOnly {
		t.Fatalf("go-only row = %+v", rows[1])
	}
	if rows[2].path != "batch/rust_only" || rows[2].rustNs != 5 || rows[2].status != statusRustOnly {
		t.Fatalf("rust-only row = %+v", rows[2])
	}
	goResults, rustResults := loadMaps(t)
	if got := check(rows, goResults, rustResults, nil); len(got) != 2 || exitCode(got) != 3 {
		t.Fatalf("undeclared unpaired rows are harness failures: %v", got)
	}
	if got := check(rows, goResults, rustResults, []string{"Batch/go_only", "batch/rust_only"}); len(got) != 0 {
		t.Fatalf("declared one-sided rows pass: %v", got)
	}
	if got := check(rows, goResults, rustResults, []string{"batch/go_only", "batch/rust_only", "batch/encode_flate", "batch/gone"}); len(got) != 2 {
		t.Fatalf("stale one-sided declarations must fail: %v", got)
	}
}

// A Rust path beyond the margin fails; within it does not.
func TestMarginDecidesFailure(t *testing.T) {
	goResults := map[string]*goResult{"a": {ns: []float64{100}}}
	for rust, fails := range map[float64]bool{105: false, 106: true} {
		rustResults := map[string]rustResult{"a": {ns: rust}}
		got := check(join(goResults, rustResults, 5), goResults, rustResults, nil)
		if want := map[bool]int{false: 0, true: 1}[fails]; exitCode(got) != want {
			t.Fatalf("Rust %v ns vs Go 100 ns at 5%%: %v", rust, got)
		}
	}
}

// A side that produced no results fails even when nothing is unpaired against it.
func TestEmptySideFails(t *testing.T) {
	goResults := map[string]*goResult{}
	rustResults := map[string]rustResult{}
	if got := check(nil, goResults, rustResults, nil); len(got) != 2 || exitCode(got) != 3 {
		t.Fatalf("empty inputs are harness failures: %v", got)
	}
}

// A name ending in -digits keeps it when GOMAXPROCS=1 omits the suffix.
func TestProcsSuffixOnlyWhenShared(t *testing.T) {
	out := map[string]*goResult{}
	in := "BenchmarkChunk/size-1024 \t 10 \t 5 ns/op\nBenchmarkChunk/size-64 \t 10 \t 3 ns/op\n"
	if err := parseGo(strings.NewReader(in), out); err != nil {
		t.Fatal(err)
	}
	if out["chunk/size-1024"] == nil || out["chunk/size-64"] == nil {
		t.Fatalf("names = %v", out)
	}
}

func TestTableMarksSlower(t *testing.T) {
	var buf bytes.Buffer
	writeTable(&buf, join(map[string]*goResult{"a": {ns: []float64{100}}}, map[string]rustResult{"a": {ns: 200}}, 5), 5)
	if !strings.Contains(buf.String(), "| a | 100 | 200 | 2.00 |") || !strings.Contains(buf.String(), "**slower**") {
		t.Fatal(buf.String())
	}
}
