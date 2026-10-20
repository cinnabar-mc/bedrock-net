package main

import (
	"bytes"
	"math"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T) []row {
	t.Helper()
	goResults := map[string]*goResult{}
	if err := readGoFile(filepath.Join("testdata", "go.txt"), goResults); err != nil {
		t.Fatal(err)
	}
	rustResults := map[string]rustResult{}
	if err := readCriterion(filepath.Join("testdata", "criterion"), rustResults); err != nil {
		t.Fatal(err)
	}
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
	if r.goBytes != 512 || r.goAllocs != 2 || math.Abs(r.rustMBps-64000/1155.0*1e3) > 1e-6 {
		t.Fatalf("paired metrics = %+v", r)
	}
	if rows[1].path != "batch/go_only" || rows[1].status != statusGoOnly {
		t.Fatalf("go-only row = %+v", rows[1])
	}
	if rows[2].path != "batch/rust_only" || rows[2].rustNs != 5 || rows[2].status != statusRustOnly {
		t.Fatalf("rust-only row = %+v", rows[2])
	}
	if failed(rows, false) || !failed(rows, true) {
		t.Fatal("unpaired rows fail only under --strict-pairs")
	}
}

// A Rust path beyond the margin fails; within it does not.
func TestMarginDecidesFailure(t *testing.T) {
	goResults := map[string]*goResult{"a": {ns: []float64{100}}}
	if failed(join(goResults, map[string]rustResult{"a": {ns: 105}}, 5), false) {
		t.Fatal("5% slower is inside a 5% margin")
	}
	if !failed(join(goResults, map[string]rustResult{"a": {ns: 106}}, 5), false) {
		t.Fatal("6% slower must fail a 5% margin")
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
