package main

import (
	"bytes"
	"testing"
)

// TestJOSEAdmission checks actual Go decisions, fixture uniqueness and deterministic generation.
func TestJOSEAdmission(t *testing.T) {
	cases, err := joseAdmissionFixtures()
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 630 {
		t.Fatalf("admission inventory changed: %d", len(cases))
	}
	repeat, err := joseAdmissionFixtures()
	encoded := offlineEncode(cases)
	if err != nil || !bytes.Equal(encoded, offlineEncode(repeat)) {
		t.Fatal("admission fixture generation changed")
	}
	seen := map[string]bool{}
	counts := map[string]int{}
	for _, row := range cases {
		if seen[row.Name] {
			t.Fatalf("duplicate case %s", row.Name)
		}
		seen[row.Name] = true
		counts[row.Kind]++
	}
	if len(counts) != 3 || counts["certificate"] != 576 || counts["url"] != 26 || counts["thumbprint"] != 28 {
		t.Fatal("missing admission context")
	}
	t.Logf("%d admission rows: %v; %d encoded bytes", len(cases), counts, len(encoded))
}
