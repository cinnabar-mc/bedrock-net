package main

import "testing"

// TestOfflineTimeFixtures retains both full Parse anchors and deterministic caller-time comparisons.
func TestOfflineTimeFixtures(t *testing.T) {
	cases, err := offlineTimeFixtures()
	if err != nil {
		t.Fatal(err)
	}
	anchors := 0
	for _, fixture := range cases {
		if fixture.ParseAnchor {
			anchors++
		}
	}
	if len(cases) != 117 || anchors != 72 {
		t.Fatalf("got %d cases/%d Parse anchors", len(cases), anchors)
	}
}
