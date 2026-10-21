package main

import (
	"bytes"
	"testing"
)

// TestOfflineShapes exercises the pinned parser for every original shape control.
func TestOfflineShapes(t *testing.T) {
	fixtures, err := offlineShapes()
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtures) != 153 {
		t.Fatalf("missing shape controls: %d", len(fixtures))
	}
	repeat, err := offlineShapes()
	if err != nil || !bytes.Equal(offlineEncode(fixtures), offlineEncode(repeat)) {
		t.Fatal("shape fixture generation changed between runs")
	}
	counts := map[string]int{}
	names := map[string]bool{}
	for _, fixture := range fixtures {
		if names[fixture.Name] {
			t.Fatalf("duplicate case %s", fixture.Name)
		}
		names[fixture.Name] = true
		counts[fixture.Group]++
	}
	if counts["chain"] != 24 || counts["header"] != 129 {
		t.Fatal("shape group inventory changed")
	}
	t.Logf("%d shape cases: %v", len(fixtures), counts)
}
