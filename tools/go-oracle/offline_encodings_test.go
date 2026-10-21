package main

import "testing"

// TestOfflineEncodingFixtures anchors compact encodings before Rust compares them.
func TestOfflineEncodingFixtures(t *testing.T) {
	cases, err := offlineEncodingFixtures()
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 33 {
		t.Fatalf("got %d encoding controls", len(cases))
	}
}
