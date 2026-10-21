package main

import "testing"

// TestJOSEHeaderFixtures keeps all role-specific Go decisions anchored before Rust comparison.
func TestJOSEHeaderFixtures(t *testing.T) {
	fixtures, err := joseHeaderFixtures()
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtures) != 37 {
		t.Fatalf("got %d header controls", len(fixtures))
	}
}
