package main

import "testing"

// TestOfflineCurveFixtures keeps each expected Go acceptance and final key anchored.
func TestOfflineCurveFixtures(t *testing.T) {
	cases, err := offlineCurveFixtures()
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 52 {
		t.Fatalf("got %d curve cases", len(cases))
	}
}
