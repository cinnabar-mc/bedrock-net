package main

import (
	"bytes"
	"testing"
)

// TestOfflineFixtures checks actual Parse decisions and reproducible synthetic wire bytes.
func TestOfflineFixtures(t *testing.T) {
	first, err := offlineFixtures()
	if err != nil {
		t.Fatal(err)
	}
	second, err := offlineFixtures()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 55 || !bytes.Equal(offlineEncode(first), offlineEncode(second)) {
		t.Fatal("offline fixture inventory or determinism changed")
	}
	accepted := 0
	for _, fixture := range first {
		if fixture.Accepted {
			accepted++
		}
	}
	if accepted != 28 {
		t.Fatalf("accepted %d fixtures, want 28", accepted)
	}
}
