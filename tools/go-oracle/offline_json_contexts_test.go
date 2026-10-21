package main

import (
	"bytes"
	"testing"
)

// TestOfflineJSONContexts checks every context and deterministic generation without private inputs.
func TestOfflineJSONContexts(t *testing.T) {
	cases, err := offlineJSONContexts()
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 128 {
		t.Fatalf("context inventory changed: %d", len(cases))
	}
	repeat, err := offlineJSONContexts()
	if err != nil || !bytes.Equal(offlineEncode(cases), offlineEncode(repeat)) {
		t.Fatal("JSON context requests are not deterministic")
	}
	names := map[string]bool{}
	counts := map[string]int{}
	for _, row := range cases {
		name := row.Context + "/" + row.Name
		if names[name] {
			t.Fatalf("duplicate case %s", name)
		}
		names[name] = true
		counts[row.Context]++
	}
	if len(counts) != 8 {
		t.Fatal("missing JSON contexts")
	}
	for context, count := range counts {
		if count != 16 {
			t.Fatalf("%s inventory changed: %d", context, count)
		}
	}
	t.Logf("%d JSON context cases: %v", len(cases), counts)
}
