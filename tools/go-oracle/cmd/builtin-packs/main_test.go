package main

import (
	"reflect"
	"testing"
)

func TestSourcePacksPreservesOrderAndNamedFields(t *testing.T) {
	source := []byte(`package minecraft
var unrelated = 1
var exemptedPacks = []exemptedResourcePack{
 {version: "second", uuid: "b"},
 {uuid: "a", version: "first"},
}`)
	packs, err := sourcePacks(source)
	if err != nil {
		t.Fatal(err)
	}
	if expected := []pack{{"b", "second"}, {"a", "first"}}; !reflect.DeepEqual(packs, expected) {
		t.Fatalf("extracted %v, want original order %v", packs, expected)
	}
}

func TestSourcePacksRejectsUnrecognizedExemptions(t *testing.T) {
	for _, declaration := range []string{
		`var somethingElse = []exemptedResourcePack{{uuid: "a", version: "1"}}`,
		`var exemptedPacks = buildExemptions()`,
		`var exemptedPacks = []exemptedResourcePack{}`,
		`var exemptedPacks = []exemptedResourcePack{{uuid: "a", version: "1", extra: true}}`,
		`var exemptedPacks = []exemptedResourcePack{{uuid: "a", uuid: "b"}}`,
		`var exemptedPacks = []exemptedResourcePack{{uuid: "a", version: currentVersion}}`,
	} {
		if _, err := sourcePacks([]byte("package minecraft\n" + declaration)); err == nil {
			t.Errorf("accepted an unrecognized exemption declaration: %s", declaration)
		}
	}
}
