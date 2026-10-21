package main

import (
	"bytes"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"strings"
)

// admissionThumbprints checks the two digest widths through the shared signed-header anchors.
func admissionThumbprints(add func(string, string, string, bool) error) error {
	for _, slot := range []struct {
		name  string
		width int
	}{{"x5t", 20}, {"x5t#S256", 32}} {
		rest := strings.Repeat("01", slot.width-1)
		for _, row := range []struct {
			name  string
			value []byte
			want  bool
		}{
			{"empty", nil, true}, {"raw", bytes.Repeat([]byte{0xab}, slot.width), true},
			{"lower", []byte(strings.Repeat("ab", slot.width)), true},
			{"upper", []byte(strings.Repeat("AB", slot.width)), true},
			{"mixed", []byte(strings.Repeat("aB", slot.width)), true},
			{"wrapped_base64", []byte(strings.Repeat("01", slot.width)), true},
			{"plus_all", []byte(strings.Repeat("+1", slot.width)), false},
			{"plus_first", []byte("+1" + rest), false},
			{"plus_middle", []byte(strings.Repeat("01", slot.width/2) + "+1" + strings.Repeat("01", slot.width/2-1)), false},
			{"plus_last", []byte(rest + "+1"), false},
			{"minus_first", []byte("-1" + rest), false},
			{"plus_second", []byte("0+" + rest), false},
			{"nonhex", []byte("g1" + rest), false},
			{"space", []byte(" 1" + rest), false},
		} {
			jwk := offlineShapeEC(elliptic.P384())
			text := base64.RawURLEncoding.EncodeToString(row.value)
			if row.name == "wrapped_base64" {
				text = text[:2] + "\r\n" + text[2:]
			}
			jwk[slot.name] = text
			if err := add(fmt.Sprintf("thumbprint/%s/%s", slot.name, row.name), "thumbprint", `"jwk":`+string(offlineEncode(jwk)), row.want); err != nil {
				return err
			}
		}
	}
	return nil
}
