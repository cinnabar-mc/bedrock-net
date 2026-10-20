// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package clientdata

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
)

// TestNativeClientDataJSONBytes checks the original byte decoder inside both base64 skin claims.
func TestNativeClientDataJSONBytes(t *testing.T) {
	data, err := os.ReadFile("../../../tests/fixtures/native-client-data-json-bytes.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name       string `json:"name"`
		Prefix     string `json:"prefix"`
		Bytes      []byte `json:"bytes"`
		Suffix     string `json:"suffix"`
		ExtraDepth *int   `json:"extra_depth"`
		Accepted   bool   `json:"accepted"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	maximum := int(nativeClientDataJSONDepth(t))
	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			prefix, suffix := test.Prefix, test.Suffix
			if test.ExtraDepth != nil {
				depth := maximum - 1 + *test.ExtraDepth
				prefix = `{"nested":` + strings.Repeat("[", depth) + `"`
				suffix = `"` + strings.Repeat("]", depth) + `}`
			}
			decoded := append([]byte(prefix), test.Bytes...)
			decoded = append(decoded, suffix...)
			encoded := base64.StdEncoding.EncodeToString(decoded)
			for _, field := range []string{"SkinGeometryData", "SkinResourcePatch"} {
				t.Run(field, func(t *testing.T) {
					object := []byte(fmt.Sprintf(
						`{"GameVersion":"1.26.50","DeviceOS":1,"LanguageCode":"en_US","ThirdPartyName":"Fixture","SkinId":"fixture","Unknown":1e999,%q:%q}`,
						field, encoded,
					))
					var client login.ClientData
					if err := json.Unmarshal(object, &client); err != nil {
						t.Fatal(err)
					}
					if string(client.ExtraData["Unknown"]) != "1e999" {
						t.Fatal("original raw unknown value changed")
					}
					if err := client.Validate(); (err == nil) != test.Accepted {
						t.Fatalf("original skin byte admission = %v, want %v", err == nil, test.Accepted)
					}
				})
			}
		})
	}
}
