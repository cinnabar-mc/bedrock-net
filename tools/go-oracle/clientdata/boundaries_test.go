// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package clientdata

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
)

// TestNativeClientDataStringBoundaries checks the shared tokens against the original decoder.
func TestNativeClientDataStringBoundaries(t *testing.T) {
	data, err := os.ReadFile("../../../tests/fixtures/native-client-data-string-boundaries.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name     string  `json:"name"`
		Token    string  `json:"token"`
		Accepted bool    `json:"accepted"`
		Decoded  *string `json:"decoded"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			var client login.ClientData
			object := []byte(`{"DeviceModel":"before","devicemodel":` + test.Token + `,"DeviceModel":null,"Unknown":1e999}`)
			err := json.Unmarshal(object, &client)
			if (err == nil) != test.Accepted {
				t.Fatalf("actual Go string admission = %v, want %v", err == nil, test.Accepted)
			}
			if !test.Accepted {
				return
			}
			wanted := "before"
			if test.Decoded != nil {
				wanted = *test.Decoded
			}
			if client.DeviceModel != wanted || string(client.ExtraData["Unknown"]) != "1e999" {
				t.Fatal("actual Go scalar or opaque value differs from the shared boundary")
			}
			if test.Decoded != nil {
				var keyed login.ClientData
				if err := json.Unmarshal([]byte(`{`+test.Token+`:1e999}`), &keyed); err != nil {
					t.Fatal(err)
				}
				if string(keyed.ExtraData[*test.Decoded]) != "1e999" {
					t.Fatal("actual Go object-key decoding or opaque value changed")
				}
			}
		})
	}
}

// TestNativeClientDataLocaleBoundaries checks the original complete title metadata validator.
func TestNativeClientDataLocaleBoundaries(t *testing.T) {
	data, err := os.ReadFile("../../../tests/fixtures/native-client-data-locale-boundaries.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Locale   string `json:"locale"`
		Accepted bool   `json:"accepted"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, test := range cases {
		t.Run(test.Locale, func(t *testing.T) {
			client := login.ClientData{
				GameVersion: "1.26.50", DeviceOS: 1, LanguageCode: test.Locale,
				ThirdPartyName: "Fixture", SkinID: "fixture",
			}
			if err := client.Validate(); (err == nil) != test.Accepted {
				t.Fatalf("actual Go metadata admission = %v, want %v", err == nil, test.Accepted)
			}
		})
	}
}
