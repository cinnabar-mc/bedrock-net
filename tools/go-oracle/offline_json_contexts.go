// Synthetic JSON contexts for the pinned Login parser's typed and generic decoders.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
)

type offlineJSONContext struct {
	Name     string `json:"name"`
	Context  string `json:"context"`
	Request  []byte `json:"request"`
	Accepted bool   `json:"accepted"`
}

// offlineJSONMember appends exact synthetic JSON, including intentionally malformed values.
func offlineJSONMember(object []byte, name, value string) []byte {
	prefix := string(object[:len(object)-1])
	if len(object) > 2 {
		prefix += ","
	}
	return []byte(prefix + string(offlineEncode(name)) + ":" + value + "}")
}

// offlineJSONFrame bypasses JSON marshaling so deep values reach their actual decoding context.
func offlineJSONFrame(envelope []byte, client string) []byte {
	var out bytes.Buffer
	for _, part := range [][]byte{envelope, []byte(client)} {
		if err := binary.Write(&out, binary.LittleEndian, int32(len(part))); err != nil {
			panic(err)
		}
		out.Write(part)
	}
	return out.Bytes()
}

// offlineJSONContexts signs raw bytes and anchors every decision to the actual Go Login parser.
func offlineJSONContexts() ([]offlineJSONContext, error) {
	key := offlineKey(7)
	public := login.MarshalPublicKey(&key.PublicKey)
	header := offlineEncode(map[string]any{"alg": "ES384", "x5u": public})
	identity := offlineEncode(map[string]any{"cpk": public, "xname": "TokenName"})
	legacy := offlineEncode(map[string]any{"extraData": map[string]any{"displayName": "TokenName"}})
	metadata := offlineEncode(map[string]any{"DeviceOS": 1, "GameVersion": "1.26.51", "LanguageCode": "en_US", "SkinId": "synthetic", "ThirdPartyName": "MetadataName", "ServerAddress": "127.0.0.1:19132"})
	// offlineShapeToken uses a fixed fixture-only nonce and independently verifies each signature.
	token := offlineShapeToken(key, header, identity)
	client := offlineShapeToken(key, header, metadata)
	envelope := offlineEncode(map[string]any{"Token": token})
	chain := offlineEncode(map[string]any{"chain": []string{offlineShapeToken(key, header, legacy)}})
	rows := []struct {
		name, value string
		genericBad  bool
		depth       int
	}{
		{"null", `null`, false, 0},
		{"canonical", `{"same":1}`, false, 0},
		{"nested_duplicate", `{"same":1,"same":2}`, true, 0},
		{"escaped_duplicate", `{"same":1,"\u0073ame":2}`, true, 0},
		{"surrogate_key", `{"\ud800":1}`, false, 0},
		{"surrogate_duplicate", `{"\ud800":1,"\ufffd":2}`, true, 0},
		{"case_distinct", `{"same":1,"Same":2}`, false, 0},
		{"separate_objects", `[{"same":1},{"same":2}]`, false, 0},
		{"string_delimiters", `{"same":"[{}]\\\""}`, false, 0},
		{"overflow", `1e400`, true, 0},
		{"negative_overflow", `-1e400`, true, 0},
		{"underflow", `1e-400`, false, 0},
		{"malformed", `{"same":}`, true, -1},
	}
	for _, depth := range []int{9999, 10000, 15000} {
		rows = append(rows, struct {
			name, value string
			genericBad  bool
			depth       int
		}{fmt.Sprintf("depth_%d", depth), strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth), false, depth})
	}
	var cases []offlineJSONContext
	for _, row := range rows {
		for _, context := range []string{"modern", "legacy", "header", "metadata", "outer", "certificate", "jwk", "geometry"} {
			outer, signedClient := envelope, client
			generic := context == "legacy" || context == "header" || context == "metadata"
			standard := context == "metadata" || context == "outer" || context == "certificate" || context == "geometry"
			mapOverflow := context == "geometry" && (row.value == "1e400" || row.value == "-1e400")
			want := row.depth >= 0 && !(generic && row.genericBad) && !mapOverflow && !(standard && row.depth >= 10000)
			switch context {
			case "modern":
				outer = offlineEncode(map[string]any{"Token": offlineShapeToken(key, header, offlineJSONMember(identity, "unknown", row.value))})
			case "legacy":
				outer = offlineEncode(map[string]any{"chain": []string{offlineShapeToken(key, header, offlineJSONMember(legacy, "unknown", row.value))}})
			case "header":
				outer = offlineEncode(map[string]any{"Token": offlineShapeToken(key, offlineJSONMember(header, "unknown", row.value), identity)})
			case "metadata":
				signedClient = offlineShapeToken(key, header, offlineJSONMember(metadata, "unknown", row.value))
			case "geometry":
				geometry := base64.StdEncoding.EncodeToString(offlineJSONMember([]byte(`{}`), "unknown", row.value))
				signedClient = offlineShapeToken(key, header, offlineJSONMember(metadata, "SkinGeometryData", string(offlineEncode(geometry))))
			case "outer":
				outer = offlineJSONMember(envelope, "unknown", row.value)
			case "certificate":
				outer = offlineEncode(map[string]any{"Certificate": string(offlineJSONMember(chain, "unknown", row.value))})
			case "jwk":
				jwk := offlineJSONMember([]byte(`{"kty":"OKP","crv":"Ed25519","x":"AQ"}`), "unknown", row.value)
				outer = offlineEncode(map[string]any{"Token": offlineShapeToken(key, offlineJSONMember(header, "jwk", string(jwk)), identity)})
			}
			request := offlineJSONFrame(outer, signedClient)
			id, _, auth, err := login.Parse(request, nil)
			if (err == nil) != want || (want && (auth.XBOXLiveAuthenticated || id.DisplayName != "MetadataName")) {
				return nil, fmt.Errorf("%s/%s: want %v, got %v", context, row.name, want, err)
			}
			cases = append(cases, offlineJSONContext{row.name, context, request, want})
		}
	}
	return cases, nil
}
