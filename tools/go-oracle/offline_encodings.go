// Synthetic compact JWT encoding controls for the pinned Go Login parser.
package main

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
)

type offlineEncodingFixture struct {
	Name           string `json:"name"`
	Request        []byte `json:"request"`
	Legacy         []byte `json:"legacy"`
	Authenticated  []byte `json:"authenticated"`
	Server         string `json:"server"`
	Payload        []byte `json:"payload"`
	Accepted       bool   `json:"accepted"`
	LegacyAccepted bool   `json:"legacy_accepted"`
	ServerAccepted bool   `json:"server_accepted"`
}

// encodingToken signs the original bytes with a fixed public test key/nonce, never for real data.
func encodingToken(header, payload []byte, key *ecdsa.PrivateKey) string {
	input := base64.RawURLEncoding.EncodeToString(header) + "."
	var fields map[string]any
	_ = json.Unmarshal(header, &fields)
	if b64, ok := fields["b64"].(bool); ok && !b64 {
		input += string(payload)
	} else {
		input += base64.RawURLEncoding.EncodeToString(payload)
	}
	digest := sha512.Sum384([]byte(input))
	n := key.Curve.Params().N
	x, _ := key.Curve.ScalarBaseMult([]byte{13})
	r := new(big.Int).Mod(x, n)
	s := new(big.Int).Mul(r, key.D)
	s.Add(s, new(big.Int).SetBytes(digest[:])).Mul(s, new(big.Int).ModInverse(big.NewInt(13), n)).Mod(s, n)
	if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
		panic("invalid synthetic JWT signature")
	}
	raw := make([]byte, 96)
	r.FillBytes(raw[:48])
	s.FillBytes(raw[48:])
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(raw)
}

// encodingEdit changes only a compact wire representation or one signed byte for a rejection control.
func encodingEdit(token, kind string) string {
	parts := strings.Split(token, ".")
	for index, name := range []string{"header", "payload", "signature"} {
		if kind == name+"_crlf" {
			parts[index] = parts[index][:2] + "\r\n" + parts[index][2:]
		}
		if kind == name+"_padding" {
			parts[index] += "="
		}
		if kind == name+"_space" {
			parts[index] = parts[index][:2] + " " + parts[index][2:]
		}
		if kind == name+"_unused_bits" {
			alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
			part := parts[index]
			if len(part)%4 == 0 {
				panic("fixture has no unused bits")
			}
			last := strings.IndexByte(alphabet, part[len(part)-1])
			parts[index] = part[:len(part)-1] + string(alphabet[last+1])
		}
	}
	if kind == "tampered_payload" {
		raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
		parts[1] = base64.RawURLEncoding.EncodeToString(append(raw, ' '))
	}
	if kind == "tampered_signature" {
		raw, _ := base64.RawURLEncoding.DecodeString(parts[2])
		raw[0] ^= 1
		parts[2] = base64.RawURLEncoding.EncodeToString(raw)
	}
	return strings.Join(parts, ".")
}

// encodingUnpadded ensures a representation has unused low bits without changing its JSON value.
func encodingUnpadded(raw []byte) []byte {
	if len(raw)%3 == 0 {
		return append(raw, ' ')
	}
	return raw
}

// offlineEncodingFixtures anchors every expected decision and emits original synthetic payloads.
func offlineEncodingFixtures() ([]offlineEncodingFixture, error) {
	key := offlineKey(7)
	cpk := login.MarshalPublicKey(&key.PublicKey)
	// header leaves unused base64 bits available for the wire-encoding controls.
	header := func(extra string) []byte {
		return encodingUnpadded([]byte(`{"alg":"ES384","x5u":"` + cpk + `"` + extra + `}`))
	}
	client := encodingUnpadded([]byte(` {"DeviceOS":1,"GameVersion":"1.26.51","LanguageCode":"en_US","SkinId":"synthetic","ThirdPartyName":"MetadataName","ServerAddress":"127.0.0.1:19132","Nonce":"n\u006fnce"} `))
	legacy := encodingUnpadded(offlineEncode(map[string]any{"extraData": map[string]any{"XUID": "", "displayName": "LegacyName"}}))
	salt := encodingUnpadded(offlineEncode(map[string]any{"salt": base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef"))}))
	identity := offlineToken(key, "ES384", cpk, map[string]any{"cpk": cpk, "xid": "", "xname": "TokenName"})
	validClient := encodingToken(header(""), client, key)
	cases := []struct {
		name, extra string
		accepted    bool
	}{
		{"canonical", "", true},
		{"b64_number", `,"b64":17`, true},
		{"header_crlf", "", true}, {"payload_crlf", "", true}, {"signature_crlf", "", true},
		{"header_unused_bits", "", true}, {"payload_unused_bits", "", true},
		{"b64_true", `,"b64":true`, true}, {"b64_false", `,"b64":false,"crit":["b64"]`, true},
		{"b64_null", `,"b64":null`, true}, {"b64_string", `,"b64":"false"`, true},
		{"b64_array", `,"b64":[]`, true}, {"b64_object", `,"b64":{}`, true},
		{"b64_nested_duplicate", `,"b64":{"a":1,"a":2}`, false},
		{"b64_overflow", `,"b64":1e400`, false},
		{"unknown_surrogate", `,"extension":"\ud800"`, true},
		{"unknown_low_surrogate", `,"extension":"\udc00"`, true},
		{"unknown_escaped_literal", `,"extension":"\\ud800"`, true},
		{"unknown_utf8", ",\"extension\":\"\xff\"", true},
		{"unknown_incomplete_utf8", ",\"extension\":\"\xe2\x82\"", true},
		{"kid_utf8", ",\"kid\":\"\xff\"", true},
		{"x5u_utf8", "", true},
		{"raw_header_json", "", true},
		{"wrong_key", "", false}, {"tampered_payload", "", false}, {"tampered_signature", "", false},
		{"header_padding", "", false}, {"payload_padding", "", false}, {"signature_padding", "", false},
		{"header_space", "", false}, {"payload_space", "", false}, {"signature_space", "", false},
		{"unsupported_critical", `,"crit":["unknown"]`, false},
	}
	var out []offlineEncodingFixture
	for _, test := range cases {
		h := header(test.extra)
		if test.name == "raw_header_json" {
			h = []byte(" { \"x5u\" : \"" + cpk + "\", \"a\\u006cg\" : \"ES384\", \"extension\" : \"\\ud800\" }\n")
		}
		if test.name == "x5u_utf8" {
			h = []byte(`{"alg":"ES384","x5u":"` + cpk + "\xff" + `"}`)
		}
		signer := key
		if test.name == "wrong_key" {
			signer = offlineKey(9)
		}
		rawClient := encodingEdit(encodingToken(h, client, signer), test.name)
		rawLegacy := encodingEdit(encodingToken(h, legacy, signer), test.name)
		rawServer := encodingEdit(encodingToken(h, salt, signer), test.name)
		f := offlineEncodingFixture{Name: test.name, Request: offlineFrame(map[string]any{"Token": identity}, rawClient), Legacy: offlineFrame(map[string]any{"chain": []string{rawLegacy}}, validClient), Authenticated: offlineFrame(map[string]any{"AuthenticationType": 0, "Token": "synthetic-provider"}, rawClient), Server: rawServer, Payload: client, Accepted: test.accepted}
		f.LegacyAccepted = test.accepted && test.name != "x5u_utf8"
		f.ServerAccepted = f.LegacyAccepted
		for role, request := range map[string][]byte{"metadata": f.Request, "legacy": f.Legacy} {
			identity, data, auth, err := login.Parse(request, nil)
			expected := test.accepted
			if role == "legacy" {
				expected = f.LegacyAccepted
			}
			if (err == nil) != expected {
				return nil, fmt.Errorf("JWT encoding %s/%s changed: %v", test.name, role, err)
			}
			if err == nil && (identity.DisplayName != "MetadataName" || auth.XBOXLiveAuthenticated || !auth.PublicKey.Equal(&key.PublicKey) || data.Nonce != "nonce") {
				return nil, fmt.Errorf("JWT encoding result %s/%s changed", test.name, role)
			}
		}
		tok, err := jwt.ParseSigned(rawServer, []jose.SignatureAlgorithm{jose.ES384})
		var claims struct {
			Salt string `json:"salt"`
		}
		var serverKey ecdsa.PublicKey
		if err == nil {
			text, _ := tok.Headers[0].ExtraHeaders[jose.HeaderKey("x5u")].(string)
			err = login.ParsePublicKey(text, &serverKey)
		}
		if err == nil {
			err = tok.Claims(&serverKey, &claims)
		}
		if (err == nil) != f.ServerAccepted {
			return nil, fmt.Errorf("JWT server encoding %s changed: %v", test.name, err)
		}
		if err == nil && claims.Salt != base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef")) {
			return nil, fmt.Errorf("JWT server salt %s changed", test.name)
		}
		out = append(out, f)
	}
	return out, nil
}
