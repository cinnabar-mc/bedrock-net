// Shared protected-header controls across unverified and verified Login roles.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
)

type joseHeaderFixture struct {
	Name     string            `json:"name"`
	Requests map[string][]byte `json:"requests"`
	Server   string            `json:"server"`
	Accepted map[string]bool   `json:"accepted"`
}

// joseHeaderFixtures independently anchors the same protected-header shape in every Login role.
func joseHeaderFixtures() ([]joseHeaderFixture, error) {
	key := offlineKey(7)
	cpk := login.MarshalPublicKey(&key.PublicKey)
	canonical := []byte(`{"alg":"ES384","x5u":"` + cpk + `"}`)
	identity := offlineEncode(map[string]any{"cpk": cpk, "xid": "", "xname": "TokenName"})
	metadata := offlineEncode(map[string]any{"DeviceOS": 1, "GameVersion": "1.26.51", "LanguageCode": "en_US", "SkinId": "synthetic", "ThirdPartyName": "MetadataName", "ServerAddress": "127.0.0.1:19132"})
	extra := map[string]any{"extraData": map[string]any{"displayName": "TokenName", "XUID": ""}}
	canonicalClient := encodingToken(canonical, metadata, key)
	canonicalIdentity := encodingToken(canonical, identity, key)
	first := encodingToken(canonical, offlineEncode(map[string]any{"identityPublicKey": cpk}), key)
	last := encodingToken(canonical, offlineEncode(offlineChanged(extra, "iss", "Mojang")), key)
	jwk := string(offlineEncode(offlineShapeEC(elliptic.P384())))
	// withJWK adds a typed JWK whose ignored field has deliberately non-generic JSON contents.
	withJWK := func(member string) string { return `,"jwk":` + strings.TrimSuffix(jwk, "}") + "," + member + "}" }
	rows := []struct {
		name, members           string
		modern, signed, extract bool
	}{
		{"canonical", "", true, true, true},
		{"x5u_number", `,"x5u":17`, true, true, false},
		{"x5u_bool", `,"x5u":true`, true, true, false},
		{"x5u_object", `,"x5u":{"x":[1,true,null]}`, true, true, false},
		{"x5u_overflow", `,"x5u":1e400`, false, false, false},
		{"x5u_duplicate", `,"x5u":{"x":1,"x":2}`, false, false, false},
		{"kid_number", `,"kid":17`, false, false, false},
		{"kid_null", `,"kid":null`, true, true, true},
		{"kid_case", `,"KID":17`, true, true, true},
		{"nonce_object", `,"nonce":{}`, false, false, false},
		{"nonce_case", `,"NONCE":{}`, true, true, true},
		{"nonce_escaped", `,"no\u006ece":"value"`, true, true, true},
		{"known_duplicate", `,"kid":"a","kid":null`, false, false, false},
		{"known_escaped_duplicate", `,"kid":"a","\u006bid":"b"`, false, false, false},
		{"case_distinct", `,"kid":"a","KID":17`, true, true, true},
		{"algorithm_case", `,"ALG":17`, true, true, true},
		{"algorithm_case_overflow", `,"ALG":1e400`, false, false, false},
		{"algorithm_escaped", "", true, true, true},
		{"algorithm_missing_exact", "", false, false, false},
		{"algorithm_duplicate", `,"a\u006cg":"ES384"`, false, false, false},
		{"algorithm_rs256", "", true, false, false},
		{"generic_duplicate", `,"extension":{"x":1,"x":2}`, false, false, false},
		{"generic_escaped_duplicate", `,"extension":{"x":1,"\u0078":2}`, false, false, false},
		{"generic_overflow", `,"extension":1e400`, false, false, false},
		{"generic_underflow", `,"extension":1e-400`, true, true, true},
		{"unknown_top_duplicate", `,"extension":null,"extension":null`, false, false, false},
		{"jwk_public", `,"jwk":` + jwk, true, true, true},
		{"jwk_ignored_duplicate", withJWK(`"ignored":{"x":1,"x":2}`), true, true, true},
		{"jwk_ignored_overflow", withJWK(`"ignored":1e400`), true, true, true},
		{"jwk_typed_kid", withJWK(`"kid":17`), false, false, false},
		{"critical_number", `,"crit":17`, true, false, false},
		{"critical_object", `,"crit":{"x":true}`, true, false, false},
		{"critical_unknown", `,"crit":["unknown"]`, true, false, false},
		{"critical_case", `,"CRIT":17`, true, true, true},
		{"critical_null", `,"crit":null`, true, true, true},
		{"b64_false", `,"b64":false,"crit":["b64"]`, true, true, true},
		{"b64_object", `,"b64":{}`, true, true, true},
	}
	var fixtures []joseHeaderFixture
	for _, row := range rows {
		prefix := `{"alg":"ES384"`
		members := row.members
		if !strings.HasPrefix(row.name, "x5u_") {
			prefix += `,"x5u":"` + cpk + `"`
		}
		if row.name == "algorithm_escaped" {
			prefix = `{"a\u006cg":"ES384","x5u":"` + cpk + `"`
		}
		if row.name == "algorithm_missing_exact" {
			prefix = `{"ALG":"ES384","x5u":"` + cpk + `"`
		}
		if row.name == "algorithm_rs256" {
			prefix = `{"alg":"RS256","x5u":"` + cpk + `"`
		}
		header := []byte(prefix + members + "}")
		modern := encodingToken(header, identity, key)
		modern = modern[:strings.LastIndexByte(modern, '.')] + ".AA"
		client := encodingToken(header, metadata, key)
		legacy := encodingToken(header, offlineEncode(extra), key)
		middle := encodingToken(header, offlineEncode(map[string]any{"iss": "Mojang", "identityPublicKey": cpk}), key)
		requests := map[string][]byte{
			"modern":        offlineFrame(map[string]any{"Token": modern}, canonicalClient),
			"metadata":      offlineFrame(map[string]any{"Token": canonicalIdentity}, client),
			"legacy":        offlineFrame(map[string]any{"chain": []string{legacy}}, canonicalClient),
			"linked":        offlineFrame(map[string]any{"chain": []string{first, middle, last}}, canonicalClient),
			"authenticated": offlineFrame(map[string]any{"AuthenticationType": 0, "Token": "synthetic-provider"}, client),
		}
		expected := map[string]bool{"modern": row.modern, "metadata": row.signed, "authenticated": row.signed, "legacy": row.extract, "linked": row.signed, "server": row.extract}
		for role, request := range requests {
			if role == "authenticated" {
				continue
			} // The same signed metadata owner is compared through a Rust test provider.
			id, _, auth, err := login.Parse(request, nil)
			if (err == nil) != expected[role] || (err == nil && (auth.XBOXLiveAuthenticated || id.DisplayName != "MetadataName" || !auth.PublicKey.Equal(&key.PublicKey))) {
				return nil, fmt.Errorf("header anchor %s/%s changed: %v", row.name, role, err)
			}
		}
		server := encodingToken(header, offlineEncode(map[string]any{"salt": base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef"))}), key)
		tok, err := jwt.ParseSigned(server, []jose.SignatureAlgorithm{jose.ES384})
		var serverKey ecdsa.PublicKey
		if err == nil {
			value, _ := tok.Headers[0].ExtraHeaders[jose.HeaderKey("x5u")].(string)
			err = login.ParsePublicKey(value, &serverKey)
		}
		if err == nil {
			var claims map[string]any
			err = tok.Claims(&serverKey, &claims)
		}
		if (err == nil) != expected["server"] {
			return nil, fmt.Errorf("server header anchor %s changed: %v", row.name, err)
		}
		fixtures = append(fixtures, joseHeaderFixture{row.name, requests, server, expected})
	}
	return fixtures, nil
}
