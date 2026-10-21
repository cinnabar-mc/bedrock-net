// Synthetic offline Login cases for the pinned Go parser.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
)

type offlineFixture struct {
	Name        string `json:"name"`
	Request     []byte `json:"request"`
	Accepted    bool   `json:"accepted"`
	Key         string `json:"key"`
	DisplayName string `json:"display_name,omitempty"`
	XUID        string `json:"xuid"`
	Identity    string `json:"identity"`
	ExchangeKey string `json:"exchange_key"`
}

// offlineKey uses a small fixed scalar solely for synthetic, reproducible identity selection.
func offlineKey(scalar int64) *ecdsa.PrivateKey {
	d := big.NewInt(scalar)
	x, y := elliptic.P384().ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P384(), X: x, Y: y}, D: d}
}

// offlineEncode turns original fixture values into compact JSON and fails on local fixture errors.
func offlineEncode(value any) []byte {
	out, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return out
}

// offlineToken signs fixture JSON with a fixed test nonce; these keys and signatures must never protect real data.
// The header can deliberately request another algorithm without changing the underlying fixture signer.
func offlineToken(k *ecdsa.PrivateKey, algorithm, headerKey string, claims any) string {
	header := offlineEncode(map[string]any{"alg": algorithm, "x5u": headerKey})
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(offlineEncode(claims))
	digest := sha512.Sum384([]byte(input))
	n := k.Curve.Params().N
	nonce := big.NewInt(13)
	x, _ := k.Curve.ScalarBaseMult(nonce.Bytes())
	r := new(big.Int).Mod(x, n)
	s := new(big.Int).Mul(r, k.D)
	s.Add(s, new(big.Int).SetBytes(digest[:]))
	s.Mul(s, new(big.Int).ModInverse(nonce, n)).Mod(s, n)
	if !ecdsa.Verify(&k.PublicKey, digest[:], r, s) {
		panic("invalid local fixture signature")
	}
	signature := make([]byte, 96)
	r.FillBytes(signature[:48])
	s.FillBytes(signature[48:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// offlineFrame writes the same two signed little-endian fields carried by a Login request.
func offlineFrame(envelope any, client string) []byte {
	var out bytes.Buffer
	for _, part := range [][]byte{offlineEncode(envelope), []byte(client)} {
		if err := binary.Write(&out, binary.LittleEndian, int32(len(part))); err != nil {
			panic(err)
		}
		out.Write(part)
	}
	return out.Bytes()
}

// offlineChanged clones a fixture object before changing its one selected field.
func offlineChanged(original map[string]any, name string, value any) map[string]any {
	copy := make(map[string]any, len(original)+1)
	for k, v := range original {
		copy[k] = v
	}
	copy[name] = value
	return copy
}

// offlineFixtures anchors all decisions and returns deterministic synthetic requests and Go results.
func offlineFixtures() ([]offlineFixture, error) {
	client, other := offlineKey(7), offlineKey(9)
	cpk, opk := login.MarshalPublicKey(&client.PublicKey), login.MarshalPublicKey(&other.PublicKey)
	claims := map[string]any{"cpk": cpk, "xname": "TokenName", "xid": "", "leguuid": "00000000-0000-4000-8000-000000000001"}
	metadata := map[string]any{"DeviceOS": 1, "GameVersion": "1.26.51", "LanguageCode": "en_US", "SkinId": "synthetic", "ThirdPartyName": "MetadataName", "ServerAddress": "127.0.0.1:19132"}
	validToken := offlineToken(client, "ES384", cpk, claims)
	validClient := offlineToken(client, "ES384", cpk, metadata)
	var cases []offlineFixture
	add := func(name string, envelope any, raw string, accepted bool, finalKey string) {
		cases = append(cases, offlineFixture{Name: name, Request: offlineFrame(envelope, raw), Accepted: accepted, Key: finalKey})
	}
	modern := func(name string, auth any, algorithm string, accepted bool) {
		add(name, map[string]any{"AuthenticationType": 2, "Token": offlineToken(client, algorithm, cpk, auth)}, validClient, accepted, "client")
	}
	for _, mode := range []any{0, 2, 3, 255, nil} {
		add(fmt.Sprintf("modern_mode_%v", mode), map[string]any{"AuthenticationType": mode, "Token": validToken}, validClient, true, "client")
	}
	add("modern_mode_absent", map[string]any{"Token": validToken}, validClient, true, "client")
	add("mode_1_rejected", map[string]any{"AuthenticationType": 1, "Token": validToken}, validClient, false, "")
	add("mode_256_rejected", map[string]any{"AuthenticationType": 256, "Token": validToken}, validClient, false, "")
	modern("modern_uuid_absent", offlineChanged(claims, "leguuid", nil), "ES384", true)
	modern("modern_uuid_empty", offlineChanged(claims, "leguuid", ""), "ES384", true)
	modern("modern_uuid_nil", offlineChanged(claims, "leguuid", "00000000-0000-0000-0000-000000000000"), "ES384", true)
	modern("modern_uuid_malformed", offlineChanged(claims, "leguuid", "not-a-uuid"), "ES384", true)
	modern("modern_no_name", offlineChanged(claims, "xname", ""), "ES384", true)
	modern("modern_claimed_numeric_xuid", offlineChanged(claims, "xid", "123"), "ES384", true)
	modern("modern_claimed_bad_xuid", offlineChanged(claims, "xid", "not-an-int"), "ES384", false)
	modern("modern_claimed_xuid_bad_uuid", offlineChanged(offlineChanged(claims, "xid", "123"), "leguuid", "not-a-uuid"), "ES384", false)
	modern("modern_claimed_xuid_name_empty", offlineChanged(offlineChanged(claims, "xid", "123"), "xname", ""), "ES384", false)
	modern("modern_claimed_xuid_derived_uuid", offlineChanged(offlineChanged(claims, "xid", "123"), "leguuid", ""), "ES384", true)
	modern("modern_expired", offlineChanged(claims, "exp", 1), "ES384", true)
	modern("modern_not_yet_valid", offlineChanged(claims, "nbf", 4102444800), "ES384", true)
	modern("modern_wrong_audience", offlineChanged(claims, "aud", "fixture-other"), "ES384", true)
	modern("modern_rs256_unverified", claims, "RS256", true)
	modern("modern_hs256_rejected", claims, "HS256", false)
	modern("modern_none_rejected", claims, "none", false)
	modern("modern_cpk_wrong_key", offlineChanged(claims, "cpk", opk), "ES384", false)
	modern("modern_cpk_null", offlineChanged(claims, "cpk", nil), "ES384", false)
	modern("modern_cpk_wrong_type", offlineChanged(claims, "cpk", 17), "ES384", false)
	modern("modern_cpk_invalid_der", offlineChanged(claims, "cpk", "AAAA"), "ES384", false)
	parts := strings.Split(validToken, ".")
	add("modern_invalid_identity_signature_accepted", map[string]any{"Token": parts[0] + "." + parts[1] + ".AA"}, validClient, true, "client")
	add("modern_bad_identity_signature_encoding", map[string]any{"Token": parts[0] + "." + parts[1] + ".!"}, validClient, false, "")
	add("client_wrong_signature", map[string]any{"Token": validToken}, offlineToken(other, "ES384", opk, metadata), false, "")
	add("client_header_key_ignored", map[string]any{"Token": validToken}, offlineToken(client, "ES384", opk, metadata), true, "client")
	add("client_final_key_rotation", map[string]any{"Token": validToken}, offlineToken(client, "ES384", cpk, offlineChanged(metadata, "identityPublicKey", opk)), true, "other")
	add("client_final_key_null", map[string]any{"Token": validToken}, offlineToken(client, "ES384", cpk, offlineChanged(metadata, "identityPublicKey", nil)), false, "")
	add("client_bad_device", map[string]any{"Token": validToken}, offlineToken(client, "ES384", cpk, offlineChanged(metadata, "DeviceOS", 0)), false, "")
	add("client_bad_skin", map[string]any{"Token": validToken}, offlineToken(client, "ES384", cpk, offlineChanged(metadata, "SkinId", "")), false, "")
	add("client_bad_name", map[string]any{"Token": validToken}, offlineToken(client, "ES384", cpk, offlineChanged(metadata, "ThirdPartyName", "")), false, "")
	add("client_null_name", map[string]any{"Token": validToken}, offlineToken(client, "ES384", cpk, offlineChanged(metadata, "ThirdPartyName", nil)), false, "")
	add("client_unknown_float_overflow", map[string]any{"Token": validToken}, offlineToken(client, "ES384", cpk, offlineChanged(metadata, "unknown", json.RawMessage("1e400"))), false, "")
	add("empty_token_without_chain", map[string]any{"Token": ""}, validClient, false, "")
	legacyClaims := map[string]any{"extraData": map[string]any{"displayName": "LegacyName", "identity": "00000000-0000-4000-8000-000000000002", "XUID": ""}}
	legacy := offlineToken(client, "ES384", cpk, legacyClaims)
	add("legacy_one", map[string]any{"chain": []string{legacy}}, validClient, true, "client")
	add("legacy_certificate_string", map[string]any{"Certificate": string(offlineEncode(map[string]any{"chain": []string{legacy}}))}, validClient, true, "client")
	add("legacy_one_rotates_key", map[string]any{"chain": []string{offlineToken(client, "ES384", cpk, offlineChanged(legacyClaims, "identityPublicKey", opk))}}, offlineToken(other, "ES384", opk, metadata), true, "other")
	add("legacy_one_expired", map[string]any{"chain": []string{offlineToken(client, "ES384", cpk, offlineChanged(legacyClaims, "exp", 1))}}, validClient, false, "")
	add("legacy_two_rejected", map[string]any{"chain": []string{legacy, legacy}}, validClient, false, "")
	legacyParts := strings.Split(legacy, ".")
	add("legacy_one_bad_signature", map[string]any{"chain": []string{legacyParts[0] + "." + legacyParts[1] + ".AA"}}, validClient, false, "")
	add("legacy_one_invalid_xuid_rejected", map[string]any{"chain": []string{offlineToken(client, "ES384", cpk, offlineChanged(legacyClaims, "extraData", map[string]any{"displayName": "", "identity": "bad", "XUID": "bad"}))}}, validClient, false, "")
	add("legacy_one_empty_xuid_bad_uuid", map[string]any{"chain": []string{offlineToken(client, "ES384", cpk, offlineChanged(legacyClaims, "extraData", map[string]any{"displayName": "", "identity": "bad", "XUID": ""}))}}, validClient, true, "client")
	chain3 := []string{offlineToken(client, "ES384", cpk, map[string]any{"identityPublicKey": opk}), offlineToken(other, "ES384", opk, map[string]any{"iss": "Mojang", "identityPublicKey": cpk}), offlineToken(client, "ES384", cpk, offlineChanged(legacyClaims, "iss", "Mojang"))}
	add("legacy_three_untrusted", map[string]any{"chain": chain3}, validClient, true, "client")
	chain3Claimed := append([]string(nil), chain3...)
	chain3Claimed[2] = offlineToken(client, "ES384", cpk, map[string]any{"iss": "Mojang", "extraData": map[string]any{"XUID": "123"}})
	add("legacy_three_untrusted_xuid_rejected", map[string]any{"chain": chain3Claimed}, validClient, false, "")
	add("modern_ignores_broken_legacy_signature", map[string]any{"Token": validToken, "chain": []string{"broken"}}, validClient, true, "client")
	add("modern_invalid_certificate_json_rejected", map[string]any{"Token": validToken, "Certificate": "{"}, validClient, false, "")
	add("modern_empty_certificate_uses_chain", map[string]any{"Token": validToken, "Certificate": "", "chain": []string{"broken"}}, validClient, true, "client")
	add("modern_malformed_typed_chain_rejected", map[string]any{"Token": validToken, "chain": []any{42}}, validClient, false, "")
	oversized := offlineFrame(map[string]any{"Token": validToken}, validClient)
	envelopeLength := int(binary.LittleEndian.Uint32(oversized[:4]))
	binary.LittleEndian.PutUint32(oversized[4+envelopeLength:8+envelopeLength], uint32(len(validClient)+5))
	cases = append(cases, offlineFixture{Name: "declared_client_length_exceeds_input", Request: oversized, Accepted: true, Key: "client"})
	for i := range cases {
		test := &cases[i]
		identity, _, auth, err := login.Parse(test.Request, nil)
		accepted := err == nil
		actualKey := ""
		if auth.PublicKey != nil {
			if auth.PublicKey.Equal(&client.PublicKey) {
				actualKey = "client"
			} else if auth.PublicKey.Equal(&other.PublicKey) {
				actualKey = "other"
			} else {
				actualKey = "unknown"
			}
		}
		ok := accepted == test.Accepted
		if accepted {
			ok = ok && !auth.XBOXLiveAuthenticated && identity.DisplayName == "MetadataName" && actualKey == test.Key
			test.DisplayName = identity.DisplayName
		}
		if !ok {
			return nil, fmt.Errorf("offline decision changed for %s", test.Name)
		}
		test.XUID = identity.XUID
		test.Identity = identity.Identity
		if accepted {
			test.ExchangeKey = login.MarshalPublicKey(auth.PublicKey)
		}
	}
	return cases, nil
}
