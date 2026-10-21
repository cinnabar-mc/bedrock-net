// Synthetic Login header and outer-array shape controls for the pinned Go parser.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
)

type offlineShape struct {
	Name     string `json:"name"`
	Group    string `json:"group"`
	Request  []byte `json:"request"`
	Accepted bool   `json:"accepted"`
}

// offlineShapeSign uses a fixed nonce only for publicly known synthetic fixture keys.
func offlineShapeSign(k *ecdsa.PrivateKey, digest []byte) (*big.Int, *big.Int) {
	n := k.Curve.Params().N
	x, _ := k.Curve.ScalarBaseMult([]byte{13})
	r := new(big.Int).Mod(x, n)
	s := new(big.Int).Mul(r, k.D)
	s.Add(s, new(big.Int).SetBytes(digest))
	s.Mul(s, new(big.Int).ModInverse(big.NewInt(13), n)).Mod(s, n)
	return r, s
}

// offlineShapeToken signs exact header/payload bytes, including deliberately invalid JSON shapes.
func offlineShapeToken(k *ecdsa.PrivateKey, header, payload []byte) string {
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha512.Sum384([]byte(input))
	r, s := offlineShapeSign(k, digest[:])
	if !ecdsa.Verify(&k.PublicKey, digest[:], r, s) {
		panic("invalid synthetic signature")
	}
	signature := make([]byte, 96)
	r.FillBytes(signature[:48])
	s.FillBytes(signature[48:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

type offlineCertificateSigner struct{ key *ecdsa.PrivateKey }

// Public returns only the synthetic certificate's public key.
func (s offlineCertificateSigner) Public() crypto.PublicKey { return &s.key.PublicKey }

// Sign makes certificate fixtures deterministic without verifying or trusting their issuer.
func (s offlineCertificateSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	r, v := offlineShapeSign(s.key, digest)
	return asn1.Marshal(struct{ R, S *big.Int }{r, v})
}

// offlineShapeCertificate creates an original self-signed test certificate with fixed validity.
func offlineShapeCertificate(key *ecdsa.PrivateKey, public crypto.PublicKey, extensions []pkix.Extension) []byte {
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic.invalid"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1, 0), SignatureAlgorithm: x509.ECDSAWithSHA384, ExtraExtensions: extensions}
	der, err := x509.CreateCertificate(nil, template, template, public, offlineCertificateSigner{key})
	if err != nil {
		panic(err)
	}
	return der
}

// offlineShapeEC returns a correctly padded public JWK for a fixed scalar on the requested curve.
func offlineShapeEC(curve elliptic.Curve) map[string]any {
	x, y := curve.ScalarBaseMult([]byte{7})
	width := (curve.Params().BitSize + 7) / 8
	return map[string]any{"kty": "EC", "crv": curve.Params().Name, "x": base64.RawURLEncoding.EncodeToString(x.FillBytes(make([]byte, width))), "y": base64.RawURLEncoding.EncodeToString(y.FillBytes(make([]byte, width)))}
}

// offlineShapes checks header decoding and Go's retained string backing across outer chain aliases.
func offlineShapes() ([]offlineShape, error) {
	key := offlineKey(7)
	public := login.MarshalPublicKey(&key.PublicKey)
	header := offlineEncode(map[string]any{"alg": "ES384", "x5u": public})
	identity := offlineEncode(map[string]any{"cpk": public, "xname": "TokenName"})
	extra := offlineEncode(map[string]any{"extraData": map[string]any{"displayName": "TokenName"}})
	client := offlineShapeToken(key, header, offlineEncode(map[string]any{"DeviceOS": 1, "GameVersion": "1.26.51", "LanguageCode": "en_US", "SkinId": "synthetic", "ThirdPartyName": "MetadataName", "ServerAddress": "127.0.0.1:19132"}))
	legacy := offlineShapeToken(key, header, extra)
	var cases []offlineShape
	add := func(name, group string, envelope any, want bool) {
		request := offlineFrame(envelope, client)
		id, _, auth, err := login.Parse(request, nil)
		if (err == nil) != want || (want && (auth.XBOXLiveAuthenticated || id.DisplayName != "MetadataName")) {
			panic(fmt.Sprintf("%s: want %v, got %v", name, want, err))
		}
		cases = append(cases, offlineShape{name, group, request, want})
	}
	modern := func(name, members string, want bool) {
		raw := []byte(`{"alg":"ES384","x5u":` + string(offlineEncode(public)) + `,` + members + `}`)
		token := offlineShapeToken(key, raw, identity)
		// The identity signature is deliberately unverified in this mode.
		token = token[:strings.LastIndexByte(token, '.')] + ".AA"
		add(name, "header", map[string]any{"Token": token}, want)
	}
	for _, field := range []string{"kid", "nonce"} {
		for _, value := range []string{`null`, `""`, `"value"`, `17`, `true`, `[]`, `{}`} {
			modern(field+"_"+value, `"`+field+`":`+value, value == "null" || strings.HasPrefix(value, `"`))
		}
	}
	for _, row := range []struct {
		name, members string
		want          bool
	}{
		{"generic_nested", `"extension":{"a":[1,true,null,"v"]}`, true},
		{"generic_overflow", `"extension":1e400`, false},
		{"generic_negative_overflow", `"extension":-1e400`, false},
		{"generic_underflow", `"extension":1e-400`, true},
		{"generic_nested_overflow", `"extension":[{"x":1e400}]`, false},
		{"generic_nested_duplicate", `"extension":{"x":1,"x":2}`, false},
		{"generic_escaped_duplicate", `"extension":{"x":1,"\u0078":2}`, false},
		{"top_duplicate", `"kid":"one","kid":null`, false},
		{"top_escaped_duplicate", `"kid":"one","\u006bid":"two"`, false},
		{"top_unknown_duplicate", `"extension":null,"extension":null`, false},
		{"header_names_exact", `"KID":17,"NONCE":false`, true},
		{"modern_crit_unknown", `"crit":["unimplemented"]`, true},
		{"modern_crit_number", `"crit":17`, true},
		{"modern_crit_object", `"crit":{"x":true}`, true},
		{"modern_b64_false", `"b64":false`, true},
		{"modern_b64_wrong_type", `"b64":"false"`, true},
		{"jwk_null", `"jwk":null`, true},
		{"jwk_number", `"jwk":17`, false},
		{"jwk_empty", `"jwk":{}`, false},
		{"jwk_unsupported", `"jwk":{"kty":"unknown"}`, false},
		{"jwk_oct_empty", `"jwk":{"kty":"oct","k":""}`, false},
		{"jwk_oct_null", `"jwk":{"kty":"oct","k":null}`, false},
		{"jwk_oct_invalid", `"jwk":{"kty":"oct","k":"!"}`, false},
		{"jwk_oct_padded", `"jwk":{"kty":"oct","k":"AQ=="}`, false},
		{"jwk_oct_crlf", `"jwk":{"kty":"oct","k":"A\r\nQ"}`, false},
		{"jwk_oct_trailing_bits", `"jwk":{"kty":"oct","k":"Af"}`, false},
		{"jwk_unknown_overflow_ignored", `"jwk":{"kty":"OKP","crv":"Ed25519","x":"AQ","unknown":1e400}`, true},
		{"jwk_unknown_nested_duplicate_ignored", `"jwk":{"kty":"OKP","crv":"Ed25519","x":"AQ","unknown":{"x":1,"x":2}}`, true},
		{"jwk_top_duplicate", `"jwk":{"kty":"oct","k":"AQ","k":"Ag"}`, false},
		{"jwk_typed_unused", `"jwk":{"kty":"oct","k":"AQ","n":17}`, false},
		{"jwk_exact_names", `"jwk":{"KTY":"oct","k":"AQ"}`, false},
		{"rsa_public_zero", `"jwk":{"kty":"RSA","n":"","e":"EQ"}`, true},
		{"rsa_public_zero_exponent", `"jwk":{"kty":"RSA","n":"","e":""}`, false},
		{"rsa_public_signed_exponent", `"jwk":{"kty":"RSA","n":"AQ","e":"__________8"}`, true},
		{"rsa_public_low_exponent", `"jwk":{"kty":"RSA","n":"AQ","e":"AQAAAAAAAAAR"}`, true},
		{"rsa_public_missing", `"jwk":{"kty":"RSA","n":"AQ"}`, false},
		{"rsa_private_valid", `"jwk":{"kty":"RSA","n":"DKE","e":"EQ","d":"CsE","p":"PQ","q":"NQ"}`, false},
		{"rsa_private_bad_d", `"jwk":{"kty":"RSA","n":"DKE","e":"EQ","d":"AQ","p":"PQ","q":"NQ"}`, false},
		{"rsa_private_partial_crt_ignored", `"jwk":{"kty":"RSA","n":"DKE","e":"EQ","d":"CsE","p":"PQ","q":"NQ","dp":"AQ"}`, false},
		{"rsa_private_bad_crt", `"jwk":{"kty":"RSA","n":"DKE","e":"EQ","d":"CsE","p":"PQ","q":"NQ","dp":"AQ","dq":"AQ","qi":"AQ"}`, false},
		{"ed_public_short", `"jwk":{"kty":"OKP","crv":"Ed25519","x":"AQ"}`, true},
		{"ed_public_null_private", `"jwk":{"kty":"OKP","crv":"Ed25519","x":"AQ","d":null}`, true},
		{"ed_public_unused_bad_base64", `"jwk":{"kty":"OKP","crv":"Ed25519","x":"AQ","qi":"!"}`, false},
		{"ed_public_unused_bad_type", `"jwk":{"kty":"OKP","crv":"Ed25519","x":"AQ","use":17}`, false},
		{"ed_private_empty", `"jwk":{"kty":"OKP","crv":"Ed25519","x":"","d":""}`, false},
		{"ed_missing_x", `"jwk":{"kty":"OKP","crv":"Ed25519","d":"AQ"}`, false},
		{"ed_wrong_curve", `"jwk":{"kty":"OKP","crv":"X25519","x":"AQ"}`, false},
		{"x5c_null", `"x5c":null`, true},
		{"x5c_empty", `"x5c":[]`, true},
		{"x5c_wrong_type", `"x5c":""`, false},
		{"x5c_null_element", `"x5c":[null]`, false},
		{"x5c_bad_der", `"x5c":["MAA="]`, false},
		{"x5c_bad_encoding", `"x5c":["!"]`, false},
	} {
		modern(row.name, row.members, row.want)
	}
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		jwk := offlineShapeEC(curve)
		modern("ec_public_"+curve.Params().Name, `"jwk":`+string(offlineEncode(jwk)), true)
		width := (curve.Params().BitSize + 7) / 8
		for _, row := range []struct {
			name, field string
			value       any
			want        bool
		}{
			{"private_zero", "d", base64.RawURLEncoding.EncodeToString(make([]byte, width)), false},
			{"private_empty", "d", "", false},
			{"short_x", "x", "AQ", false},
			{"bad_point", "x", base64.RawURLEncoding.EncodeToString(make([]byte, width)), false},
			{"null_y", "y", nil, false},
			{"typed_alg", "alg", 17, false},
		} {
			modern("ec_"+curve.Params().Name+"_"+row.name, `"jwk":`+string(offlineEncode(offlineChanged(jwk, row.field, row.value))), row.want)
		}
	}
	cert := offlineShapeCertificate(key, &key.PublicKey, nil)
	cert64 := base64.StdEncoding.EncodeToString(cert)
	modern("x5c_valid_expired", `"x5c":[`+string(offlineEncode(cert64))+`]`, true)
	modern("x5c_trailing_der", `"x5c":[`+string(offlineEncode(base64.StdEncoding.EncodeToString(append(append([]byte(nil), cert...), 0))))+`]`, false)
	tampered := append([]byte(nil), cert...)
	tampered[len(tampered)-1] ^= 1
	modern("x5c_signature_unverified", `"x5c":[`+string(offlineEncode(base64.StdEncoding.EncodeToString(tampered)))+`]`, true)
	for _, row := range []struct {
		name   string
		public crypto.PublicKey
		jwk    map[string]any
	}{
		{"rsa", &rsa.PublicKey{N: big.NewInt(3233), E: 17}, map[string]any{"kty": "RSA", "n": "DKE", "e": "EQ"}},
		{"ed25519", ed25519.PublicKey(make([]byte, 32)), map[string]any{"kty": "OKP", "crv": "Ed25519", "x": ""}},
	} {
		encoded := base64.StdEncoding.EncodeToString(offlineShapeCertificate(key, row.public, nil))
		modern("x5c_valid_"+row.name, `"x5c":[`+string(offlineEncode(encoded))+`]`, true)
		row.jwk["x5c"] = []string{encoded}
		modern("jwk_cert_matches_"+row.name, `"jwk":`+string(offlineEncode(row.jwk)), true)
	}
	for _, row := range []struct {
		name           string
		oid            asn1.ObjectIdentifier
		critical, want bool
		value          []byte
	}{
		{"unknown_critical", asn1.ObjectIdentifier{1, 2, 3, 4}, true, true, []byte{0xff}},
		{"ignored_issuer_alt_name", asn1.ObjectIdentifier{2, 5, 29, 18}, false, true, []byte{0xff}},
		{"ignored_sct", asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, false, true, []byte{0xff}},
		{"bad_key_usage", asn1.ObjectIdentifier{2, 5, 29, 15}, false, false, []byte{0xff}},
		{"bad_basic_constraints", asn1.ObjectIdentifier{2, 5, 29, 19}, false, false, []byte{0xff}},
		{"critical_subject_key", asn1.ObjectIdentifier{2, 5, 29, 14}, true, false, []byte{4, 1, 1}},
		{"critical_authority_key", asn1.ObjectIdentifier{2, 5, 29, 35}, true, false, []byte{0x30, 0}},
		{"critical_authority_info", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}, true, false, []byte{0x30, 0}},
	} {
		encoded := base64.StdEncoding.EncodeToString(offlineShapeCertificate(key, &key.PublicKey, []pkix.Extension{{Id: row.oid, Critical: row.critical, Value: row.value}}))
		modern("x5c_extension_"+row.name, `"x5c":[`+string(offlineEncode(encoded))+`]`, row.want)
	}
	jwk := offlineShapeEC(elliptic.P384())
	jwk["x5c"] = []string{cert64}
	modern("jwk_cert_matches", `"jwk":`+string(offlineEncode(jwk)), true)
	wrong := offlineShapeEC(elliptic.P256())
	wrong["x5c"] = []string{cert64}
	modern("jwk_cert_mismatch", `"jwk":`+string(offlineEncode(wrong)), false)
	one, two := sha1.Sum(cert), sha256.Sum256(cert)
	for _, row := range []struct {
		field  string
		digest []byte
	}{{"x5t", one[:]}, {"x5t#S256", two[:]}} {
		for _, hex := range []bool{false, true} {
			value := row.digest
			if hex {
				value = []byte(fmt.Sprintf("%x", value))
			}
			modern(fmt.Sprintf("jwk_thumbprint_%s_%v", row.field, hex), `"jwk":`+string(offlineEncode(offlineChanged(jwk, row.field, base64.RawURLEncoding.EncodeToString(value)))), true)
		}
		modern("jwk_thumbprint_wrong_"+row.field, `"jwk":`+string(offlineEncode(offlineChanged(jwk, row.field, base64.RawURLEncoding.EncodeToString(make([]byte, len(row.digest)))))), false)
		modern("jwk_thumbprint_size_"+row.field, `"jwk":`+string(offlineEncode(offlineChanged(jwk, row.field, "AQ"))), false)
	}
	for _, row := range []struct {
		url  string
		want bool
	}{{"relative/path", true}, {"urn:opaque%zz", true}, {"https://example.invalid/key?bad=%zz", true}, {"http://[example]/key", false}, {"https://example.invalid/%zz", false}, {"https://%41.invalid/key", false}, {":bad", false}, {"http://host:bad/key", false},
		{"POSTGRES://first:42,second:43/key", true}, {"https://first:42,second:43/key", false}, {"http://[::1]/key", true}, {"http://[::1%25zone]/key", true}, {"http://[::1%25]/key", false}, {"http://[::1%25a[b]/key", false}, {"http://user:pass@example.invalid/key", true}, {"http://u%00@example.invalid/key", true}} {
		modern("jwk_url_"+row.url, `"jwk":`+string(offlineEncode(offlineChanged(jwk, "x5u", row.url))), row.want)
	}
	quoted := string(offlineEncode(legacy))
	linked := []string{
		offlineToken(key, "ES384", public, map[string]any{"identityPublicKey": public}),
		offlineToken(key, "ES384", public, map[string]any{"iss": "Mojang", "identityPublicKey": public}),
		offlineToken(key, "ES384", public, map[string]any{"iss": "Mojang", "extraData": map[string]any{"displayName": "TokenName"}}),
	}
	three := string(offlineEncode(linked))
	for _, row := range []struct {
		name, fields string
		want         bool
	}{
		{"aliased_null", `"chain":[` + quoted + `],"CHAIN":[null]`, true},
		{"exact_null", `"chain":[` + quoted + `],"chain":[null]`, true},
		{"initial_null", `"chain":[null]`, false},
		{"truncate_one", `"chain":` + three + `,"CHAIN":[null]`, true},
		{"retain_reextended", `"chain":` + three + `,"CHAIN":[null],"chain":[null,null,null]`, true},
		{"reset_reextended", `"chain":` + three + `,"CHAIN":[],"chain":[null,null,null]`, false},
		{"null_reset_reextended", `"chain":` + three + `,"CHAIN":null,"chain":[null,null,null]`, false},
		{"extend_null", `"chain":[` + quoted + `],"CHAIN":[null,null,null]`, false},
		{"null_resets", `"chain":[` + quoted + `],"CHAIN":null,"chain":[null]`, false},
		{"empty_resets", `"chain":[` + quoted + `],"CHAIN":[],"chain":[null]`, false},
		{"earlier_type_error", `"chain":[17],"CHAIN":[` + quoted + `]`, false},
		{"empty_then_valid", `"chain":[],"CHAIN":[` + quoted + `],"chain":[null]`, true},
	} {
		for _, certificate := range []bool{false, true} {
			raw := `{` + row.fields + `}`
			var envelope any = []byte(raw)
			if certificate {
				envelope = map[string]any{"Certificate": raw}
			} else {
				envelope = offlineRawJSON(raw)
			}
			add(fmt.Sprintf("chain_%s_certificate_%v", row.name, certificate), "chain", envelope, row.want)
		}
	}
	return cases, nil
}

// offlineRawJSON preserves aliases and duplicates in an original synthetic outer object.
type offlineRawJSON string

// MarshalJSON preserves exact JSON fixture bytes rather than escaping the object as a string.
func (raw offlineRawJSON) MarshalJSON() ([]byte, error) { return []byte(raw), nil }
