// Synthetic certificate and auxiliary URL admission controls for signed Login headers.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
)

type joseAdmissionFixture struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Request  []byte `json:"request"`
	Server   string `json:"server"`
	Accepted bool   `json:"accepted"`
}

// admissionDER wraps original fixture contents without decoding or canonicalizing their interior.
func admissionDER(tag byte, value []byte) []byte {
	out := []byte{tag}
	n := len(value)
	if n < 128 {
		out = append(out, byte(n))
	} else {
		var length []byte
		for n > 0 {
			length = append([]byte{byte(n)}, length...)
			n >>= 8
		}
		out = append(out, 128|byte(len(length)))
		out = append(out, length...)
	}
	return append(out, value...)
}

// admissionHex decodes readable original DER controls and fails on a local fixture typo.
func admissionHex(value string) []byte {
	data, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return data
}

// admissionFields splits only the valid original certificate used as a mutation carrier.
func admissionFields(value []byte) [][]byte {
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(value, &outer); err != nil {
		panic(err)
	}
	var fields [][]byte
	for data := outer.Bytes; len(data) > 0; {
		var field asn1.RawValue
		rest, err := asn1.Unmarshal(data, &field)
		if err != nil {
			panic(err)
		}
		fields = append(fields, field.FullBytes)
		data = rest
	}
	return fields
}

// admissionSerial replaces the serial TLV while recomputing both enclosing sequence lengths.
func admissionSerial(cert, serial []byte) []byte {
	outer := admissionFields(cert)
	tbs := admissionFields(outer[0])
	tbs[1] = serial
	var contents []byte
	for _, part := range tbs {
		contents = append(contents, part...)
	}
	outer[0] = admissionDER(0x30, contents)
	contents = nil
	for _, part := range outer {
		contents = append(contents, part...)
	}
	return admissionDER(0x30, contents)
}

// admissionVersion changes the version and appends uninterpreted TBS bytes after its public key.
func admissionVersion(cert []byte, version int, tail []byte) []byte {
	outer := admissionFields(cert)
	fields := admissionFields(outer[0])[:7]
	if version < 0 {
		fields[0] = nil
	} else {
		fields[0] = admissionDER(0xa0, admissionDER(2, []byte{byte(version)}))
	}
	outer[0] = admissionDER(0x30, append(bytes.Join(fields, nil), tail...))
	return admissionDER(0x30, bytes.Join(outer, nil))
}

// admissionNames encodes one GeneralName, optionally inside a permitted NameConstraints subtree.
func admissionNames(tag byte, value []byte, constraint bool) []byte {
	name := admissionDER(tag, value)
	if constraint {
		name = admissionDER(0xa0, admissionDER(0x30, name))
	}
	return admissionDER(0x30, name)
}

// joseAdmissionFixtures anchors header parsing, signed metadata and server verification independently.
func joseAdmissionFixtures() ([]joseAdmissionFixture, error) {
	key := offlineKey(7)
	public := login.MarshalPublicKey(&key.PublicKey)
	identity := encodingToken([]byte(`{"alg":"ES384","x5u":"`+public+`"}`), offlineEncode(map[string]any{"cpk": public, "xname": "TokenName"}), key)
	metadata := offlineEncode(map[string]any{"DeviceOS": 1, "GameVersion": "1.26.51", "LanguageCode": "en_US", "SkinId": "synthetic", "ThirdPartyName": "MetadataName", "ServerAddress": "127.0.0.1:19132"})
	var fixtures []joseAdmissionFixture
	// add keeps the header key independent from the auxiliary certificate/JWK data.
	add := func(name, kind, member string, want bool) error {
		header := []byte(`{"alg":"ES384","x5u":"` + public + `",` + member + `}`)
		client := encodingToken(header, metadata, key)
		_, err := jwt.ParseSigned(client, []jose.SignatureAlgorithm{jose.ES384})
		if (err == nil) != want {
			return fmt.Errorf("%s/header: want %v, got %v", name, want, err)
		}
		id, _, auth, err := login.Parse(offlineFrame(map[string]any{"Token": identity}, client), nil)
		if (err == nil) != want || (want && (id.DisplayName != "MetadataName" || auth.XBOXLiveAuthenticated)) {
			return fmt.Errorf("%s/metadata: %v", name, err)
		}
		server := encodingToken(header, offlineEncode(map[string]any{"salt": base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef"))}), key)
		tok, err := jwt.ParseSigned(server, []jose.SignatureAlgorithm{jose.ES384})
		var serverKey ecdsa.PublicKey
		if err == nil {
			text, _ := tok.Headers[0].ExtraHeaders[jose.HeaderKey("x5u")].(string)
			err = login.ParsePublicKey(text, &serverKey)
		}
		if err == nil {
			var claims map[string]any
			err = tok.Claims(&serverKey, &claims)
		}
		if (err == nil) != want {
			return fmt.Errorf("%s/server: want %v, got %v", name, want, err)
		}
		fixtures = append(fixtures, joseAdmissionFixture{name, kind, offlineFrame(map[string]any{"AuthenticationType": 0, "Token": "synthetic-provider"}, client), server, want})
		return nil
	}
	// certificate tests both the generic x5c field and its typed public-JWK binding.
	certificate := func(name string, cert []byte, want bool) error {
		chain := []string{base64.StdEncoding.EncodeToString(cert)}
		if err := add(name+"/x5c", "certificate", `"x5c":`+string(offlineEncode(chain)), want); err != nil {
			return err
		}
		jwk := offlineShapeEC(elliptic.P384())
		jwkWant := want
		if want {
			parsed, err := x509.ParseCertificate(cert)
			if err != nil {
				return fmt.Errorf("%s/certificate: %w", name, err)
			}
			encoded, err := (jose.JSONWebKey{Key: parsed.PublicKey}).MarshalJSON()
			if err != nil {
				// Unknown certificate algorithms have no leaf key to compare; DSA has one.
				jwkWant = parsed.PublicKey == nil
			} else {
				jwk = make(map[string]any)
				if err := json.Unmarshal(encoded, &jwk); err != nil {
					return err
				}
			}
		}
		jwk["x5c"] = chain
		return add(name+"/jwk", "certificate", `"jwk":`+string(offlineEncode(jwk)), jwkWant)
	}
	base := offlineShapeCertificate(key, &key.PublicKey, nil)
	for _, row := range admissionCoreCertificates(base) {
		if err := certificate("core/"+row.name, row.der, row.want); err != nil {
			return nil, err
		}
	}
	for _, row := range []struct {
		name, serial string
		want         bool
	}{
		{"serial_one", "020101", true}, {"serial_zero", "020100", true}, {"serial_sign_octet", "02020080", true},
		{"serial_nonminimal", "02020001", false}, {"serial_empty", "0200", false}, {"serial_negative", "0201ff", false},
		{"serial_negative_nonminimal", "0202ffff", false}, {"serial_long_length", "02810101", false},
		{"serial_leading_length_zero", "0282000101", false}, {"serial_indefinite", "0280010000", false},
		{"serial_constructed", "220101", false},
	} {
		if err := certificate(row.name, admissionSerial(base, admissionHex(row.serial)), row.want); err != nil {
			return nil, err
		}
	}
	if err := certificate("serial_large", admissionSerial(base, admissionDER(2, append([]byte{1}, make([]byte, 128)...))), true); err != nil {
		return nil, err
	}
	// Older versions and ignored tails are distinct from interpreted extension records.
	unknownRecord := admissionDER(0x30, admissionHex("06022a030401ff"))
	records := admissionDER(0x30, unknownRecord)
	for _, row := range []struct {
		name    string
		version int
		tail    []byte
		want    bool
	}{
		{"v1_ignored_extension", 0, admissionHex("a301ff"), true},
		{"v1_default_ignored_extension", -1, admissionHex("a301ff"), true},
		{"v2_ignored_extension", 1, admissionHex("8101ffa301ff"), true},
		{"v3_opaque_unique_id", 2, admissionHex("8101ff"), true},
		{"v3_bad_extension_envelope", 2, admissionHex("a301ff"), false},
		{"v3_extension_wrapper_tail", 2, admissionDER(0xa3, append(append([]byte(nil), records...), 0xff)), true},
		{"v3_extension_record_tail", 2, admissionDER(0xa3, admissionDER(0x30, admissionDER(0x30, admissionHex("06022a030401ffff")))), true},
		{"v3_non_der_critical", 2, admissionDER(0xa3, admissionDER(0x30, admissionDER(0x30, admissionHex("06022a030101010401ff")))), false},
		{"v3_duplicate_extension", 2, admissionDER(0xa3, admissionDER(0x30, append(append([]byte(nil), unknownRecord...), unknownRecord...))), false},
		{"v3_ignored_tbs_tail", 2, []byte{0xff}, true},
	} {
		if err := certificate(row.name, admissionVersion(base, row.version, row.tail), row.want); err != nil {
			return nil, err
		}
	}
	outer := admissionFields(base)
	if err := certificate("outer_ignored_tail", admissionDER(0x30, append(bytes.Join(outer, nil), 0xff)), true); err != nil {
		return nil, err
	}
	rows := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		critical bool
		value    []byte
		want     bool
	}{}
	// extension records original value bytes so even malformed DER reaches the actual decoder.
	extension := func(name string, number int, critical bool, value string, want bool) {
		rows = append(rows, struct {
			name     string
			oid      asn1.ObjectIdentifier
			critical bool
			value    []byte
			want     bool
		}{name, asn1.ObjectIdentifier{2, 5, 29, number}, critical, admissionHex(value), want})
	}
	extension("ski_empty", 14, false, "0400", true)
	extension("ski_critical", 14, true, "040101", false)
	extension("ski_wrong_tag", 14, false, "0500", false)
	extension("key_usage", 15, false, "03020780", true)
	extension("key_usage_empty", 15, false, "030100", true)
	extension("key_usage_padding", 15, false, "03020701", false)
	extension("key_usage_nonminimal_length", 15, false, "03810100", false)
	extension("basic_true", 19, false, "30030101ff", true)
	extension("basic_boolean_non_der", 19, false, "3003010101", false)
	extension("basic_max_int64", 19, false, "300a02087fffffffffffffff", true)
	extension("basic_overflow", 19, false, "300b0209008000000000000000", false)
	extension("basic_negative", 19, false, "30030201ff", false)
	extension("basic_opaque_tail", 19, false, "3001ff", true)
	extension("authority_key_empty", 35, false, "3000", true)
	extension("authority_key_critical", 35, true, "3000", false)
	extension("authority_key_opaque_tail", 35, false, "3001ff", true)
	extension("policy_constraints_wide", 36, false, "300780050100000000", true)
	extension("policy_constraints_negative", 36, false, "30038001ff", true)
	extension("policy_constraints_overflow", 36, false, "300b8009008000000000000000", false)
	extension("policy_constraints_nonminimal", 36, false, "300480020001", false)
	extension("policy_constraints_opaque_tail", 36, false, "3001ff", true)
	extension("inhibit_wide", 54, false, "02050100000000", true)
	extension("inhibit_max_int64", 54, false, "02087fffffffffffffff", true)
	extension("inhibit_negative", 54, false, "0201ff", true)
	extension("inhibit_overflow", 54, false, "0209008000000000000000", false)
	extension("inhibit_nonminimal", 54, false, "02020001", false)
	extension("eku_empty", 37, false, "3000", true)
	extension("eku_oid", 37, false, "300306012a", true)
	extension("eku_large_oid", 37, false, "30080606818080808000", false)
	extension("eku_bad_oid", 37, false, "30020600", false)
	extension("policy_oid", 32, false, "3005300306012a", true)
	extension("policy_large_oid", 32, false, "300a30080606818080808000", true)
	extension("policy_duplicate", 32, false, "300a300306012a300306012a", false)
	extension("policy_bad_oid", 32, false, "3006300406028000", false)
	extension("policy_opaque_qualifier", 32, false, "3006300406012aff", true)
	extension("mappings_raw_oids", 33, false, "3006300406000600", true)
	extension("mappings_missing_oid", 33, false, "300430020600", false)
	extension("crl_empty_point", 31, false, "30023000", true)
	extension("crl_raw_uri", 31, false, "30093007a005a0038601ff", true)
	extension("crl_relative_name", 31, false, "30063004a002a100", false)
	extension("crl_bad_sequence", 31, false, "3001ff", false)
	extension("unknown_critical", 99, true, "ff", true)
	extension("ignored_issuer_names", 18, false, "ff", true)
	extension("name_constraints_empty", 30, false, "3000", false)
	extension("name_constraints_empty_permitted", 30, false, "3002a000", false)
	for _, row := range []struct {
		name  string
		tag   byte
		value string
		want  bool
	}{
		{"ip_three", 0x87, "010203", false}, {"ip_four", 0x87, "01020304", true}, {"ip_sixteen", 0x87, "00000000000000000000000000000001", true},
		{"dns_unicode", 0x82, "c3a9", false}, {"email_unicode", 0x81, "c3a9", false}, {"uri_unicode", 0x86, "c3a9", false},
		{"dns_ascii_control", 0x82, "00", true}, {"unknown_general_name", 0x80, "ff", true}, {"constructed_dns_opaque", 0xa2, "ff", true},
	} {
		rows = append(rows, struct {
			name     string
			oid      asn1.ObjectIdentifier
			critical bool
			value    []byte
			want     bool
		}{"san_" + row.name, asn1.ObjectIdentifier{2, 5, 29, 17}, false, admissionNames(row.tag, admissionHex(row.value), false), row.want})
	}
	for _, row := range []struct {
		name, uri string
		want      bool
	}{
		{"opaque", "urn:opaque%zz", true}, {"bad_escape", "https://example.invalid/%zz", false}, {"host_trailing_dot", "https://example.invalid./", false}, {"host_empty_label", "https://a..invalid/", false}, {"host_port", "https://example.invalid:42/", true}, {"host_ipv6", "https://[::1]/", true}, {"host_bad_literal", "https://[example]/", false}, {"host_byte", "https://%ff.invalid/", false}, {"fragment_control", "https://example.invalid/#\n", true},
	} {
		rows = append(rows, struct {
			name     string
			oid      asn1.ObjectIdentifier
			critical bool
			value    []byte
			want     bool
		}{"san_uri_" + row.name, asn1.ObjectIdentifier{2, 5, 29, 17}, false, admissionNames(0x86, []byte(row.uri), false), row.want})
	}
	for _, row := range []struct {
		name  string
		tag   byte
		value string
		want  bool
	}{
		{"dns", 0x82, ".example.invalid", true}, {"dns_empty", 0x82, "", true}, {"dns_bad", 0x82, "bad..name", false}, {"dns_trailing", 0x82, "example.invalid.", false},
		{"email", 0x81, "a@example.invalid", true}, {"email_bad", 0x81, "a..b@example.invalid", false}, {"email_quoted", 0x81, "\"a b\"@example.invalid", true}, {"email_empty_domain", 0x81, "a@", true},
		{"uri", 0x86, "example.invalid", true}, {"uri_ip", 0x86, "127.0.0.1", false}, {"uri_empty", 0x86, "", true},
		{"unknown", 0x83, "opaque", true},
	} {
		rows = append(rows, struct {
			name     string
			oid      asn1.ObjectIdentifier
			critical bool
			value    []byte
			want     bool
		}{"constraints_" + row.name, asn1.ObjectIdentifier{2, 5, 29, 30}, false, admissionNames(row.tag, []byte(row.value), true), row.want})
	}
	extension("constraints_ip", 30, false, hex.EncodeToString(admissionNames(0x87, admissionHex("01020304ffffff00"), true)), true)
	extension("constraints_bad_mask", 30, false, hex.EncodeToString(admissionNames(0x87, admissionHex("01020304ff00ff00"), true)), false)
	extension("constraints_opaque_minimum", 30, false, "300aa0083006820161ffffff", true)
	for _, row := range []struct {
		name     string
		critical bool
		value    string
		want     bool
	}{
		{"raw_uri", false, "3008300606012a8601ff", true}, {"critical", true, "3000", false}, {"other_location", false, "3007300506012affff", true}, {"missing_oid", false, "30023000", false},
	} {
		rows = append(rows, struct {
			name     string
			oid      asn1.ObjectIdentifier
			critical bool
			value    []byte
			want     bool
		}{"aia_" + row.name, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}, row.critical, admissionHex(row.value), row.want})
	}
	for _, row := range rows {
		cert := offlineShapeCertificate(key, &key.PublicKey, []pkix.Extension{{Id: row.oid, Critical: row.critical, Value: row.value}})
		if err := certificate(row.name, cert, row.want); err != nil {
			return nil, err
		}
	}
	for _, row := range []struct {
		url  string
		want bool
	}{
		{"https://example.invalid/#\n", true}, {"https://example.invalid/#\x00", true}, {"https://example.invalid/\n#ok", false}, {"https://example.invalid/?q=\n", false},
		{"https://example.invalid/#%zz", false}, {"https://example.invalid/?q=%zz", true}, {"urn:opaque%zz", true}, {"urn:opaque\n", false},
		{"https://%ff.invalid/key", true}, {"https://%fe%ff.invalid/key", true}, {"https://%41.invalid/key", false}, {"https://%25.invalid/key", true},
		{"https://%7f.invalid/key", false}, {"https://host name/key", false}, {"https://user%ff:pass@example.invalid/key", true}, {"https://u%00@example.invalid/key", true},
		{"relative/path#\n", true}, {"//[::1%25zone]/", true}, {"//[::1%25%ff]/", false}, {"//[::1%25]/", false},
		{"http://[example]/", false}, {"POSTGRES://one:42,two:43/", true}, {"https://one:42,two:43/", false}, {"https://host:/", true},
		{"https://example.invalid/%zz", false}, {"https://example.invalid/#%ff", true},
	} {
		jwk := offlineShapeEC(elliptic.P384())
		jwk["x5u"] = row.url
		if err := add("url/"+row.url, "url", `"jwk":`+string(offlineEncode(jwk)), row.want); err != nil {
			return nil, err
		}
	}
	if err := admissionThumbprints(add); err != nil {
		return nil, err
	}
	return fixtures, nil
}
