// Original selected-field mutations of synthetic certificates; signatures remain independent.
package main

import "bytes"

// admissionCoreCertificate records one explicit certificate admission expectation.
type admissionCoreCertificate struct {
	name string
	der  []byte
	want bool
}

// admissionField replaces one TBS field while retaining all other original bytes.
func admissionField(cert []byte, index int, field []byte) []byte {
	outer := admissionFields(cert)
	tbs := admissionFields(outer[0])
	tbs[index] = field
	outer[0] = admissionDER(0x30, bytes.Join(tbs, nil))
	return admissionDER(0x30, bytes.Join(outer, nil))
}

// admissionSPKI builds the required public-key fields, leaving their contents untouched.
func admissionSPKI(algorithm, key []byte) []byte {
	return admissionDER(0x30, append(admissionDER(0x30, algorithm), admissionDER(3, append([]byte{0}, key...))...))
}

// admissionCoreCertificates covers interpreted names, validity, algorithms and public-key fields.
func admissionCoreCertificates(base []byte) []admissionCoreCertificate {
	var rows []admissionCoreCertificate
	// field gives every case a separately named, signed-consumer carrier.
	field := func(name string, index int, value []byte, want bool) {
		rows = append(rows, admissionCoreCertificate{name, admissionField(base, index, value), want})
	}
	for _, row := range []struct {
		name, value string
		want        bool
	}{
		{"null", "0500", false}, {"integer", "020101", false}, {"constructed_utf8", "2c00", false},
		{"universal_string", "1c0400000041", false}, {"utf8_empty", "0c00", true}, {"utf8_unicode", "0c02c3a9", true},
		{"utf8_overlong", "0c02c080", false}, {"utf8_surrogate", "0c03eda080", false},
		{"printable_extensions", "13032a2641", true}, {"printable_underscore", "13015f", false},
		{"numeric", "1203312032", true}, {"numeric_letter", "120141", false},
		{"ia5_controls", "1602007f", true}, {"ia5_high", "160180", false}, {"t61_bytes", "140200ff", true},
		{"bmp_empty", "1e00", true}, {"bmp_text", "1e0200e9", true}, {"bmp_terminator", "1e0400410000", true},
		{"bmp_odd", "1e0100", false}, {"bmp_surrogate", "1e02d800", false},
		{"bmp_noncharacter", "1e02fdd0", false}, {"bmp_ffff", "1e02ffff", false}, {"bmp_fffe", "1e02fffe", false},
	} {
		name := admissionDER(0x30, admissionDER(0x31, admissionDER(0x30, append(admissionHex("0603550403"), admissionHex(row.value)...))))
		for _, index := range []int{3, 5} {
			prefix := map[int]string{3: "issuer/", 5: "subject/"}[index]
			field(prefix+row.name, index, name, row.want)
		}
	}
	attribute := admissionHex("300806035504030c0141")
	for _, row := range []struct {
		name string
		der  []byte
		want bool
	}{
		{"empty", admissionDER(0x30, nil), true}, {"empty_set", admissionHex("30023100"), true},
		{"attribute_tail", admissionHex("300d310b300906035504030c0141ff"), true},
		{"multiple_attributes", admissionDER(0x30, admissionDER(0x31, append(append([]byte(nil), attribute...), attribute...))), true},
		{"attribute_missing_value", admissionHex("3009310730050603550403"), false},
		{"attribute_bad_oid", admissionHex("30083106300406000c00"), false},
		{"attribute_large_oid", admissionHex("300e310c300a06068180808080000c00"), false},
		{"set_bad_tail", admissionDER(0x30, admissionDER(0x31, append(append([]byte(nil), attribute...), 0xff))), false},
		{"name_bad_tail", admissionDER(0x30, append(admissionDER(0x31, attribute), 0xff)), false},
	} {
		for _, index := range []int{3, 5} {
			prefix := map[int]string{3: "issuer/", 5: "subject/"}[index]
			field(prefix+row.name, index, row.der, row.want)
		}
	}
	for _, row := range []struct {
		name, text string
		tag        byte
		want       bool
	}{
		{"utc_seconds", "500101000000Z", 23, true}, {"utc_minutes", "5001010000Z", 23, true},
		{"utc_offset", "500101000000+0130", 23, true}, {"utc_minutes_offset", "5001010000-0130", 23, true},
		{"utc_zero_offset", "500101000000+0000", 23, false}, {"utc_negative_zero", "500101000000-0000", 23, false},
		{"utc_24h_offset", "500101000000+2400", 23, true}, {"utc_2459_offset", "500101000000-2459", 23, true},
		{"utc_25h_offset", "500101000000+2500", 23, false}, {"utc_60m_offset", "500101000000+0060", 23, false},
		{"utc_leap", "000229000000Z", 23, true}, {"utc_bad_leap", "990229000000Z", 23, false},
		{"utc_bad_hour", "500101240000Z", 23, false}, {"utc_leap_second", "500101000060Z", 23, false},
		{"utc_fraction", "500101000000.0Z", 23, false}, {"utc_missing_minutes", "50010100Z", 23, false},
		{"general_seconds", "20500101000000Z", 24, true}, {"general_missing_seconds", "205001010000Z", 24, false},
		{"general_offset", "20500101000000-0130", 24, true}, {"general_zero_offset", "20500101000000+0000", 24, false},
		{"general_24h_offset", "20500101000000+2400", 24, true}, {"general_2459_offset", "20500101000000-2459", 24, true},
		{"general_60m_offset", "20500101000000+0060", 24, false}, {"general_fraction", "20500101000000.1Z", 24, false},
		{"general_comma", "20500101000000,0Z", 24, false}, {"general_year_zero", "00000229000000Z", 24, true},
		{"general_bad_leap", "19000229000000Z", 24, false}, {"general_leap", "20000229000000Z", 24, true},
		{"general_last_year", "99991231235959Z", 24, true}, {"general_bad_month", "20501301000000Z", 24, false},
		{"general_bad_day", "20500231000000Z", 24, false}, {"general_bad_hour", "20500101240000Z", 24, false},
		{"general_lower_z", "20500101000000z", 24, false}, {"general_zone_colon", "20500101000000+01:30", 24, false},
		{"general_no_zone", "20500101000000", 24, false}, {"general_trailing", "20500101000000ZZ", 24, false},
	} {
		for position := 0; position < 2; position++ {
			values := [][]byte{admissionDER(23, []byte("700101000000Z")), admissionDER(23, []byte("700101000001Z"))}
			values[position] = admissionDER(row.tag, []byte(row.text))
			prefix := []string{"not_before/", "not_after/"}[position]
			field(prefix+row.name, 4, admissionDER(0x30, bytes.Join(values, nil)), row.want)
		}
	}
	validity := admissionFields(admissionFields(base)[0])[4]
	field("validity_ignored_tail", 4, admissionDER(0x30, append(bytes.Join(admissionFields(validity), nil), 0xff)), true)
	field("validity_missing_second", 4, admissionDER(0x30, admissionDER(23, []byte("700101000000Z"))), false)
	rsa := admissionHex("06092a864886f70d0101010500")
	for _, row := range []struct {
		name, bits string
		want       bool
	}{
		{"minimal", "3006020101020103", true}, {"nonminimal_modulus_tlv", "300702810101020103", false},
		{"nonminimal_exponent_tlv", "300702010102810103", false}, {"ignored_inner_tail", "3007020101020103ff", true},
		{"ignored_outer_tail", "3006020101020103ff", true}, {"modulus_nonminimal", "300702020001020103", false},
		{"modulus_zero", "3006020100020103", false}, {"modulus_negative", "30060201ff020103", false},
		{"modulus_sign_octet", "300702020080020103", true}, {"exponent_zero", "3006020101020100", false},
		{"exponent_negative", "30060201010201ff", false}, {"exponent_max", "300d02010102087fffffffffffffff", true},
		{"exponent_overflow", "300e0201010209008000000000000000", false}, {"missing_exponent", "3003020101", false},
		{"nonminimal_sequence", "308106020101020103", false}, {"wrong_modulus_tag", "3006040101020103", false},
	} {
		field("rsa/"+row.name, 6, admissionSPKI(rsa, admissionHex(row.bits)), row.want)
	}
	for _, row := range []struct {
		name, algorithm string
		want            bool
	}{
		{"missing_params", "06092a864886f70d010101", false}, {"wrong_params", "06092a864886f70d0101010400", false},
		{"opaque_ai_tail", "06092a864886f70d0101010500ff", true}, {"nonempty_null", "06092a864886f70d010101050100", false},
		{"nonminimal_null", "06092a864886f70d010101058100", false},
	} {
		field("rsa/"+row.name, 6, admissionSPKI(admissionHex(row.algorithm), admissionHex("3006020101020103")), row.want)
	}
	for _, row := range []struct {
		name, algorithm, bits string
		want                  bool
	}{
		{"dsa_minimal", "06072a8648ce3804013009020101020101020101", "020101", true},
		{"dsa_inner_tail", "06072a8648ce380401300a020101020101020101ff", "020101ff", true},
		{"dsa_nonminimal_y", "06072a8648ce3804013009020101020101020101", "02810101", false},
		{"dsa_nonminimal_p", "06072a8648ce380401300a02810101020101020101", "020101", false},
		{"dsa_zero_p", "06072a8648ce3804013009020100020101020101", "020101", false},
		{"dsa_missing_g", "06072a8648ce3804013006020101020101", "020101", false},
		{"dsa_zero_y", "06072a8648ce3804013009020101020101020101", "020100", false},
		{"ed25519", "06032b6570", "0000000000000000000000000000000000000000000000000000000000000000", true},
		{"ed25519_params", "06032b65700500", "0000000000000000000000000000000000000000000000000000000000000000", false},
		{"ed25519_short", "06032b6570", "00", false},
		{"x25519", "06032b656e", "0000000000000000000000000000000000000000000000000000000000000000", true},
		{"x25519_params", "06032b656e0500", "0000000000000000000000000000000000000000000000000000000000000000", true},
		{"x25519_short", "06032b656e", "00", true},
		{"unknown", "06022a03", "", true}, {"unknown_opaque_parameter", "06022a033001ff", "ff", true},
		{"unknown_bad_parameter", "06022a03ff", "", false}, {"unknown_bad_oid", "0600", "", false},
	} {
		field("spki/"+row.name, 6, admissionSPKI(admissionHex(row.algorithm), admissionHex(row.bits)), row.want)
	}
	spki := admissionFields(admissionFields(base)[0])[6]
	field("spki/ec_ignored_tail", 6, admissionDER(0x30, append(bytes.Join(admissionFields(spki), nil), 0xff)), true)
	for _, row := range []struct {
		name, algorithm string
		want            bool
	}{
		{"unknown", "06022a03", true}, {"opaque_parameter", "06022a033001ff", true},
		{"ignored_ai_tail", "06022a030500ff", true}, {"bad_parameter", "06022a03ff", false}, {"bad_oid", "0600", false},
	} {
		cert := admissionField(base, 2, admissionDER(0x30, admissionHex(row.algorithm)))
		outer := admissionFields(cert)
		outer[1] = admissionDER(0x30, admissionHex(row.algorithm))
		rows = append(rows, admissionCoreCertificate{"signature/" + row.name, admissionDER(0x30, bytes.Join(outer, nil)), row.want})
	}
	field("version_int64_wrap", 0, admissionDER(0xa0, admissionHex("02087fffffffffffffff")), true)
	return rows
}
