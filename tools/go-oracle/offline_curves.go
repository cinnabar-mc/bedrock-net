// Synthetic curve controls for the pinned offline Login parser.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"

	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
)

type offlineCurveFixture struct {
	Name     string `json:"name"`
	Request  []byte `json:"request"`
	Accepted bool   `json:"accepted"`
	Signer   string `json:"signer"`
	Exchange string `json:"exchange"`
	P384     bool   `json:"p384"`
}

// curveHash applies ECDSA's leftmost order-bit truncation to SHA384.
func curveHash(input string, c elliptic.Curve) *big.Int {
	digest := sha512.Sum384([]byte(input))
	e := new(big.Int).SetBytes(digest[:])
	if excess := 384 - c.Params().N.BitLen(); excess > 0 {
		e.Rsh(e, uint(excess))
	}
	return e
}

// curveInput uses the existing fixture encoder without trusting a header key.
func curveInput(claims any) string {
	return base64.RawURLEncoding.EncodeToString(offlineEncode(map[string]any{"alg": "ES384", "x5u": "ignored"})) + "." + base64.RawURLEncoding.EncodeToString(offlineEncode(claims))
}

// curveSignature encodes exactly two 48-byte unsigned ES384 integers.
func curveSignature(input string, r, s *big.Int) string {
	raw := make([]byte, 96)
	r.FillBytes(raw[:48])
	s.FillBytes(raw[48:])
	return input + "." + base64.RawURLEncoding.EncodeToString(raw)
}

// curveToken signs only synthetic fixture data, using public fixed scalars and nonces.
func curveToken(c elliptic.Curve, claims any) (string, *ecdsa.PublicKey) {
	input := curveInput(claims)
	x, y := c.ScalarBaseMult([]byte{7})
	key := &ecdsa.PublicKey{Curve: c, X: x, Y: y}
	rx, _ := c.ScalarBaseMult([]byte{13})
	r := new(big.Int).Mod(rx, c.Params().N)
	s := new(big.Int).Mul(r, big.NewInt(7))
	s.Add(s, curveHash(input, c)).Mul(s, new(big.Int).ModInverse(big.NewInt(13), c.Params().N)).Mod(s, c.Params().N)
	digest := sha512.Sum384([]byte(input))
	if !ecdsa.Verify(key, digest[:], r, s) {
		panic("invalid synthetic curve signature")
	}
	if c == elliptic.P521() {
		raw := make([]byte, 132)
		r.FillBytes(raw[:66])
		s.FillBytes(raw[66:])
		return input + "." + base64.RawURLEncoding.EncodeToString(raw), key
	}
	return curveSignature(input, r, s), key
}

// curveRecovered constructs Q=(sR-eG)/r for a bounded signature, without claiming a private Q.
// infinity instead chooses Q=-eG/r so verification must reject its infinity result.
func curveRecovered(c elliptic.Curve, claims any, large, infinity bool) (string, *ecdsa.PublicKey) {
	input := curveInput(claims)
	r, s := big.NewInt(1), big.NewInt(1)
	if large {
		r.Sub(new(big.Int).Lsh(big.NewInt(1), 384), big.NewInt(1))
		s.Set(r)
	}
	var x, y *big.Int
	if !infinity {
		p := c.Params().P
		for {
			rhs := new(big.Int).Exp(r, big.NewInt(3), p)
			rhs.Sub(rhs, new(big.Int).Mul(r, big.NewInt(3))).Add(rhs, c.Params().B).Mod(rhs, p)
			if y = new(big.Int).ModSqrt(rhs, p); y != nil {
				break
			}
			r.Sub(r, big.NewInt(1))
		}
		x, y = c.ScalarMult(r, y, s.Bytes())
	}
	e := curveHash(input, c)
	ex, ey := c.ScalarBaseMult(e.Bytes())
	ey.Sub(c.Params().P, ey)
	if infinity {
		x, y = ex, ey
	} else {
		x, y = c.Add(x, y, ex, ey)
	}
	x, y = c.ScalarMult(x, y, new(big.Int).ModInverse(r, c.Params().N).Bytes())
	key := &ecdsa.PublicKey{Curve: c, X: x, Y: y}
	digest := sha512.Sum384([]byte(input))
	if ecdsa.Verify(key, digest[:], r, s) == infinity {
		panic("synthetic recovered-key control changed")
	}
	return curveSignature(input, r, s), key
}

// offlineCurveFixtures asserts independent Go decisions before returning every synthetic request.
func offlineCurveFixtures() ([]offlineCurveFixture, error) {
	metadata := map[string]any{"DeviceOS": 1, "GameVersion": "1.26.51", "LanguageCode": "en_US", "SkinId": "synthetic", "ThirdPartyName": "CurveName", "ServerAddress": "127.0.0.1:19132"}
	rotated := login.MarshalPublicKey(&offlineKey(9).PublicKey)
	var cases []offlineCurveFixture
	// add frames modern claims and records the expected signer separately from a signed rotation.
	add := func(name, token string, signer *ecdsa.PublicKey, accepted bool, exchange string, p384 bool) {
		cpk := login.MarshalPublicKey(signer)
		claims := map[string]any{"cpk": cpk, "xid": "", "xname": "CurveName"}
		identity := curveInput(claims) + ".AA" // Modern identity signatures are unverified.
		envelope := map[string]any{"Token": identity}
		cases = append(cases, offlineCurveFixture{name, offlineFrame(envelope, token), accepted, cpk, exchange, p384})
	}
	for _, c := range []elliptic.Curve{elliptic.P224(), elliptic.P256(), elliptic.P384()} {
		name := c.Params().Name
		token, key := curveToken(c, metadata)
		cpk := login.MarshalPublicKey(key)
		add(name+"_unchanged", token, key, true, cpk, c == elliptic.P384())
		rotation, _ := curveToken(c, offlineChanged(metadata, "identityPublicKey", rotated))
		add(name+"_rotation", rotation, key, true, rotated, true)
		for _, scalar := range []string{"r_zero", "s_zero", "r_order", "s_order", "r_wide", "s_wide"} {
			parts := strings.Split(token, ".")
			raw, _ := base64.RawURLEncoding.DecodeString(parts[2])
			offset := 0
			if strings.HasPrefix(scalar, "s_") {
				offset = 48
			}
			clear(raw[offset : offset+48])
			if strings.HasSuffix(scalar, "order") {
				c.Params().N.FillBytes(raw[offset : offset+48])
			}
			if strings.HasSuffix(scalar, "wide") {
				for j := range raw[offset : offset+48] {
					raw[offset+j] = 255
				}
			}
			add(name+"_"+scalar, parts[0]+"."+parts[1]+"."+base64.RawURLEncoding.EncodeToString(raw), key, false, "", false)
		}
		bad := strings.Split(token, ".")
		bad[1] = base64.RawURLEncoding.EncodeToString(offlineEncode(offlineChanged(metadata, "SkinId", "tampered")))
		add(name+"_tampered_payload", strings.Join(bad, "."), key, false, "", false)
		bad = strings.Split(token, ".")
		raw, _ := base64.RawURLEncoding.DecodeString(bad[2])
		raw[95] ^= 1
		bad[2] = base64.RawURLEncoding.EncodeToString(raw)
		add(name+"_tampered_signature", strings.Join(bad, "."), key, false, "", false)
		inf, infKey := curveRecovered(c, metadata, false, true)
		add(name+"_infinity", inf, infKey, false, "", false)
		legacy, _ := curveToken(c, map[string]any{"identityPublicKey": rotated, "extraData": map[string]any{"XUID": "", "displayName": "CurveName"}})
		parts := strings.Split(legacy, ".")
		parts[0] = base64.RawURLEncoding.EncodeToString(offlineEncode(map[string]any{"alg": "ES384", "x5u": cpk}))
		// Changing the signed header requires a fresh signature with the same fixed fixture scalar.
		input := parts[0] + "." + parts[1]
		rx, _ := c.ScalarBaseMult([]byte{13})
		r := new(big.Int).Mod(rx, c.Params().N)
		s := new(big.Int).Mul(r, big.NewInt(7))
		s.Add(s, curveHash(input, c)).Mul(s, new(big.Int).ModInverse(big.NewInt(13), c.Params().N)).Mod(s, c.Params().N)
		legacy = curveSignature(input, r, s)
		client := offlineToken(offlineKey(9), "ES384", rotated, metadata)
		cases = append(cases, offlineCurveFixture{Name: name + "_legacy_rotation", Request: offlineFrame(map[string]any{"chain": []string{legacy}}, client), Accepted: true, Signer: rotated, Exchange: rotated, P384: true})
		badDER, _ := base64.StdEncoding.DecodeString(cpk)
		clear(badDER[len(badDER)-2*((c.Params().BitSize+7)/8):])
		identity := curveInput(map[string]any{"cpk": base64.StdEncoding.EncodeToString(badDER)}) + ".AA"
		cases = append(cases, offlineCurveFixture{Name: name + "_invalid_point", Request: offlineFrame(map[string]any{"Token": identity}, token)})
	}
	for _, large := range []bool{false, true} {
		for _, rotate := range []bool{false, true} {
			claims := metadata
			if rotate {
				claims = offlineChanged(metadata, "identityPublicKey", rotated)
			}
			token, key := curveRecovered(elliptic.P521(), claims, large, false)
			exchange := login.MarshalPublicKey(key)
			if rotate {
				exchange = rotated
			}
			add(fmt.Sprintf("P-521_large_%v_rotation_%v", large, rotate), token, key, true, exchange, rotate)
		}
	}
	token, key := curveRecovered(elliptic.P521(), metadata, false, true)
	add("P-521_infinity", token, key, false, "", false)
	token, key = curveRecovered(elliptic.P521(), metadata, true, false)
	for _, part := range []string{"r_zero", "s_zero", "tampered_signature", "tampered_payload"} {
		fields := strings.Split(token, ".")
		raw, _ := base64.RawURLEncoding.DecodeString(fields[2])
		switch part {
		case "r_zero":
			clear(raw[:48])
		case "s_zero":
			clear(raw[48:])
		case "tampered_signature":
			raw[95] ^= 1
		case "tampered_payload":
			fields[1] = base64.RawURLEncoding.EncodeToString(offlineEncode(offlineChanged(metadata, "SkinId", "tampered")))
		}
		fields[2] = base64.RawURLEncoding.EncodeToString(raw)
		add("P-521_"+part, strings.Join(fields, "."), key, false, "", false)
	}
	ordinary, ordinaryKey := curveToken(elliptic.P521(), metadata)
	add("P-521_ordinary_132_bytes", ordinary, ordinaryKey, false, "", false)
	badDER, _ := base64.StdEncoding.DecodeString(login.MarshalPublicKey(key))
	clear(badDER[len(badDER)-132:])
	identity := curveInput(map[string]any{"cpk": base64.StdEncoding.EncodeToString(badDER)}) + ".AA"
	cases = append(cases, offlineCurveFixture{Name: "P-521_invalid_point", Request: offlineFrame(map[string]any{"Token": identity}, token)})

	middle, q := curveRecovered(elliptic.P521(), map[string]any{"iss": "Mojang", "identityPublicKey": rotated}, true, false)
	first := offlineToken(offlineKey(7), "ES384", login.MarshalPublicKey(&offlineKey(7).PublicKey), map[string]any{"identityPublicKey": login.MarshalPublicKey(q)})
	last := offlineToken(offlineKey(9), "ES384", rotated, map[string]any{"iss": "Mojang", "extraData": map[string]any{"XUID": "", "displayName": "CurveName"}})
	client := offlineToken(offlineKey(9), "ES384", rotated, metadata)
	cases = append(cases, offlineCurveFixture{Name: "P-521_legacy_middle_rotation", Request: offlineFrame(map[string]any{"chain": []string{first, middle, last}}, client), Accepted: true, Signer: rotated, Exchange: rotated, P384: true})
	fields := strings.Split(middle, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(fields[2])
	raw[95] ^= 1
	fields[2] = base64.RawURLEncoding.EncodeToString(raw)
	cases = append(cases, offlineCurveFixture{Name: "P-521_legacy_bad_signature", Request: offlineFrame(map[string]any{"chain": []string{first, strings.Join(fields, "."), last}}, client)})
	for i := range cases {
		test := &cases[i]
		identity, _, auth, err := login.Parse(test.Request, nil)
		if (err == nil) != test.Accepted {
			return nil, fmt.Errorf("curve decision changed for %s: %v", test.Name, err)
		}
		if test.Accepted && (auth.XBOXLiveAuthenticated || identity.DisplayName != "CurveName" || login.MarshalPublicKey(auth.PublicKey) != test.Exchange) {
			return nil, fmt.Errorf("curve result changed for %s", test.Name)
		}
	}
	return cases, nil
}
