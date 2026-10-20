package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"os"
	"testing"
)

// TestClientDataCases anchors raw-member fixtures through the complete signed Parse path.
func TestClientDataCases(t *testing.T) {
	encoded, err := os.ReadFile("client-data-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name         string
		Remove       []string
		Claims       string
		ClaimsBase64 string `json:"claims_base64"`
		Accepted     bool
	}
	if err := json.Unmarshal(encoded, &cases); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES384, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	const now = 1800000000
	token, err := jwt.Signed(signer).Claims(map[string]any{
		"iss": "synthetic.invalid", "aud": "synthetic", "exp": now + 3600, "nbf": 0, "iat": 0,
		"ipt": "PlayFab", "mid": "", "tid": "", "cpk": base64.StdEncoding.EncodeToString(der),
		"xid": "2535400000000001", "xname": "Probe",
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(map[string]any{"AuthenticationType": 0, "Token": token})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			base := map[string]any{"DeviceOS": 1, "GameVersion": "1.26.51", "LanguageCode": "en_US", "SkinId": "synthetic", "ThirdPartyName": "Probe"}
			for _, name := range c.Remove {
				delete(base, name)
			}
			payload, err := json.Marshal(base)
			if err != nil {
				t.Fatal(err)
			}
			claims := []byte(c.Claims)
			if c.ClaimsBase64 != "" {
				claims, err = base64.StdEncoding.DecodeString(c.ClaimsBase64)
				if err != nil {
					t.Fatal(err)
				}
			}
			payload = append(payload[:len(payload)-1], ',')
			payload = append(payload, claims...)
			payload = append(payload, '}', '\n')
			signed, err := signer.Sign(payload)
			if err != nil {
				t.Fatal(err)
			}
			client, err := signed.CompactSerialize()
			if err != nil {
				t.Fatal(err)
			}
			request := binary.LittleEndian.AppendUint32(nil, uint32(len(envelope)))
			request = append(request, envelope...)
			request = binary.LittleEndian.AppendUint32(request, uint32(len(client)))
			request = append(request, client...)
			result, err := loginParse(&serveRequest{Request: request, ProviderKey: der, Issuer: "synthetic.invalid", Audience: "synthetic", Now: now})
			if err != nil {
				t.Fatal(err)
			}
			r := result.(map[string]any)
			if r["accepted"] != c.Accepted {
				t.Fatalf("accepted=%v want %v: %v", r["accepted"], c.Accepted, r["reason"])
			}
		})
	}
}
