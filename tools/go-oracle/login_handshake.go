package main

import (
	"crypto/ecdsa"
	"encoding/base64"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
)

// urlHost returns the standard parser's host bytes without resolving the address.
func urlHost(address string) any {
	parsed, err := url.Parse("http://" + address + "/")
	if err != nil {
		return map[string]any{"accepted": false}
	}
	return map[string]any{"accepted": true, "host": []byte(parsed.Host)}
}

// serverHandshake checks the pinned client's signature, claim shape and salt decoding rules.
func serverHandshake(token string) bool {
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES384})
	if err != nil {
		return false
	}
	public := new(ecdsa.PublicKey)
	text, _ := parsed.Headers[0].ExtraHeaders["x5u"].(string)
	if login.ParsePublicKey(text, public) != nil {
		return false
	}
	var claims struct {
		Salt string `json:"salt"`
	}
	if parsed.Claims(public, &claims) != nil {
		return false
	}
	_, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(claims.Salt, "="))
	return err == nil
}
