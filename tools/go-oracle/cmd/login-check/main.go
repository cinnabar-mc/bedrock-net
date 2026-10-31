// Command login-check verifies synthetic Rust Login requests and emits a server key exchange.
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/netip"
	"os"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
)

const maxInputBytes = 1024 * 1024

type request struct {
	IdentityToken      string `json:"identity_token"`
	AuthenticationType *uint8 `json:"authentication_type"`
	ConnectionRequest  []byte `json:"request"`
	ClientScalar       []byte `json:"client_scalar"`
	ServerScalar       []byte `json:"server_scalar"`
	Salt               []byte `json:"salt"`
}

type response struct {
	AuthClaims  map[string]json.RawMessage `json:"auth_claims"`
	ClientJSON  []byte                     `json:"client_json"`
	ServerToken string                     `json:"server_token"`
	Name        string                     `json:"name"`
	UUID        string                     `json:"uuid"`
}

// main reports failures once and keeps the command restricted to its stdin fixture protocol.
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run parses and verifies a bounded synthetic request without accounts, assets or network access.
func run() error {
	if len(os.Args) != 1 {
		return errors.New("unexpected arguments")
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, maxInputBytes+1))
	if err != nil {
		return fmt.Errorf("read fixture: %w", err)
	}
	if len(data) > maxInputBytes {
		return errors.New("fixture input is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var input request
	if err := decoder.Decode(&input); err != nil {
		return fmt.Errorf("read fixture: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing fixture input")
	}
	if input.IdentityToken != "" {
		if input.AuthenticationType != nil || len(input.ConnectionRequest) != 0 || len(input.ClientScalar) != 0 || len(input.ServerScalar) != 0 || len(input.Salt) != 0 {
			return errors.New("mixed identity and handshake fixtures")
		}
		return projectIdentity(input.IdentityToken)
	}
	rest := input.ConnectionRequest
	envelope, err := takeField(&rest)
	if err != nil {
		return err
	}
	clientToken, err := takeField(&rest)
	if err != nil {
		return err
	}
	if len(rest) != 0 || envelope[len(envelope)-1] != '\n' {
		return errors.New("invalid outer request formatting")
	}
	var outer struct {
		AuthenticationType uint8  `json:"AuthenticationType"`
		Token              string `json:"Token"`
	}
	outerDecoder := json.NewDecoder(bytes.NewReader(envelope))
	outerDecoder.DisallowUnknownFields()
	if err := outerDecoder.Decode(&outer); err != nil {
		return fmt.Errorf("decode token-only envelope: %w", err)
	}
	expectedType := uint8(2)
	if input.AuthenticationType != nil {
		expectedType = *input.AuthenticationType
	}
	if (expectedType != 0 && expectedType != 2) || outer.AuthenticationType != expectedType {
		return errors.New("unexpected fixture AuthenticationType")
	}
	client, err := ecdh.P384().NewPrivateKey(input.ClientScalar)
	if err != nil {
		return fmt.Errorf("client scalar: %w", err)
	}
	clientX, clientY := elliptic.Unmarshal(elliptic.P384(), client.PublicKey().Bytes())
	if clientX == nil || clientY == nil {
		return errors.New("invalid generated client public key")
	}
	clientPublic := &ecdsa.PublicKey{Curve: elliptic.P384(), X: clientX, Y: clientY}
	claims, _, err := verifyToken(outer.Token, clientPublic)
	if err != nil {
		return err
	}
	_, clientJSON, err := verifyToken(string(clientToken), clientPublic)
	if err != nil {
		return err
	}
	var metadata struct {
		ServerAddress string
	}
	if err := json.Unmarshal(clientJSON, &metadata); err != nil {
		return fmt.Errorf("fixture client data: %w", err)
	}
	address, err := netip.ParseAddrPort(metadata.ServerAddress)
	if err != nil || !address.Addr().IsLoopback() {
		return errors.New("fixture metadata must use a loopback socket address")
	}
	identity, _, auth, err := login.Parse(input.ConnectionRequest, nil)
	if err != nil {
		return fmt.Errorf("parse Rust Login: %w", err)
	}
	if auth.PublicKey == nil || auth.XBOXLiveAuthenticated {
		return errors.New("fixture must produce a self-signed connection key")
	}
	if !auth.PublicKey.Equal(clientPublic) {
		return errors.New("Login public key does not match the connection proof key")
	}
	server, err := ecdh.P384().NewPrivateKey(input.ServerScalar)
	if err != nil {
		return fmt.Errorf("server scalar: %w", err)
	}
	x, y := elliptic.Unmarshal(elliptic.P384(), server.PublicKey().Bytes())
	if x == nil || y == nil {
		return errors.New("invalid generated server public key")
	}
	serverKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P384(), X: x, Y: y},
		D:         new(big.Int).SetBytes(input.ServerScalar),
	}
	options := new(jose.SignerOptions).WithHeader("x5u", login.MarshalPublicKey(&serverKey.PublicKey))
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES384, Key: serverKey}, options)
	if err != nil {
		return fmt.Errorf("server signer: %w", err)
	}
	serverToken, err := jwt.Signed(signer).Claims(struct {
		Salt string `json:"salt"`
	}{Salt: base64.RawStdEncoding.EncodeToString(input.Salt)}).Serialize()
	if err != nil {
		return fmt.Errorf("server token: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(response{
		AuthClaims: claims, ClientJSON: clientJSON, ServerToken: serverToken,
		Name: identity.DisplayName, UUID: identity.Identity,
	})
}

// projectIdentity compares only the pinned Go claim projection, without asserting issuer trust.
// Rust supplies one synthetic token; its separate accepting tests verify actual provider signatures.
func projectIdentity(token string) error {
	identity, err := login.ParseTokenIdentityData(context.Background(), token, nil)
	if err != nil {
		return fmt.Errorf("project synthetic identity: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		XUID           string `json:"xuid"`
		Name           string `json:"name"`
		UUID           string `json:"uuid"`
		PlayFabID      string `json:"playfab_id"`
		PlayFabTitleID string `json:"playfab_title_id"`
	}{identity.XUID, identity.DisplayName, identity.Identity, identity.PlayFabID, identity.PlayFabTitleID})
}

// takeField checks a little-endian field length before slicing the request.
func takeField(rest *[]byte) ([]byte, error) {
	if len(*rest) < 4 {
		return nil, errors.New("truncated request length")
	}
	length := binary.LittleEndian.Uint32((*rest)[:4])
	*rest = (*rest)[4:]
	if length == 0 || uint64(length) > uint64(len(*rest)) {
		return nil, errors.New("invalid request field length")
	}
	field := (*rest)[:length]
	*rest = (*rest)[length:]
	return field, nil
}

// verifyToken checks the signature and line-terminated header/payload representation.
func verifyToken(token string, key *ecdsa.PublicKey) (map[string]json.RawMessage, []byte, error) {
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES384})
	if err != nil {
		return nil, nil, err
	}
	claims := make(map[string]json.RawMessage)
	if err := parsed.Claims(key, &claims); err != nil {
		return nil, nil, fmt.Errorf("verify Rust signature: %w", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("invalid compact token")
	}
	payload := []byte{}
	for index, part := range parts[:2] {
		decoded, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return nil, nil, err
		}
		if len(decoded) == 0 || decoded[len(decoded)-1] != '\n' {
			return nil, nil, errors.New("token JSON must be line terminated")
		}
		if index == 1 {
			payload = decoded
		}
	}
	return claims, payload, nil
}
