package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// maxFrame bounds one request; the oversized-batch corpus needs tens of MiB.
const maxFrame = 256 << 20

// serveRequest is one length-prefixed JSON request; fields are per op.
type serveRequest struct {
	Op string `json:"op"`

	// Batch codec settings. A nil Compression means before NetworkSettings.
	Compression     *string    `json:"compression"`
	Threshold       int        `json:"threshold"`
	MaxDecompressed int        `json:"max_decompressed"`
	PacketLimit     bool       `json:"packet_limit"`
	Messages        [][]byte   `json:"messages"`
	Batches         [][][]byte `json:"batches"`

	// Login.
	Scalar      []byte          `json:"scalar"`
	ClientData  json.RawMessage `json:"client_data"`
	DisplayName string          `json:"display_name"`
	Identity    string          `json:"identity"`
	Token       string          `json:"token"`
	Request     []byte          `json:"request"`
	ProviderKey []byte          `json:"provider_key"`
	Issuer      string          `json:"issuer"`
	Audience    string          `json:"audience"`
	Now         int64           `json:"now"`
	Address     string          `json:"address"`
}

type decodeResult struct {
	Outcome string   `json:"outcome"`
	Packets [][]byte `json:"packets,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// serve answers framed requests on stdin until EOF, keeping one process per test binary.
func serve(in io.Reader, out io.Writer) error {
	r := bufio.NewReader(in)
	w := bufio.NewWriter(out)
	for {
		var size [4]byte
		if _, err := io.ReadFull(r, size[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		n := binary.LittleEndian.Uint32(size[:])
		if n > maxFrame {
			return fmt.Errorf("request of %d bytes exceeds %d", n, maxFrame)
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(r, data); err != nil {
			return err
		}
		var req serveRequest
		var resp any
		if err := json.Unmarshal(data, &req); err != nil {
			resp = map[string]string{"error": "request: " + err.Error()}
		} else if resp, err = handle(&req); err != nil {
			resp = map[string]string{"error": err.Error()}
		}
		encoded, err := json.Marshal(resp)
		if err != nil {
			return err
		}
		binary.LittleEndian.PutUint32(size[:], uint32(len(encoded)))
		if _, err := w.Write(size[:]); err != nil {
			return err
		}
		if _, err := w.Write(encoded); err != nil {
			return err
		}
		if err := w.Flush(); err != nil {
			return err
		}
	}
}

func handle(req *serveRequest) (any, error) {
	switch req.Op {
	case "decode_batch":
		return decodeBatch(req)
	case "encode_batch":
		return encodeBatch(req)
	case "login_build":
		return loginBuild(req)
	case "login_parse":
		return loginParse(req)
	case "offline_shapes":
		return offlineShapes()
	case "offline_curve_fixtures":
		return offlineCurveFixtures()
	case "offline_encoding_fixtures":
		return offlineEncodingFixtures()
	case "offline_time_fixtures":
		return offlineTimeFixtures()
	case "jose_headers":
		return joseHeaderFixtures()
	case "jose_admission":
		return joseAdmissionFixtures()
	case "offline_json_contexts":
		return offlineJSONContexts()
	case "resolve_udp":
		_, err := net.ResolveUDPAddr("udp", req.Address)
		return map[string]bool{"resolved": err == nil}, nil
	case "offline_fixtures":
		return offlineFixtures()
	default:
		return nil, fmt.Errorf("unknown op %q", req.Op)
	}
}

// transport supplies NetherNet's empty batch header to the codec, like the real transport.
type transport struct {
	frames  [][]byte
	written [][]byte
}

func (t *transport) BatchHeader() []byte {
	return nil
}
func (t *transport) Read([]byte) (int, error) { return 0, io.ErrNoProgress }
func (t *transport) ReadPacket() ([]byte, error) {
	if len(t.frames) == 0 {
		return nil, io.EOF
	}
	frame := t.frames[0]
	t.frames = t.frames[1:]
	return frame, nil
}
func (t *transport) Write(p []byte) (int, error) {
	t.written = append(t.written, bytes.Clone(p))
	return len(p), nil
}

func compressionNamed(name string) (packet.Compression, error) {
	switch name {
	case "flate":
		return packet.FlateCompression, nil
	case "snappy":
		return packet.SnappyCompression, nil
	case "none":
		return packet.NopCompression, nil
	}
	return nil, fmt.Errorf("unknown compression %q", name)
}

// decodeBatch feeds consecutive messages to one Decoder and classifies each result as
// accept ("packets"), "dropped" (ErrBatchDropped) or "fatal"; it stops at the first fatal.
func decodeBatch(req *serveRequest) (any, error) {
	t := &transport{frames: req.Messages}
	d := packet.NewDecoder(t)
	if !req.PacketLimit {
		d.DisableBatchPacketLimit()
	}
	if req.Compression != nil {
		c, err := compressionNamed(*req.Compression)
		if err != nil {
			return nil, err
		}
		d.EnableCompression(c, req.MaxDecompressed)
	}
	results := make([]decodeResult, 0, len(req.Messages))
	for range req.Messages {
		packets, err := d.Decode()
		switch {
		case err == nil:
			if packets == nil {
				packets = [][]byte{}
			}
			results = append(results, decodeResult{Outcome: "packets", Packets: packets})
		case errors.Is(err, packet.ErrBatchDropped):
			results = append(results, decodeResult{Outcome: "dropped", Error: err.Error()})
		default:
			results = append(results, decodeResult{Outcome: "fatal", Error: err.Error()})
			return map[string]any{"results": results}, nil
		}
	}
	return map[string]any{"results": results}, nil
}

// encodeBatch runs one Encoder over consecutive Encode calls and returns each call's writes.
func encodeBatch(req *serveRequest) (any, error) {
	t := &transport{}
	e := packet.NewEncoder(t)
	if req.Compression != nil {
		c, err := compressionNamed(*req.Compression)
		if err != nil {
			return nil, err
		}
		e.EnableCompression(c, req.Threshold)
	}
	results := make([][][]byte, 0, len(req.Batches))
	for _, packets := range req.Batches {
		t.written = nil
		if err := e.Encode(packets); err != nil {
			return nil, err
		}
		results = append(results, t.written)
	}
	return map[string]any{"results": results}, nil
}

func scalarKey(scalar []byte) (*ecdsa.PrivateKey, error) {
	k, err := ecdh.P384().NewPrivateKey(scalar)
	if err != nil {
		return nil, err
	}
	x, y := elliptic.Unmarshal(elliptic.P384(), k.PublicKey().Bytes())
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P384(), X: x, Y: y}, D: new(big.Int).SetBytes(scalar)}, nil
}

// loginBuild formats offline and token requests with the pinned Go encoders.
func loginBuild(req *serveRequest) (any, error) {
	k, err := scalarKey(req.Scalar)
	if err != nil {
		return nil, err
	}
	var data login.ClientData
	if err := json.Unmarshal(req.ClientData, &data); err != nil {
		return nil, err
	}
	offline := login.EncodeOffline(login.IdentityData{DisplayName: req.DisplayName, Identity: req.Identity}, data, k)
	result := map[string]any{"offline": offline}
	if req.Token != "" {
		result["token"] = login.EncodeToken(data, k, req.Token)
	}
	return result, nil
}

// loginParse runs the pinned Go Parse with a static-key OIDC verifier for the supplied provider.
func loginParse(req *serveRequest) (any, error) {
	var verifier *oidc.IDTokenVerifier
	if len(req.ProviderKey) != 0 {
		public, err := x509.ParsePKIXPublicKey(req.ProviderKey)
		if err != nil {
			return nil, err
		}
		now := time.Unix(req.Now, 0)
		verifier = oidc.NewVerifier(req.Issuer, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{public}}, &oidc.Config{
			ClientID: req.Audience, SupportedSigningAlgs: []string{oidc.ES384}, Now: func() time.Time { return now },
		})
	}
	identity, client, auth, err := login.Parse(req.Request, verifier)
	if err != nil {
		return map[string]any{"accepted": false, "reason": err.Error()}, nil
	}
	return map[string]any{
		"accepted":      true,
		"authenticated": auth.XBOXLiveAuthenticated,
		"xuid":          identity.XUID,
		"display_name":  identity.DisplayName,
		"identity":      identity.Identity,
		"third_party":   client.ThirdPartyName,
		"nonce":         client.Nonce,
		"exchange_key":  login.MarshalPublicKey(auth.PublicKey),
	}, nil
}
