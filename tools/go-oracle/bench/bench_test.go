package bench

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

// capture records every batch an Encoder writes; copies are taken only when kept.
type capture struct {
	keep   bool
	frames [][]byte
}

func (c *capture) Write(p []byte) (int, error) {
	if c.keep {
		c.frames = append(c.frames, bytes.Clone(p))
	}
	return len(p), nil
}

// queue feeds prepared batches to a Decoder, one per ReadPacket.
type queue struct {
	frames [][]byte
	next   int
	cycle  bool
}

func (q *queue) Read([]byte) (int, error) { return 0, io.ErrNoProgress }

func (q *queue) ReadPacket() ([]byte, error) {
	if q.next == len(q.frames) {
		if !q.cycle {
			return nil, io.EOF
		}
		q.next = 0
	}
	frame := q.frames[q.next]
	q.next++
	return frame, nil
}

func load(b *testing.B) *Cases {
	b.Helper()
	c, err := Load()
	if err != nil {
		b.Fatal(err)
	}
	return c
}

// packets expands a packet set and proves it matches the input the Rust benches read.
func packets(b *testing.B, c *Cases, set string) [][]byte {
	b.Helper()
	p, err := c.Packets(set)
	if err != nil {
		b.Fatal(err)
	}
	digests, err := LoadDigests()
	if err != nil {
		b.Fatal(err)
	}
	h := sha256.New()
	for _, packet := range p {
		h.Write(packet)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != digests.PacketSets[set] {
		b.Fatalf("packet set %s digest %s, digests.json has %s", set, got, digests.PacketSets[set])
	}
	return p
}

// verifyFrames decodes frames with a fresh, unlimited decoder and requires exactly want, in
// order. Each benchmark checks its own output this way once, outside the timed loop.
func verifyFrames(b *testing.B, frames [][]byte, compression packet.Compression, key *[32]byte, want [][]byte) {
	b.Helper()
	var got [][]byte
	if compression == nil && key == nil {
		// The plain Decoder caps batches at 16 MiB, so the oversized split input is walked here.
		for _, frame := range frames {
			data := frame[1:]
			for len(data) > 0 {
				var n uint32
				var i int
				for shift := 0; ; shift += 7 {
					n |= uint32(data[i]&0x7f) << shift
					i++
					if data[i-1]&0x80 == 0 {
						break
					}
				}
				got = append(got, data[i:i+int(n)])
				data = data[i+int(n):]
			}
		}
	} else {
		d := packet.NewDecoder(&queue{frames: frames})
		d.DisableBatchPacketLimit()
		d.EnableCompression(compression, -1)
		if key != nil {
			d.EnableEncryption(*key)
		}
		for range frames {
			pks, err := d.Decode()
			if err != nil {
				b.Fatalf("decode own output: %v", err)
			}
			got = append(got, pks...)
		}
	}
	if len(got) != len(want) {
		b.Fatalf("own output decodes to %d packets, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			b.Fatalf("own output packet %d differs from the input", i)
		}
	}
}

func ignore([]byte) error { return nil }

// codecGroup runs encode/decode style cases for one compression setting (nil = before NetworkSettings).
func codecGroup(b *testing.B, group string, compression packet.Compression) {
	c := load(b)
	threshold := c.CompressionThreshold
	if len(c.Cases(group)) == 0 {
		b.Fatalf("cases.json lists no %s cases", group)
	}
	for _, tc := range c.Cases(group) {
		pks := packets(b, c, tc.Set)
		b.Run(tc.Name(), func(b *testing.B) {
			enc := func(w io.Writer) *packet.Encoder {
				e := packet.NewEncoder(w)
				if compression != nil {
					e.EnableCompression(compression, threshold)
				}
				return e
			}
			b.SetBytes(Size(pks))
			b.ReportAllocs()
			switch tc.Op {
			case "encode", "compress":
				w := &capture{keep: true}
				if err := enc(w).Encode(pks); err != nil {
					b.Fatal(err)
				}
				verifyFrames(b, w.frames, compression, nil, pks)
				e := enc(&capture{})
				b.ResetTimer()
				for range b.N {
					if err := e.Encode(pks); err != nil {
						b.Fatal(err)
					}
				}
			case "decode", "decompress":
				w := &capture{keep: true}
				if err := enc(w).Encode(pks); err != nil {
					b.Fatal(err)
				}
				if len(w.frames) != 1 {
					b.Fatalf("decode input %s spans %d batches", tc.Set, len(w.frames))
				}
				verifyFrames(b, w.frames, compression, nil, pks)
				d := packet.NewDecoder(&queue{frames: w.frames, cycle: true})
				d.DisableBatchPacketLimit()
				if compression != nil {
					d.EnableCompression(compression, 0)
				}
				b.ResetTimer()
				for range b.N {
					if err := d.DecodeFunc(ignore); err != nil {
						b.Fatal(err)
					}
				}
			default:
				b.Fatalf("unknown op %s", tc.Op)
			}
		})
	}
}

func BenchmarkBatchFraming(b *testing.B) { codecGroup(b, "BatchFraming", nil) }
func BenchmarkFlate(b *testing.B)        { codecGroup(b, "Flate", packet.FlateCompression) }
func BenchmarkSnappy(b *testing.B)       { codecGroup(b, "Snappy", packet.SnappyCompression) }

// BenchmarkEncryption measures the negotiated uncompressed (0xff) path with batch encryption.
func BenchmarkEncryption(b *testing.B) {
	c := load(b)
	var key [32]byte
	for i := range key {
		key[i] = c.EncryptionKeyByte
	}
	if len(c.Cases("Encryption")) == 0 {
		b.Fatal("cases.json lists no Encryption cases")
	}
	for _, tc := range c.Cases("Encryption") {
		pks := packets(b, c, tc.Set)
		b.Run(tc.Name(), func(b *testing.B) {
			// Two consecutive frames from a fresh stream must decrypt and decode to the input.
			check := &capture{keep: true}
			ce := packet.NewEncoder(check)
			ce.EnableCompression(packet.NopCompression, 0)
			ce.EnableEncryption(key)
			for range 2 {
				if err := ce.Encode(pks); err != nil {
					b.Fatal(err)
				}
			}
			verifyFrames(b, check.frames, packet.NopCompression, &key, append(append([][]byte{}, pks...), pks...))
			w := &capture{}
			e := packet.NewEncoder(w)
			e.EnableCompression(packet.NopCompression, 0)
			e.EnableEncryption(key)
			b.SetBytes(Size(pks))
			b.ReportAllocs()
			switch tc.Op {
			case "encrypt":
				for range b.N {
					if err := e.Encode(pks); err != nil {
						b.Fatal(err)
					}
				}
			case "decrypt":
				// Decryption consumes each frame in stream order and in place, so frames are
				// produced in lockstep chunks outside the timer.
				q := &queue{}
				d := packet.NewDecoder(q)
				d.DisableBatchPacketLimit()
				d.EnableCompression(packet.NopCompression, 0)
				d.EnableEncryption(key)
				chunk := max(1, min(4096, int((64<<20)/max(Size(pks), 1))))
				refill := func() {
					w.keep, w.frames = true, w.frames[:0]
					for range chunk {
						if err := e.Encode(pks); err != nil {
							b.Fatal(err)
						}
					}
					q.frames, q.next = w.frames, 0
				}
				refill()
				b.ResetTimer()
				for range b.N {
					if q.next == len(q.frames) {
						b.StopTimer()
						refill()
						b.StartTimer()
					}
					if err := d.DecodeFunc(ignore); err != nil {
						b.Fatal(err)
					}
				}
			default:
				b.Fatalf("unknown op %s", tc.Op)
			}
		})
	}
}

// fixedKey derives the deterministic P-384 key whose scalar is fill repeated 48 times.
func fixedKey(b *testing.B, fill byte) *ecdsa.PrivateKey {
	scalar := bytes.Repeat([]byte{fill}, 48)
	k, err := ecdh.P384().NewPrivateKey(scalar)
	if err != nil {
		b.Fatal(err)
	}
	x, y := elliptic.Unmarshal(elliptic.P384(), k.PublicKey().Bytes())
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P384(), X: x, Y: y}, D: new(big.Int).SetBytes(scalar)}
}

func BenchmarkLogin(b *testing.B) {
	c := load(b)
	l := c.Login
	raw, err := os.ReadFile(filepath.Join(Dir, l.ClientData))
	if err != nil {
		b.Fatal(err)
	}
	var clientData login.ClientData
	if err := json.Unmarshal(raw, &clientData); err != nil {
		b.Fatal(err)
	}
	client := fixedKey(b, l.ClientScalarByte)
	provider := fixedKey(b, l.ProviderScalarByte)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES384, Key: provider}, nil)
	if err != nil {
		b.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(map[string]any{
		"iss": l.Issuer, "aud": l.Audience, "exp": l.Expiry, "nbf": 0, "iat": 0,
		"ipt": "PlayFab", "mid": "", "tid": "", "cpk": login.MarshalPublicKey(&client.PublicKey),
		"xid": l.XUID, "xname": l.DisplayName,
	}).Serialize()
	if err != nil {
		b.Fatal(err)
	}
	verifier := oidc.NewVerifier(l.Issuer, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&provider.PublicKey}}, &oidc.Config{
		ClientID: l.Audience, SupportedSigningAlgs: []string{oidc.ES384}, Now: func() time.Time { return time.Unix(l.Expiry-3600, 0) },
	})
	request := login.EncodeToken(clientData, client, token)
	identity := login.IdentityData{DisplayName: l.DisplayName, Identity: l.Identity}
	// Each case checks its own output once: the request parses, signatures verify where the
	// parser verifies them, and the identity survives.
	if id, _, _, err := login.Parse(login.EncodeOffline(identity, clientData, client), nil); err != nil || id.DisplayName != clientData.ThirdPartyName {
		b.Fatalf("own offline request: %v", err)
	}
	if id, _, _, err := login.Parse(login.EncodeToken(clientData, client, token), verifier); err != nil || id.XUID != l.XUID {
		b.Fatalf("own token request: %v", err)
	}
	if id, _, _, err := login.Parse(request, verifier); err != nil || id.XUID != l.XUID {
		b.Fatalf("verified identity: %v", err)
	}
	b.Run("encode_offline", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			_ = login.EncodeOffline(identity, clientData, client)
		}
	})
	b.Run("encode_token", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			_ = login.EncodeToken(clientData, client, token)
		}
	})
	b.Run("verify_token", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, _, _, err := login.Parse(request, verifier); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkPacks(b *testing.B) {
	c := load(b)
	names := make([]string, 0, len(c.Packs.Archives))
	for name := range c.Packs.Archives {
		names = append(names, name)
	}
	for _, name := range sorted(names) {
		size := c.Packs.Archives[name]
		archive, err := c.Archive(size)
		if err != nil {
			b.Fatal(err)
		}
		digests, err := LoadDigests()
		if err != nil {
			b.Fatal(err)
		}
		want := sha256.Sum256(archive)
		if hex.EncodeToString(want[:]) != digests.Archives[name] {
			b.Fatalf("archive %s differs from the input the Rust benches read", name)
		}
		chunkSize := c.Packs.ChunkSize
		count, _ := resource.ChunkCount(size, chunkSize)
		b.Run("assemble_verify_"+name, func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for range b.N {
				a, err := resource.NewAssembler(size, chunkSize)
				if err != nil {
					b.Fatal(err)
				}
				for i := range count {
					off := uint64(i) * uint64(chunkSize)
					done, err := a.Add(i, archive[off:min(off+uint64(chunkSize), size)])
					if err != nil {
						b.Fatal(err)
					}
					if done != (i == count-1) {
						b.Fatalf("assembler reported completion %v after chunk %d of %d", done, i, count)
					}
				}
				// Pack opens the assembled bytes and hashes them, as the Rust transfer verifies its own.
				pack, err := a.Pack()
				if err != nil {
					b.Fatal(err)
				}
				if pack.Checksum() != want || uint64(pack.Size()) != size {
					b.Fatal("assembled archive differs from the input")
				}
			}
		})
		b.Run("sha256_"+name, func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for range b.N {
				if sha256.Sum256(archive) != want {
					b.Fatal("hash changed")
				}
			}
		})
	}
}

func sorted(s []string) []string {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	return s
}
