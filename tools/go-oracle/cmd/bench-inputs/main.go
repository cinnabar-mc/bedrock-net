// Command bench-inputs writes the deterministic synthetic benchmark inputs under testdata/bench.
package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/cinnabar-mc/bedrock-net/tools/go-oracle/bench"
)

// main writes into the directory named by its only argument.
func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: bench-inputs DIR")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// rng is xorshift64*, chosen so the inputs never depend on a library's generator.
type rng uint64

func (r *rng) next() uint64 {
	*r ^= *r >> 12
	*r ^= *r << 25
	*r ^= *r >> 27
	return uint64(*r) * 2685821657736338717
}

func (r *rng) bytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(r.next() >> 56)
	}
	return out
}

func varuint(buf *bytes.Buffer, v uint32) {
	for v >= 0x80 {
		buf.WriteByte(byte(v) | 0x80)
		v >>= 7
	}
	buf.WriteByte(byte(v))
}

func run(dir string) error {
	r := rng(0x9e3779b97f4a7c15)
	var game bytes.Buffer
	for i := range 64 {
		game.Write(lengthPrefixed(gamePacket(&r, i)))
	}
	var chunk bytes.Buffer
	chunk.Write(lengthPrefixed(chunkPacket(&r)))
	clientData, err := clientDataJSON()
	if err != nil {
		return err
	}
	trailer, err := packTrailer()
	if err != nil {
		return err
	}
	for name, data := range map[string][]byte{
		"game_packets.bin": game.Bytes(),
		"chunk_packet.bin": chunk.Bytes(),
		"client_data.json": clientData,
		"pack_trailer.zip": trailer,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return err
		}
	}
	// Digests are computed from the files just written, through the shared loader.
	bench.Dir = dir
	cases, err := bench.Load()
	if err != nil {
		return err
	}
	digests, err := cases.ComputeDigests()
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(digests, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "digests.json"), append(out, '\n'), 0o644)
}

// packTrailer is a stored, manifest-only resource pack zip with fixed timestamps.
func packTrailer() ([]byte, error) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	manifest := `{"format_version":2,"header":{"name":"Bench","description":"synthetic","uuid":"00000000-0000-4000-8000-0000000000b1","version":[1,0,0],"min_engine_version":[1,20,0]},"modules":[{"type":"resources","uuid":"00000000-0000-4000-8000-0000000000b2","version":[1,0,0]}]}`
	f, err := w.CreateHeader(&zip.FileHeader{Name: "manifest.json", Method: zip.Store, Modified: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		return nil, err
	}
	if _, err := f.Write([]byte(manifest)); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func lengthPrefixed(packet []byte) []byte {
	var buf bytes.Buffer
	varuint(&buf, uint32(len(packet)))
	buf.Write(packet)
	return buf.Bytes()
}

// gamePacket mixes movement-like floats, text and small control packets of varied sizes.
func gamePacket(r *rng, i int) []byte {
	var buf bytes.Buffer
	switch i % 8 {
	case 0, 3: // movement: runtime ID, position/rotation floats, flags
		varuint(&buf, 0x13)
		varuint(&buf, 1)
		base := float32(i) * 1.5
		for j := range 6 {
			bits := math.Float32bits(base + float32(j)*0.25)
			buf.Write([]byte{byte(bits), byte(bits >> 8), byte(bits >> 16), byte(bits >> 24)})
		}
		buf.Write([]byte{0, 1, 0})
		varuint(&buf, uint32(i*20))
	case 1: // text
		varuint(&buf, 0x09)
		buf.WriteByte(1)
		msg := fmt.Sprintf("<Player%02d> synthetic chat message number %d for compression benchmarks", i, i)
		varuint(&buf, uint32(len(msg)))
		buf.WriteString(msg)
	case 2: // set time
		varuint(&buf, 0x0a)
		varuint(&buf, uint32(i*100))
	case 4: // actor metadata: structured, partly random
		varuint(&buf, 0x27)
		varuint(&buf, uint32(i))
		for j := range 24 {
			varuint(&buf, uint32(j))
			buf.WriteByte(byte(j % 7))
			buf.Write(r.bytes(4))
		}
	case 5: // level sound event
		varuint(&buf, 0x7b)
		varuint(&buf, 42)
		buf.Write(r.bytes(12))
		buf.WriteString("minecraft:player")
	case 6: // move delta
		varuint(&buf, 0x6f)
		varuint(&buf, uint32(i))
		buf.Write(r.bytes(14))
	case 7: // inventory-like payload with item NBT-ish structure
		varuint(&buf, 0x31)
		for j := range 36 {
			varuint(&buf, uint32(j))
			buf.Write([]byte{0x0a, 0x00, 0x00, 0x03, 0x05, 'C', 'o', 'u', 'n', 't'})
			buf.Write(r.bytes(2))
			buf.WriteByte(0)
		}
	}
	return buf.Bytes()
}

// chunkPacket is a LevelChunk-shaped payload: paletted sub-chunks with run-heavy indices plus noise.
func chunkPacket(r *rng) []byte {
	var buf bytes.Buffer
	varuint(&buf, 0x3a)
	varuint(&buf, 3)
	varuint(&buf, 7)
	varuint(&buf, 24)
	for sub := range 24 {
		buf.WriteByte(9)
		buf.WriteByte(1)
		buf.WriteByte(byte(sub))
		buf.WriteByte(4 << 1)
		words := make([]byte, 4096/8*4)
		for w := 0; w < len(words); w += 4 {
			n := r.next()
			if n%4 == 0 {
				copy(words[w:], r.bytes(4))
			} else {
				fill := byte(sub % 16 * 0x11)
				words[w], words[w+1], words[w+2], words[w+3] = fill, fill, fill, fill
			}
		}
		buf.Write(words)
		varuint(&buf, 16)
		for p := range 16 {
			varuint(&buf, uint32(p*977+sub))
		}
	}
	for range 24 {
		buf.WriteByte(1)
		varuint(&buf, 2)
	}
	buf.Write(r.bytes(64))
	return buf.Bytes()
}

// clientDataJSON is a valid synthetic ClientData with a solid 64x64 skin.
func clientDataJSON() ([]byte, error) {
	skin := bytes.Repeat([]byte{0x80, 0x80, 0x80, 0xff}, 64*64)
	geometry := `{"format_version":"1.12.0","minecraft:geometry":[{"description":{"identifier":"geometry.humanoid.custom","texture_width":64,"texture_height":64},"bones":[{"name":"root","pivot":[0,0,0],"cubes":[{"origin":[-4,0,-2],"size":[8,24,4],"uv":[0,0]}]}]}]}`
	data := map[string]any{
		"AnimatedImageData":                []any{},
		"ArmSize":                          "wide",
		"CapeData":                         "",
		"CapeId":                           "",
		"CapeImageHeight":                  0,
		"CapeImageWidth":                   0,
		"CapeOnClassicSkin":                false,
		"ClientRandomId":                   1,
		"CompatibleWithClientSideChunkGen": false,
		"CurrentInputMode":                 2,
		"DefaultInputMode":                 2,
		"DeviceId":                         "0123456789abcdef0123456789abcdef",
		"DeviceModel":                      "Synthetic Bench",
		"DeviceOS":                         1,
		"GameVersion":                      "1.26.50",
		"GuiScale":                         0,
		"IsEditorMode":                     false,
		"LanguageCode":                     "en_GB",
		"MaxViewDistance":                  16,
		"MemoryTier":                       4,
		"PersonaPieces":                    []any{},
		"PersonaSkin":                      false,
		"PieceTintColors":                  []any{},
		"PlatformOfflineId":                "",
		"PlatformOnlineId":                 "",
		"PlatformType":                     1,
		"PlayFabId":                        "",
		"PremiumSkin":                      false,
		"SelfSignedId":                     "00000000-0000-4000-8000-000000000002",
		"ServerAddress":                    "127.0.0.1:19132",
		"SkinAnimationData":                "",
		"SkinColor":                        "#0",
		"SkinData":                         base64.StdEncoding.EncodeToString(skin),
		"SkinGeometryData":                 base64.StdEncoding.EncodeToString([]byte(geometry)),
		"SkinGeometryDataEngineVersion":    base64.StdEncoding.EncodeToString([]byte("1.14.60")),
		"SkinId":                           "00000000-0000-4000-8000-000000000002_Custom",
		"SkinImageHeight":                  64,
		"SkinImageWidth":                   64,
		"SkinResourcePatch":                base64.StdEncoding.EncodeToString([]byte(`{"geometry":{"default":"geometry.humanoid.custom"}}`)),
		"ThirdPartyName":                   "BenchProbe",
		"ThirdPartyNameOnly":               false,
		"TrustedSkin":                      false,
		"UIProfile":                        0,
	}
	out, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return out, nil
}
