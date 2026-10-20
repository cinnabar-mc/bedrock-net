// Package bench holds gophertunnel benchmarks over the inputs in testdata/bench, named to pair
// with the criterion benches in this repository.
package bench

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Dir is the shared input directory, relative to this package.
var Dir = filepath.Join("..", "..", "..", "testdata", "bench")

// Cases mirrors testdata/bench/cases.json.
type Cases struct {
	PacketSets map[string]struct {
		File   string `json:"file"`
		Repeat int    `json:"repeat"`
	} `json:"packet_sets"`
	Benches              map[string][]string `json:"benches"`
	CompressionThreshold int                 `json:"compression_threshold"`
	EncryptionKeyByte    byte                `json:"encryption_key_byte"`
	Packs                struct {
		Source    string            `json:"source"`
		ChunkSize uint32            `json:"chunk_size"`
		Archives  map[string]uint64 `json:"archives"`
	} `json:"packs"`
	Login struct {
		ClientData         string `json:"client_data"`
		ClientScalarByte   byte   `json:"client_scalar_byte"`
		ProviderScalarByte byte   `json:"provider_scalar_byte"`
		Issuer             string `json:"issuer"`
		Audience           string `json:"audience"`
		XUID               string `json:"xuid"`
		DisplayName        string `json:"display_name"`
		Identity           string `json:"identity"`
		Expiry             int64  `json:"expiry"`
	} `json:"login"`
}

// Load reads the manifest.
func Load() (*Cases, error) {
	data, err := os.ReadFile(filepath.Join(Dir, "cases.json"))
	if err != nil {
		return nil, err
	}
	var c Cases
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Packets expands a named packet set into its packets, in order.
func (c *Cases) Packets(set string) ([][]byte, error) {
	spec, ok := c.PacketSets[set]
	if !ok {
		return nil, fmt.Errorf("unknown packet set %q", set)
	}
	data, err := os.ReadFile(filepath.Join(Dir, spec.File))
	if err != nil {
		return nil, err
	}
	base, err := split(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", spec.File, err)
	}
	out := make([][]byte, 0, len(base)*spec.Repeat)
	for range spec.Repeat {
		out = append(out, base...)
	}
	return out, nil
}

// Archive builds a pack archive of size bytes by repeating the source file.
func (c *Cases) Archive(size uint64) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(Dir, c.Packs.Source))
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, size)
	for uint64(len(out)) < size {
		out = append(out, data[:min(uint64(len(data)), size-uint64(len(out)))]...)
	}
	return out, nil
}

// Cases lists `op_set` names for a manifest group (`Group/op`), sorted.
func (c *Cases) Cases(group string) []Case {
	var out []Case
	for key, sets := range c.Benches {
		g, op, ok := strings.Cut(key, "/")
		if !ok || g != group {
			continue
		}
		for _, set := range sets {
			out = append(out, Case{Op: op, Set: set})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// Case is one benchmark operation over one packet set.
type Case struct{ Op, Set string }

// Name is the shared sub-benchmark name.
func (c Case) Name() string { return c.Op + "_" + c.Set }

// split parses varuint32-length-prefixed entries.
func split(data []byte) ([][]byte, error) {
	var out [][]byte
	r := bytes.NewReader(data)
	for r.Len() > 0 {
		var n uint32
		for shift := 0; ; shift += 7 {
			b, err := r.ReadByte()
			if err != nil || shift > 28 {
				return nil, fmt.Errorf("bad length prefix")
			}
			n |= uint32(b&0x7f) << shift
			if b&0x80 == 0 {
				break
			}
		}
		if int(n) > r.Len() {
			return nil, fmt.Errorf("truncated entry")
		}
		entry := make([]byte, n)
		_, _ = r.Read(entry)
		out = append(out, entry)
	}
	return out, nil
}

// Size sums packet lengths, the throughput unit both sides report.
func Size(packets [][]byte) int64 {
	var n int64
	for _, p := range packets {
		n += int64(len(p))
	}
	return n
}
