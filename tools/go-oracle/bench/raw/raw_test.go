package raw

import (
	"bytes"
	"io"
	"testing"

	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

var packetsSink []minecraft.RawPacket

// discard accepts encoded batches without retaining or copying their payload.
type discard struct{}

// BatchHeader selects the unprefixed transport envelope.
func (discard) BatchHeader() []byte { return nil }

// Write represents synchronous output admission without a network scheduler.
func (discard) Write(p []byte) (int, error) { return len(p), nil }

// rawBody builds the same 64-packet inputs as bedrock-client-tokio's raw benchmark.
func rawBody(selected bool) []byte {
	var data []byte
	if selected {
		buf := new(bytes.Buffer)
		_ = (&packet.Header{PacketID: packet.IDSetTime}).Write(buf)
		pk := &packet.SetTime{Time: 7}
		pk.Marshal(protocol.NewWriter(buf, 0))
		data = buf.Bytes()
	} else {
		data = append([]byte{0xff, 7}, bytes.Repeat([]byte{0xaa}, 4096)...)
	}
	var body []byte
	for range 64 {
		body = packet.AppendBatchPacket(body, data)
	}
	return body
}

// BenchmarkRaw measures framing, raw views, selected decoding and outgoing framing.
func BenchmarkRaw(b *testing.B) {
	for _, selected := range []bool{false, true} {
		name := "forward_opaque"
		if selected {
			name = "forward_selected"
		}
		b.Run(name, func(b *testing.B) {
			body := rawBody(selected)
			encoder := packet.NewEncoder(discard{})
			pool := packet.NewServerPool()
			if selected {
				entries, err := packet.SplitBatch(body, false)
				if err != nil {
					b.Fatal(err)
				}
				decoded, err := minecraft.DecodePacket(entries[0], pool, 0, true)
				if value, ok := decoded.(*packet.SetTime); err != nil || !ok || value.Time != 7 {
					b.Fatalf("selected fixture: %T %v", decoded, err)
				}
			}
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for b.Loop() {
				data, err := packet.SplitBatch(body, false)
				if err != nil {
					b.Fatal(err)
				}
				raw := make([]minecraft.RawPacket, len(data))
				for index, entry := range data {
					var header packet.Header
					if err := header.Read(bytes.NewBuffer(entry)); err != nil {
						b.Fatal(err)
					}
					raw[index] = minecraft.RawPacket{ID: header.PacketID, Data: entry}
					if selected {
						decoded, err := minecraft.DecodePacket(entry, pool, 0, true)
						if err != nil {
							b.Fatal(err)
						}
						raw[index].Decoded = []packet.Packet{decoded}
					}
				}
				if len(raw) != 64 {
					b.Fatal(io.ErrUnexpectedEOF)
				}
				packetsSink = raw
				if err := encoder.Encode(data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
