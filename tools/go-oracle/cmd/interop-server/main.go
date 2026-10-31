// Command interop-server accepts one loopback client through the pinned gophertunnel stack.
//
// It prints one JSON line with the address and Go's defaults, serves the named scenario,
// then prints one JSON result line. Listener scenarios use minecraft.Listen; scripted
// scenarios send packet orders a Listener never produces, through the same packet codec.
package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

// packChunkSize keeps the synthetic pack above the Go request window in chunk count.
const packChunkSize = 1024

// deadline bounds the whole helper so an unresponsive client cannot leave it running.
const deadline = 60 * time.Second

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: interop-server SCENARIO")
		os.Exit(2)
	}
	time.AfterFunc(deadline, func() {
		report(map[string]any{"result": "timeout"})
		os.Exit(1)
	})
	err := run(os.Args[1])
	result := map[string]any{"result": "ok"}
	if err != nil {
		result = map[string]any{"result": "error", "error": err.Error()}
	}
	report(result)
}

func report(v any) {
	data, _ := json.Marshal(v)
	fmt.Println(string(data))
}

func announce(addr net.Addr, chunks int) {
	report(map[string]any{
		"address":          addr.String(),
		"request_window":   minecraft.DefaultResourcePackMaxInFlightChunks,
		"pack_chunk_count": chunks,
		"protocol":         protocol.CurrentProtocol,
	})
}

func run(scenario string) error {
	switch scenario {
	case "flate", "snappy", "threshold", "chunk-pack", "url-pack":
		return listen(scenario)
	case "startgame-without-packs", "packs-info-before-login-success", "pack-stack-before-login-success",
		"transfer-before-login-success", "disconnect-before-login-success":
		return scripted(scenario)
	}
	return fmt.Errorf("unknown scenario %q", scenario)
}

// syntheticPack builds a minimal resource pack whose archive spans many small chunks.
func syntheticPack() ([]byte, error) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	manifest := `{"format_version":2,"header":{"name":"Interop","description":"synthetic","uuid":"00000000-0000-4000-8000-0000000000aa","version":[1,0,0],"min_engine_version":[1,20,0]},"modules":[{"type":"resources","uuid":"00000000-0000-4000-8000-0000000000ab","version":[1,0,0]}]}`
	f, err := w.CreateHeader(&zip.FileHeader{Name: "manifest.json", Method: zip.Store})
	if err != nil {
		return nil, err
	}
	if _, err := f.Write([]byte(manifest)); err != nil {
		return nil, err
	}
	// Stored, patterned filler so the archive is ~150 chunks regardless of compression.
	f, err = w.CreateHeader(&zip.FileHeader{Name: "filler.bin", Method: zip.Store})
	if err != nil {
		return nil, err
	}
	filler := make([]byte, 150*packChunkSize)
	for i := range filler {
		filler[i] = byte(i * 31)
	}
	if _, err := f.Write(filler); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func listen(scenario string) (err error) {
	cfg := minecraft.ListenConfig{
		AuthenticationDisabled: true,
		Compression:            packet.FlateCompression,
		ResourcePackDelivery:   minecraft.ResourcePackDeliveryConfig{ChunkSize: packChunkSize},
	}
	chunks := 0
	switch scenario {
	case "snappy":
		cfg.Compression = packet.SnappyCompression
	case "threshold":
		cfg.CompressionThreshold = 512
	case "chunk-pack", "url-pack":
		archive, err := syntheticPack()
		if err != nil {
			return err
		}
		pack, err := resource.ReadBytes(archive)
		if err != nil {
			return err
		}
		chunks = pack.DataChunkCount(packChunkSize)
		if scenario == "url-pack" {
			server, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				return err
			}
			go http.Serve(server, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(archive) }))
			pack = pack.WithDownloadURL("http://" + server.Addr().String() + "/pack.zip")
		}
		cfg.ResourcePacks = []*resource.Pack{pack}
		cfg.TexturePacksRequired = true
	}
	network, closeNetwork, err := loopbackNetwork()
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, closeNetwork()) }()
	l, err := cfg.ListenNetwork(network, "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer l.Close()
	announce(l.Addr(), chunks)
	c, err := l.Accept()
	if err != nil {
		return err
	}
	conn := c.(*minecraft.Conn)
	defer conn.Close()
	if err := conn.StartGame(minecraft.GameData{WorldName: "interop"}); err != nil {
		return fmt.Errorf("start game: %w", err)
	}
	// An ID no protocol version assigns, to check that raw bytes still reach the client.
	if err := conn.WritePacket(&packet.Unknown{PacketID: 0x3ff, Payload: []byte{1, 2, 3}}); err != nil {
		return err
	}
	if err := conn.WritePacket(&packet.Disconnect{Message: "interop complete"}); err != nil {
		return err
	}
	if err := conn.Flush(); err != nil {
		return err
	}
	// Stay connected until the client closes, so the final batch is delivered.
	for {
		if _, err := conn.ReadPacket(); err != nil {
			return nil
		}
	}
}

// scriptedConn frames generated Go packets over one NetherNet connection without encryption.
type scriptedConn struct {
	conn net.Conn
	enc  *packet.Encoder
	dec  *packet.Decoder
}

func (s *scriptedConn) write(pks ...packet.Packet) error {
	var batch [][]byte
	for _, pk := range pks {
		var buf bytes.Buffer
		h := packet.Header{PacketID: pk.ID()}
		if err := h.Write(&buf); err != nil {
			return err
		}
		pk.Marshal(protocol.NewWriter(&buf, 0))
		batch = append(batch, buf.Bytes())
	}
	return s.enc.Encode(batch)
}

// read returns the next client packet with the given ID, skipping others.
func (s *scriptedConn) read(id uint32, pk packet.Packet) error {
	for {
		packets, err := s.dec.Decode()
		if err != nil {
			return err
		}
		for _, data := range packets {
			buf := bytes.NewBuffer(data)
			var h packet.Header
			if err := h.Read(buf); err != nil {
				return err
			}
			if h.PacketID != id {
				continue
			}
			if pk != nil {
				pk.Marshal(protocol.NewReader(buf, 0, false))
			}
			return nil
		}
	}
}

// drain keeps the connection open until the client closes it, so the last batch is delivered.
func (s *scriptedConn) drain() error {
	for {
		if _, err := s.dec.Decode(); err != nil {
			return nil
		}
	}
}

func scripted(scenario string) (err error) {
	network, closeNetwork, err := loopbackNetwork()
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, closeNetwork()) }()
	l, err := network.Listen("127.0.0.1:0")
	if err != nil {
		return err
	}
	defer l.Close()
	announce(l.Addr(), 0)
	conn, err := l.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	s := &scriptedConn{conn: conn, enc: packet.NewEncoder(conn), dec: packet.NewDecoder(conn)}
	if err := s.read(packet.IDRequestNetworkSettings, nil); err != nil {
		return err
	}
	if err := s.write(&packet.NetworkSettings{CompressionThreshold: 1, CompressionAlgorithm: packet.FlateCompression.EncodeCompression()}); err != nil {
		return err
	}
	s.enc.EnableCompression(packet.FlateCompression, 1)
	s.dec.EnableCompression(packet.FlateCompression, 0)
	var loginPk packet.Login
	if err := s.read(packet.IDLogin, &loginPk); err != nil {
		return err
	}
	if _, _, _, err := login.Parse(loginPk.ConnectionRequest, nil); err != nil {
		return fmt.Errorf("parse login: %w", err)
	}
	success := &packet.PlayStatus{Status: packet.PlayStatusLoginSuccess}
	switch scenario {
	case "startgame-without-packs":
		if err := s.write(success, &packet.StartGame{WorldName: "interop", EntityRuntimeID: 1, EntityUniqueID: 1}); err != nil {
			return err
		}
		if err := s.write(&packet.ItemRegistry{}); err != nil {
			return err
		}
		var radius packet.RequestChunkRadius
		if err := s.read(packet.IDRequestChunkRadius, &radius); err != nil {
			return err
		}
		if err := s.write(&packet.ChunkRadiusUpdated{ChunkRadius: radius.ChunkRadius},
			&packet.PlayStatus{Status: packet.PlayStatusPlayerSpawn}); err != nil {
			return err
		}
		var initialized packet.SetLocalPlayerAsInitialised
		if err := s.read(packet.IDSetLocalPlayerAsInitialised, &initialized); err != nil {
			return err
		}
		if initialized.EntityRuntimeID != 1 {
			return errors.New("client initialized the wrong runtime ID")
		}
		if err := s.write(&packet.Disconnect{Message: "interop complete"}); err != nil {
			return err
		}
		return s.drain()
	case "packs-info-before-login-success", "pack-stack-before-login-success":
		stack := &packet.ResourcePackStack{BaseGameVersion: protocol.CurrentVersion}
		initial := []packet.Packet{&packet.ResourcePacksInfo{}}
		earlyStack := scenario == "pack-stack-before-login-success"
		if earlyStack {
			initial = append(initial, stack)
		}
		initial = append(initial, success)
		if err := s.write(initial...); err != nil {
			return err
		}
		var response packet.ResourcePackClientResponse
		if err := s.read(packet.IDResourcePackClientResponse, &response); err != nil {
			return err
		}
		if !earlyStack {
			if err := s.write(stack); err != nil {
				return err
			}
		}
		if err := s.read(packet.IDResourcePackClientResponse, &response); err != nil {
			return err
		}
		if response.Response != packet.PackResponseCompleted {
			return errors.New("client did not complete the pack stack")
		}
		if err := s.write(&packet.Disconnect{Message: "interop complete"}); err != nil {
			return err
		}
		return s.drain()
	case "transfer-before-login-success":
		if err := s.write(&packet.Transfer{Address: "127.0.0.1", Port: 19133}); err != nil {
			return err
		}
		return s.drain()
	case "disconnect-before-login-success":
		if err := s.write(&packet.Disconnect{Message: "interop refused"}); err != nil {
			return err
		}
		return s.drain()
	}
	return nil
}
