// Command raknet-peer serves one loopback-only transport session for Rust integration tests.
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/sandertv/go-raknet"
)

// main parses the loopback fixture options and reports command failures once.
func main() {
	closeAfter := flag.Int("close-after", 0, "close after echoing this many messages; zero echoes until the peer closes")
	ipv6 := flag.Bool("ipv6", false, "listen on IPv6 loopback instead of IPv4")
	reportUptime := flag.Bool("report-uptime", false, "send the remote uptime before echoing messages")
	flag.Parse()
	if *closeAfter < 0 || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "invalid arguments")
		os.Exit(2)
	}
	if err := run(*closeAfter, *ipv6, *reportUptime); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run publishes the ephemeral loopback address, then echoes complete RakNet messages in order.
func run(closeAfter int, ipv6, reportUptime bool) (err error) {
	address := "127.0.0.1:0"
	if ipv6 {
		address = "[::1]:0"
	}
	listener, err := raknet.Listen(address)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer func() { err = errors.Join(err, listener.Close()) }()
	if _, err := fmt.Fprintln(os.Stdout, listener.Addr()); err != nil {
		return fmt.Errorf("publish address: %w", err)
	}
	raw, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	conn := raw.(*raknet.Conn)
	defer func() { err = errors.Join(err, conn.Close()) }()
	if reportUptime {
		message := make([]byte, 9)
		message[0] = 0xfe
		binary.LittleEndian.PutUint64(message[1:], uint64(conn.SystemUptime().Milliseconds()))
		if _, err := conn.Write(message); err != nil {
			return fmt.Errorf("report uptime: %w", err)
		}
	}
	for count := 0; closeAfter == 0 || count < closeAfter; count++ {
		message, err := conn.ReadPacket()
		if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		if _, err := conn.Write(message); err != nil {
			return fmt.Errorf("echo: %w", err)
		}
	}
	if err := conn.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	<-conn.Context().Done()
	return nil
}
