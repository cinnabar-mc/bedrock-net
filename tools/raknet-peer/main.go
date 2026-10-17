// Command raknet-peer serves one loopback-only transport session for Rust integration tests.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/sandertv/go-raknet"
)

// main parses the single test-mode flag and reports command failures once.
func main() {
	closeAfter := flag.Int("close-after", 0, "close after echoing this many messages; zero echoes until the peer closes")
	flag.Parse()
	if *closeAfter < 0 || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "invalid arguments")
		os.Exit(2)
	}
	if err := run(*closeAfter); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run publishes the ephemeral loopback address, then echoes complete RakNet messages in order.
func run(closeAfter int) (err error) {
	listener, err := raknet.Listen("127.0.0.1:0")
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
