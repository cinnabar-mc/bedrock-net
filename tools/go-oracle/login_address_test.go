package main

import (
	"bytes"
	"testing"
)

// TestSplitServerAddress checks the oracle response with literal address forms and byte-preserved hosts.
func TestSplitServerAddress(t *testing.T) {
	for _, tc := range []struct {
		address string
		host    string
		port    uint16
		ok      bool
	}{
		{"host:19132", "host", 19132, true},
		{"https://host:19132:19132", "host", 19132, true},
		{"http://ho%ffst:19132", "ho\xffst", 19132, true},
		{"ftp://host:21", "host", 21, true},
		{":0", "", 0, false},
		{"host:65536", "", 0, false},
	} {
		response, err := handle(&serveRequest{Op: "split_server_address", Address: tc.address})
		if err != nil {
			t.Fatal(err)
		}
		fields := response.(map[string]any)
		if !bytes.Equal(fields["host"].([]byte), []byte(tc.host)) || fields["port"] != tc.port || fields["ok"] != tc.ok {
			t.Fatalf("split %q: %#v", tc.address, fields)
		}
	}
}
