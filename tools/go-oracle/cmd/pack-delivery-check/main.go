// Command pack-delivery-check exposes actual pinned Go delivery constants and indexing semantics.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/resource"
)

type chunkCase struct {
	Size      uint64 `json:"size"`
	ChunkSize uint32 `json:"chunk_size"`
}

type countResult struct {
	Count uint32 `json:"count"`
	Valid bool   `json:"valid"`
}

// main reports static fixture diagnostics once; stdout contains only the machine-readable result.
func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run consumes bounded caller-authored synthetic cases, without copied reference constants or policy.
func run(input io.Reader, output io.Writer) error {
	const maxInputBytes = 16 * 1024
	data, err := io.ReadAll(io.LimitReader(input, maxInputBytes+1))
	if err != nil || len(data) > maxInputBytes {
		return errors.New("pack delivery fixture input exceeds its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var cases []chunkCase
	if err := decoder.Decode(&cases); err != nil {
		return errors.New("invalid pack delivery fixture input")
	}
	if len(cases) == 0 || len(cases) > 128 {
		return errors.New("pack delivery fixture count exceeds its bound")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("pack delivery fixture has trailing input")
	}
	counts := make([]countResult, 0, len(cases))
	for _, test := range cases {
		count, valid := resource.ChunkCount(test.Size, test.ChunkSize)
		counts = append(counts, countResult{Count: count, Valid: valid})
	}
	return json.NewEncoder(output).Encode(struct {
		DefaultChunkSize uint32        `json:"default_chunk_size"`
		MaxChunkSize     uint32        `json:"max_chunk_size"`
		Counts           []countResult `json:"counts"`
	}{minecraft.DefaultResourcePackChunkSize, minecraft.MaxResourcePackChunkSize, counts})
}
