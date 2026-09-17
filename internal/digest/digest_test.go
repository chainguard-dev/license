/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package digest

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// TestFileNormalizesLineEndings covers the one normalization the scheme
// applies: the same license text carries the same terms however it was checked
// out.
func TestFileNormalizesLineEndings(t *testing.T) {
	for _, tt := range []struct{ name, unix, other string }{
		{name: "simple", unix: "a\nb\n", other: "a\r\nb\r\n"},
		{name: "trailing newline", unix: "a\n", other: "a\r\n"},
		{name: "empty lines", unix: "a\n\n\nb\n", other: "a\r\n\r\n\r\nb\r\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if Bytes([]byte(tt.unix)) != Bytes([]byte(tt.other)) {
				t.Errorf("line endings changed the digest for %q", tt.name)
			}
		})
	}
}

// TestFileKeepsOtherDifferencesSignificant is the boundary of that
// normalization: whitespace and case may change terms, so they stay part of the
// identity.
func TestFileKeepsOtherDifferencesSignificant(t *testing.T) {
	base := Bytes([]byte("MIT License\n"))
	for _, other := range []string{
		"mit license\n",
		"MIT  License\n",
		"MIT License",
		" MIT License\n",
		// A lone CR is not a line ending pair, so it is content.
		"MIT\rLicense\n",
	} {
		if Bytes([]byte(other)) == base {
			t.Errorf("%q hashed the same as the original", other)
		}
	}
}

// TestFileHandlesCRAtAChunkBoundary is the case a naive implementation gets
// wrong: whether a trailing CR belongs to a CRLF pair is only knowable from the
// next chunk, and reading the whole file to sidestep that would let one file's
// size decide how much memory the process holds.
func TestFileHandlesCRAtAChunkBoundary(t *testing.T) {
	// Place the CR as the last byte of the first chunk, with its LF first in
	// the next one.
	body := strings.Repeat("x", chunkSize-1) + "\r\n" + strings.Repeat("y", 10)
	streamed, err := File(bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	want := Bytes([]byte(strings.ReplaceAll(body, "\r\n", "\n")))
	if streamed != want {
		t.Errorf("a CRLF split across chunks was not normalized:\n  got  %s\n  want %s", streamed, want)
	}

	// A CR as the very last byte of a file has no successor, so it stays
	// content.
	trailing := strings.Repeat("x", chunkSize-1) + "\r"
	streamed, err = File(bytes.NewReader([]byte(trailing)))
	if err != nil {
		t.Fatal(err)
	}
	if streamed != Bytes([]byte(trailing)) {
		t.Error("a trailing CR was dropped, so a file lost its last byte")
	}
}

// TestFileMatchesBytes verifies the streaming and in-memory paths agree, which
// they must because one file's digest is computed by whichever is convenient.
func TestFileMatchesBytes(t *testing.T) {
	body := []byte(strings.Repeat("license text\r\n", chunkSize/4))
	streamed, err := File(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if streamed != Bytes(body) {
		t.Errorf("streaming and in-memory digests differ:\n  %s\n  %s", streamed, Bytes(body))
	}
}

func TestFileCarriesTheAlgorithm(t *testing.T) {
	got := Bytes([]byte("MIT"))
	if !strings.HasPrefix(got, Prefix) {
		t.Errorf("digest %q does not name its algorithm", got)
	}
	if len(Hex([]byte("MIT"))) != 64 {
		t.Errorf("Hex returned %d characters, want a 64-character sha256", len(Hex([]byte("MIT"))))
	}
}

func TestFileReportsAReadFailure(t *testing.T) {
	if _, err := File(failingReader{}); err == nil {
		t.Error("File over a failing reader: got nil error, want one")
	}
}

// failingReader fails on the first read.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
