/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package digest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// Prefix names the digest algorithm, in the "<algo>:<hex>" convention the rest
// of the fleet writes digests in.
const Prefix = "sha256:"

// chunkSize is how much of a file is read at a time. License texts are
// kilobytes, so this reads most of them in one pass while keeping a hostile
// file from being held whole in memory.
const chunkSize = 32 << 10

// File returns the digest of a license file's contents, with line endings
// normalized.
//
// CRLF is converted to LF before hashing, because the same license text carries
// the same terms however it was checked out, and a Windows checkout of a
// vendored dependency must not read as a different license from a Unix one.
// Nothing else is normalized: whitespace and case differences stay significant,
// since a license text that differs in either may differ in its terms.
//
// The consequence worth stating plainly is that this does not match a plain
// sha256sum of the file on disk for a file with CRLF line endings.
func File(r io.Reader) (string, error) {
	sum, err := hashNormalized(r)
	if err != nil {
		return "", err
	}
	return Prefix + hex.EncodeToString(sum), nil
}

// Bytes returns the digest of contents already in memory, by the same rules as
// File.
func Bytes(b []byte) string {
	sum, _ := hashNormalized(bytes.NewReader(b))
	return Prefix + hex.EncodeToString(sum)
}

// Hex returns the digest of contents already in memory as bare hexadecimal,
// for callers that render it into a name of their own rather than a
// "<algo>:<hex>" digest.
func Hex(b []byte) string {
	sum, _ := hashNormalized(bytes.NewReader(b))
	return hex.EncodeToString(sum)
}

// hashNormalized streams r through sha256, dropping the CR of every CRLF pair.
//
// A CR at the end of a chunk is held back rather than emitted, because whether
// it belongs to a CRLF pair is only knowable from the next chunk's first byte.
// Reading the whole file to sidestep that would let one file's size decide how
// much memory the process holds.
func hashNormalized(r io.Reader) ([]byte, error) {
	h := sha256.New()
	in := make([]byte, chunkSize)
	out := make([]byte, 0, chunkSize+1)
	heldCR := false

	for {
		n, err := r.Read(in)
		if n > 0 {
			chunk := in[:n]
			out = out[:0]
			if heldCR {
				if chunk[0] != '\n' {
					out = append(out, '\r')
				}
				heldCR = false
			}
			for i, b := range chunk {
				if b != '\r' {
					out = append(out, b)
					continue
				}
				// Whether this CR belongs to a CRLF pair is only knowable from
				// the byte after it, which the next chunk holds when the CR is
				// the last byte of this one.
				next := chunk[i+1:]
				if len(next) == 0 {
					heldCR = true
					break
				}
				if next[0] != '\n' {
					out = append(out, b)
				}
			}
			h.Write(out)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if heldCR {
		h.Write([]byte{'\r'})
	}
	return h.Sum(nil), nil
}
