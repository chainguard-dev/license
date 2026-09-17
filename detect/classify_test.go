/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package detect

import (
	"testing"
	"testing/fstest"
)

// TestSupplementIsRecognized is the regression guard the supplement exists to
// be.
//
// A license absent from the classifier's corpus does not come back
// unrecognized - it comes back as the nearest text the corpus does contain, at
// full confidence. Unicode-3.0 is the measured case: every ICU crate in a sweep
// concluded Unicode-DFS-2016, a different license, until its text was supplied.
//
// So each supplied text is classified back to its own identifier here. Without
// this, an upgrade to the classifier that shadowed one of them would restore
// the wrong answer silently, which is precisely how the original defect went
// unnoticed.
func TestSupplementIsRecognized(t *testing.T) {
	supplement := Supplement()
	if len(supplement) == 0 {
		t.Fatal("Supplement returned nothing; the embedded texts are missing")
	}

	c, err := NewClassifier()
	if err != nil {
		t.Fatal(err)
	}

	for id, text := range supplement {
		t.Run(id, func(t *testing.T) {
			matches, err := c.Identify(fstest.MapFS{"LICENSE": &fstest.MapFile{Data: text}}, "LICENSE")
			if err != nil {
				t.Fatalf("Identify: %v", err)
			}
			for _, m := range matches {
				if m.Name == id && m.Confidence >= ConfidenceThreshold {
					return
				}
			}
			t.Errorf("classified as %v, want %q at or above %v", matches, id, ConfidenceThreshold)
		})
	}
}

// TestSupplementNormalizesToItself keeps the supplement keyed on identifiers
// SPDX still lists. A text filed under a name SPDX has deprecated would be
// classified confidently and then publish an identifier nothing accepts.
func TestSupplementNormalizesToItself(t *testing.T) {
	for id := range Supplement() {
		t.Run(id, func(t *testing.T) {
			if got := identifierOf(id); got != id {
				t.Errorf("identifier: got = %q, want = %q; the supplement is keyed on a name SPDX does not carry", got, id)
			}
		})
	}
}

// TestClassifyGoldenLicenses pins the classifications the whole module rests
// on. They come from the corpus rather than from this module, so an upgrade
// that changed one of them would otherwise change every determination in the
// fleet with nothing failing.
func TestClassifyGoldenLicenses(t *testing.T) {
	c, err := NewClassifier()
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct{ fixture, want string }{
		{fixture: "mit.txt", want: "MIT"},
		{fixture: "bsd-2-clause.txt", want: "BSD-2-Clause"},
	} {
		t.Run(tt.fixture, func(t *testing.T) {
			data := readFixture(t, tt.fixture)
			matches, err := c.Identify(fstest.MapFS{"LICENSE": &fstest.MapFile{Data: data}}, "LICENSE")
			if err != nil {
				t.Fatalf("Identify: %v", err)
			}
			if len(matches) == 0 {
				t.Fatalf("%s classified as nothing", tt.fixture)
			}
			if matches[0].Name != tt.want || matches[0].Confidence < ConfidenceThreshold {
				t.Errorf("got = %+v, want %q at or above %v", matches[0], tt.want, ConfidenceThreshold)
			}
		})
	}

	// A copyright notice is not a license text, and must not be classified as
	// one: the file is real evidence, and what it says is that nobody stated
	// the terms here.
	matches, err := c.Identify(fstest.MapFS{
		"COPYRIGHT": &fstest.MapFile{Data: []byte("Copyright (c) 2026 Example Corp. All rights reserved.\n")},
	}, "COPYRIGHT")
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("a bare copyright notice classified as %+v, want nothing", matches)
	}
}

// TestIdentifyBoundsWhatItReads pins the read bound. The classifier consumes
// its reader in chunks but retains a token per word for the whole document, so
// an unbounded read lets an untrusted tree naming a huge file LICENSE decide
// how much memory the caller holds.
func TestIdentifyBoundsWhatItReads(t *testing.T) {
	c, err := NewClassifier()
	if err != nil {
		t.Fatalf("NewClassifier: %v", err)
	}
	var read int64
	fsys := endless{name: "LICENSE", size: 4 * MaxTextBytes, read: &read}
	if _, err := c.Identify(fsys, "LICENSE"); err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if read > MaxTextBytes {
		t.Errorf("bytes read: got = %d, want <= %d", read, int64(MaxTextBytes))
	}
}
