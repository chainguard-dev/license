/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package detect finds the license files in a tree and identifies what they
// are.
//
// It is the shared implementation of a step that used to exist in three
// diverging copies: in melange's build-time license check, in the evaluation of
// an upstream release, and in the License Oracle. They differ in what they do
// with the answer, not in how the answer is reached.
//
// # Discovery is scoping, identification is a conclusion
//
// Discovery decides which files are worth reading, by filename and by where
// they sit. It is a cost and attribution heuristic: a depth cap keeps a sweep
// affordable, and an ignored-directory list keeps a dependency's license from
// being read as the project's own. Neither is a claim about licensing, which is
// why the license-content hash in contenthash does not use them - two copies
// differing only in a subdirectory's license must not hash alike.
//
// Identification is separate and comes second. Classifying a COPYING file
// against a corpus of license texts is an act of conclusion, so it is reported
// with the confidence it was reached at, and a caller can re-run it against
// retained text later without re-reading the tree.
//
// # Input
//
// Every entry point takes an fs.FS. A live build workspace, an unpacked
// package, an expanded archive and an in-memory fixture are the same input, so
// there is no separate code path for any of them and no test needs a
// filesystem.
//
// # Failure is per file
//
// An unreadable file records its own error and does not discard the results for
// the others. A caller can therefore tell a tree with no license evidence from
// a tree it could not finish reading, and decide for itself which of those
// should fail its own operation.
package detect
