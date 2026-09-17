/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package digest computes the file digests this module keys data on.
//
// It exists so that the digest of a license file has one implementation.
// Discovery records it while reading a tree, and the license-content hash
// consumes it; two implementations of the same scheme would eventually disagree,
// and the disagreement would re-key every determination stored under the older
// one.
package digest
