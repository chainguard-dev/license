/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package gen derives the SPDX normalization tables from two sources of truth:
// the vendored SPDX license list, and the license names licenseclassifier can
// actually emit.
//
// Nothing here is a judgment about what a license means. The tables are a diff
// between two vocabularies, so upgrading the classifier or refreshing the SPDX
// list changes them mechanically instead of inviting someone to hand-edit an
// identifier.
//
// It is a library so the drift test can regenerate in-process rather than
// shelling out to the go tool, which would couple the test to the caller's
// module mode.
package gen
