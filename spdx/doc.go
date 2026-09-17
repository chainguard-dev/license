/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package spdx is the SPDX vocabulary: it normalizes license names onto SPDX
// identifiers, reads SPDX expressions, and answers questions about them.
//
// # Normalization
//
// The identifiers a classifier produces and the identifiers upstreams declare
// are both, routinely, not SPDX. licenseclassifier emits names that were never
// SPDX (Apache-with-LLVM-Exception, BSD-0-Clause) and names SPDX has since
// deprecated (LGPL-3.0, GPL-2.0-with-classpath-exception). Ecosystem metadata
// carries free prose and bare URLs. Comparing those against a declared
// expression without normalizing first reports disagreements that are only
// spelling, and publishing them unnormalized puts non-SPDX text in a
// licenseConcluded field.
//
// One class cannot be normalized, only reported: the GPL family's -only versus
// -or-later distinction. SPDX ships identical text for both forms, so no
// classifier can tell them apart from a license file. Normalize reports those
// identifiers as needing a grant, and the caller resolves it from the notice in
// the component's own source.
//
// # Expressions
//
// Parse reads an expression into a form that can be asked two questions, so
// that no consumer hand-rolls SPDX semantics from string matching.
//
// Identifiers is the exposure view: every identifier the expression names,
// including one from each OR branch, because this package does not elect a
// branch. A license combined with a WITH exception stays one identifier, since
// the exception is what makes the terms bearable and dropping it would report
// obligations the consumer does not have.
//
// Satisfies is the evaluation view: whether the expression can be met by a set
// of identifiers the caller accepts. An OR is satisfied by any one branch and
// an AND by all of them, which is the rule substring matching gets wrong in the
// direction that matters - "MIT OR GPL-3.0-only" is acceptable to a consumer
// that accepts MIT, and reads as unacceptable to anything scanning for the
// string "GPL".
//
// # What it will not do
//
// It does not rank families by restrictiveness. Family reports which family an
// identifier belongs to; which families a consumer will accept, and in what
// order, is a policy question with a different owner.
//
// It does not resolve a bare family name. "GPL" and "BSD" name no particular
// license, and mapping one to a guess would invent a fact the metadata does not
// contain.
package spdx
