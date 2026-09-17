/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package assess says how much a component's licensing evidence can be trusted.
//
// It answers one question: how complete and how conclusive is what we found.
// It deliberately does not answer two others. It does not decide what the
// license is; detect does that. And it does not decide what to do about a weak
// score: each consumer sets its own threshold, because a build-time warning and
// a decision to spend money on a deeper analysis are not the same bar.
//
// # Score and flags say different things
//
// A score compresses everything into one number, which is what makes it useful
// for a threshold and useless for explaining anything. So the conditions worth
// acting on individually are also reported as flags from a closed enum, and a
// consumer matches on those rather than inferring them from the number or
// parsing the rationale.
//
// # Unknown is not a low score
//
// A low score means the evidence was read and was murky. Unknown means there
// was no evidence to read: the tree could not be supplied, or every file in it
// failed. Collapsing the two would make a fetch failure indistinguishable from
// a genuinely ambiguous component, and those need different handling - one is
// retried, the other is escalated.
package assess
