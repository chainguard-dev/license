/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package assess

// Flag names an ambiguity in a component's licensing evidence. The set is
// closed, so consumers match on these values rather than parsing a rationale.
type Flag string

const (
	// FlagRelationshipAmbiguous means several licenses were identified with
	// nothing authoritative saying how they combine.
	//
	// This is the ambiguity deterministic detection structurally cannot resolve:
	// a tree holding an MIT text and an Apache-2.0 text looks identical whether
	// the author meant "both apply" or "pick one". Getting it wrong is not
	// symmetric, either - reading a conjunction as a choice tells a consumer
	// they may ignore obligations they actually have.
	FlagRelationshipAmbiguous Flag = "relationship-ambiguous"

	// FlagUnidentifiedText means license text is present that the classifier
	// could not identify, or identified below the confidence threshold.
	//
	// It is raised whether or not something else in the component classified
	// cleanly, because the unidentified text may state terms nothing else
	// states.
	FlagUnidentifiedText Flag = "unidentified-text"

	// FlagDeclaredConflict means the licenses detected in the content are not
	// the licenses the component declares.
	//
	// The declaration is not treated as the answer - it is a claim about
	// content, and the content is right there - but a disagreement between the
	// two is a finding in its own right, and the most common way a wrong
	// license reaches a customer is a declaration nobody checked.
	FlagDeclaredConflict Flag = "declared-conflict"
)
