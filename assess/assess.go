/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package assess

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"chainguard.dev/license/component"
	"chainguard.dev/license/detect"
	"chainguard.dev/license/spdx"
)

// Partial credit for the project-license term when no license text classifies
// but a weaker signal exists. A machine-readable manifest field is trusted more
// than free prose in a README, and both are trusted less than a classified
// license text.
const (
	manifestCredit = 0.8
	proseCredit    = 0.5
)

// proseChoiceCredit is the relationship certainty an explicit choice-of-license
// statement in the project's own prose earns.
//
// Slightly below the 1.0 a manifest expression earns, because prose is not a
// machine-readable field about this component and could in principle be
// describing something bundled inside it. Deliberately high enough that clean
// license texts plus an explicit statement settle the component, and low enough
// that a single unidentifiable text still keeps the score down.
const proseChoiceCredit = 0.95

// Input is the evidence one component's licensing is judged from.
//
// It is the same shape for a package's own source tree and for a published
// module, so both are graded by identical rules. Nothing in it comes from a
// downstream packaging declaration except Declared, which is compared against
// the rest rather than counted as evidence for it.
type Input struct {
	// Files are the classified license files found in the component, with their
	// exclusions already marked. Files out of scope are ignored: a vendored
	// dependency's license says nothing about this component.
	Files []detect.File
	// Manifests are the component's own author-declared license fields.
	Manifests []component.Manifest
	// Prose are license mentions in the component's own prose, the weakest
	// signal and, for ecosystems with no manifest license field, the only one
	// that can settle how several licenses combine.
	Prose []detect.ProseHint
	// Declared is the expression a downstream consumer declared for this
	// component, when there is one. It earns no credit - it is not evidence
	// about the content - and exists here only so a disagreement with the
	// content can be reported.
	Declared string
	// Incomplete records evidence that could not be gathered at all: a tree the
	// subject could not supply, an artifact that would not download. Its
	// presence is what makes an assessment Unknown rather than merely low.
	Incomplete []string
}

// Assessment is how far the evidence goes.
type Assessment struct {
	// Score runs from 0 to 1, higher meaning more complete and more conclusive
	// evidence. It is meaningless when Unknown is set.
	Score float64 `json:"score"`
	// Unknown reports that there was no evidence to weigh. A consumer must
	// branch on this before reading Score: the two mean different things and
	// call for different handling.
	Unknown bool `json:"unknown,omitempty"`
	// Flags are the ambiguities found, sorted so the value is stable.
	Flags []Flag `json:"flags,omitempty"`
	// Relationship is the operator composing several detected licenses, when
	// something established one. Only spdx.OperatorOr is ever inferred, and
	// only from an explicit statement; see choiceOfLicenseRes for why the other
	// direction is never inferred.
	Relationship string `json:"relationship,omitempty"`
	// Identifiers are the distinct SPDX identifiers detected in scope, sorted.
	Identifiers []string `json:"identifiers,omitempty"`
	// LicenseFiles counts the in-scope license files the score was drawn from.
	// Zero distinguishes a component that ships no license text at all from one
	// whose text could not be identified: the same low score, but only the
	// second has anything for a deeper look to read.
	LicenseFiles int `json:"license_files"`
	// Rationale spells out the terms behind the score, for a human reading a
	// report. Nothing should parse it; the flags are the machine-readable part.
	Rationale string `json:"rationale"`

	// The three terms behind Score, kept so a low score can be attributed
	// rather than merely reported.
	ProjectLicense float64 `json:"project_license"`
	TextResolution float64 `json:"text_resolution"`
	Relation       float64 `json:"relation"`
}

// Assess scores a component's own licensing from the evidence found in its
// content.
//
// Score is the product of three terms, so a zero in any one of them is
// decisive. They are conditions that all have to hold before deterministic
// detection can be trusted, not contributions to be averaged.
//
//   - Project license: the strongest signal naming the component's own license,
//     which is the best in-scope classifier confidence, with partial credit for
//     a manifest field or prose when no license text classifies at all.
//   - Text resolution: the fraction of in-scope license texts that classified
//     confidently. An unidentified license text is a real gap, and it stays a
//     gap even when another file in the same component classified cleanly.
//   - Relation: whether several detected licenses have something authoritative
//     composing them.
//
// Dependency resolution is deliberately absent. It measures the closure rather
// than this component, and folding it in would let one unresolvable dependency
// discredit evidence that is perfectly good - and send a deeper analysis to
// re-read source that cannot possibly contain that dependency's license.
func Assess(in Input) Assessment {
	inScope := inScopeFiles(in.Files)
	a := Assessment{
		LicenseFiles: len(inScope),
		Identifiers:  detectedIdentifiers(inScope),
	}

	if unknown, why := isUnknown(in, inScope); unknown {
		a.Unknown = true
		a.Rationale = why
		return a
	}

	project, projectSrc := projectLicense(in, inScope)
	resolution, resolved, total := textResolution(inScope)
	relation, relationSrc, operator := relationCertainty(in, a.Identifiers)

	a.ProjectLicense, a.TextResolution, a.Relation = project, resolution, relation
	a.Score = project * resolution * relation
	a.Relationship = operator
	a.Rationale = fmt.Sprintf(
		"project license %.2f (%s); text resolution %.2f (%d/%d classified); relation %.2f (%s); score %.2f",
		project, projectSrc, resolution, resolved, total, relation, relationSrc, a.Score)

	if relation == 0 {
		a.Flags = append(a.Flags, FlagRelationshipAmbiguous)
	}
	if resolved < total {
		a.Flags = append(a.Flags, FlagUnidentifiedText)
	}
	if conflictsWithDeclared(in.Declared, a.Identifiers) {
		a.Flags = append(a.Flags, FlagDeclaredConflict)
	}
	// Sorted rather than in the order the conditions happen to be written, so
	// the field matches what its documentation promises and reordering the
	// checks above cannot change a serialized assessment.
	slices.Sort(a.Flags)
	return a
}

// inScopeFiles returns the files that are evidence about the component itself.
func inScopeFiles(files []detect.File) []detect.File {
	var out []detect.File
	for _, f := range files {
		if f.InScope() {
			out = append(out, f)
		}
	}
	return out
}

// detectedIdentifiers lists the distinct identifiers classified confidently in
// scope.
//
// Every identifier a file carries counts, not only its strongest. One file can
// hold two license texts - a LICENSE that appends a bundled dependency's terms
// is the common shape - and reporting one of them would settle the component on
// a subset of what it is actually under, which is the direction of error that
// tells a consumer they may ignore obligations they have. File.Identifiers
// already applies the confidence threshold and drops names that map to no
// identifier.
func detectedIdentifiers(files []detect.File) []string {
	found := map[string]struct{}{}
	for _, f := range files {
		for _, id := range f.Identifiers() {
			found[id] = struct{}{}
		}
	}
	if len(found) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(found))
}

// isUnknown reports whether there was no evidence to weigh, and why.
//
// The test is that nothing was read and something stopped it from being read.
// A component that was read completely and simply ships no license text is not
// unknown - that is a component whose evidence is thin, which is a low score
// and a coverage gap, and the two must not be confused: one is retried, the
// other is escalated.
func isUnknown(in Input, inScope []detect.File) (bool, string) {
	readable := 0
	failed := 0
	for _, f := range inScope {
		if f.Err != "" {
			failed++
			continue
		}
		readable++
	}
	if readable > 0 || len(in.Manifests) > 0 || len(in.Prose) > 0 {
		return false, ""
	}
	switch {
	case len(in.Incomplete) > 0:
		return true, "no evidence: " + strings.Join(in.Incomplete, "; ")
	case failed > 0:
		return true, fmt.Sprintf("no evidence: all %d license files failed to be read", failed)
	default:
		return false, ""
	}
}

// projectLicense returns the strongest signal naming the component's own
// license, and a description of what produced it.
func projectLicense(in Input, inScope []detect.File) (float64, string) {
	var best float64
	var src string
	for _, f := range inScope {
		if !f.Identified() || f.Confidence <= best {
			continue
		}
		best, src = f.Confidence, fmt.Sprintf("%s=%s", f.Path, f.Identifier())
	}
	if best > 0 {
		return best, src
	}
	// A manifest whose License is empty declared nothing: it only pointed at a
	// license file, which is already counted as a license text or not at all.
	// Crediting it would score a declaration nobody made.
	for _, m := range in.Manifests {
		if m.License != "" {
			return manifestCredit, fmt.Sprintf("manifest %s=%s", m.Path, m.License)
		}
	}
	switch {
	case len(in.Prose) > 0:
		return proseCredit, fmt.Sprintf("prose license mention in %s", in.Prose[0].Path)
	default:
		return 0, "none found"
	}
}

// textResolution returns the fraction of in-scope license texts that classified
// confidently, along with the counts behind it.
//
// A component with no license text at all scores 1 here rather than 0: there is
// nothing unresolved, and the fact that nothing was found is already carried by
// the project-license term. Scoring it 0 would zero the product and make a
// component with no license text indistinguishable from one with contradictory
// text.
func textResolution(inScope []detect.File) (frac float64, resolved, total int) {
	for _, f := range inScope {
		total++
		if f.Confident() {
			resolved++
		}
	}
	if total == 0 {
		return 1, 0, 0
	}
	return float64(resolved) / float64(total), resolved, total
}

// relation returns whether several detected licenses have something composing
// them, a description of the finding, and the operator when one was
// established.
//
// One license, or none, has no relationship to be uncertain about. Several are
// settled first by a manifest expression naming all of them - an expression
// naming only some is a disagreement with what was detected, which is at least
// as much reason to look harder as silence would be - and failing that by an
// explicit choice-of-license statement in the component's own prose.
//
// The prose rung exists because whole ecosystems have no manifest license field
// to consult. Go is the clearest case: nothing in go.mod declares a license, so
// a module shipping two license texts had no way at all to say which
// relationship holds, and every one of them was escalated to be told what its
// README already said.
func relationCertainty(in Input, identifiers []string) (float64, string, string) {
	if len(identifiers) < 2 {
		return 1, "single license in scope", ""
	}
	for _, m := range in.Manifests {
		// A parse rather than spdx.Identifiers, whose documented fallback reads
		// names out of a string that is not an expression. "MIT Apache-2.0"
		// names both licenses and composes neither, and crediting it here would
		// let malformed metadata make unresolved licensing look settled. The
		// lenient reading stays correct where the question is which identifiers
		// a declaration mentions; this question is what composes them.
		expr, err := spdx.Parse(spdx.Canonicalize(m.License))
		if err != nil {
			continue
		}
		if namesAll(expr.Identifiers(), identifiers) {
			return 1, fmt.Sprintf("%d licenses, composed by %s %q", len(identifiers), m.Path, m.License), ""
		}
	}
	if hint, ok := ChoiceOfLicense(in.Prose); ok {
		return proseChoiceCredit,
			fmt.Sprintf("%d licenses (%s), offered as a choice by %s:%d %q",
				len(identifiers), strings.Join(identifiers, ", "), hint.Path, hint.Line, hint.Excerpt),
			spdx.OperatorOr
	}
	return 0, fmt.Sprintf("%d licenses (%s) with nothing composing them",
		len(identifiers), strings.Join(identifiers, ", ")), ""
}

// conflictsWithDeclared reports whether the declared expression names licenses
// the content does not carry, or omits ones it does.
//
// Nothing detected is not a conflict: a declaration cannot disagree with an
// absence of evidence, and reporting one would flag every component whose
// license file is unreadable as also being misdeclared. No declaration is not a
// conflict either, for the same reason in the other direction.
func conflictsWithDeclared(declared string, detected []string) bool {
	if strings.TrimSpace(declared) == "" || len(detected) == 0 {
		return false
	}
	declaredIDs := spdx.Identifiers(spdx.Canonicalize(declared))
	if len(declaredIDs) == 0 {
		return false
	}
	// Compared as sets, in both directions. An under-declaration hides an
	// obligation and an over-declaration claims one nobody has, and both are
	// worth a reviewer's attention.
	if !namesAll(declaredIDs, detected) {
		return true
	}
	return !namesAll(detected, declaredIDs)
}

// namesAll reports whether every one of names appears in set.
func namesAll(set []string, names []string) bool {
	for _, n := range names {
		if !slices.Contains(set, n) {
			return false
		}
	}
	return true
}
