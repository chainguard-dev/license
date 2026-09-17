/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package spdx

import (
	"regexp"
	"strings"
)

// infixOperator matches the SPDX binary operators between operands.
var infixOperator = regexp.MustCompile(`(?i)\s+(AND|OR)\s+`)

// groupedOperator matches a parenthesis pair that encloses an operator, which
// is the only case where parentheses are doing grouping rather than sitting
// inside a license's name.
var groupedOperator = regexp.MustCompile(`(?i)\([^()]*\s+(AND|OR)\s+[^()]*\)`)

// withClause matches the SPDX exception operator.
var withClause = regexp.MustCompile(`(?i)\s+WITH\s+`)

// Canonicalize rewrites a declared license value into valid SPDX, so that what
// gets published is an expression rather than whatever prose upstream wrote.
//
// Ecosystem metadata is mostly not SPDX. A pom names "The Apache Software
// License, Version 2.0", an npm field carries a bare URL, and Cargo's
// deprecated "MIT/Apache-2.0" means a choice. Left alone, none of those
// compares equal to the identifiers classified from the same component's files,
// so every one of them reads as a disagreement that is not there.
//
// Only unambiguous rewrites are made. Each operand is mapped through SPDX's own
// name and URL data, and an operand that does not resolve is left exactly as it
// was rather than guessed at - a bare "GPL" names no particular license, and
// inventing one would be worse than reporting the prose.
func Canonicalize(expr string) string {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "" {
		return expr
	}
	// The whole string first. Most declared values name one license, and prose
	// naming one license routinely contains punctuation that would defeat any
	// attempt to tokenize it: "The MIT License (MIT)" is a name, not a
	// parenthesised expression, and splitting it would lose it.
	if id, ok := FromText(trimmed); ok {
		return id
	}
	// Past that it has to be read as an expression, which means splitting it on
	// its operators - and that is only safe when no parenthesis is grouping
	// them. Note the test is for a parenthesis around an operator, not for a
	// parenthesis at all: plenty of license names contain one, as in "The GNU
	// General Public License (GPL), Version 2", and refusing to split those
	// leaves every operand beside them unmapped too.
	if groupedOperator.MatchString(trimmed) {
		return trimmed
	}
	if choice, ok := slashChoice(trimmed); ok {
		trimmed = choice
	}
	return rewriteOperands(trimmed)
}

// slashChoice rewrites Cargo's deprecated "MIT/Apache-2.0" spelling of a
// choice.
//
// It fires only when every part is a license SPDX recognizes, because a slash
// appears in plenty of strings that are not a choice of anything: "GPL2 w/ CPE"
// would otherwise become "GPL2 w OR CPE".
func slashChoice(expr string) (string, bool) {
	if !strings.Contains(expr, "/") || infixOperator.MatchString(expr) {
		return "", false
	}
	parts := strings.Split(expr, "/")
	if len(parts) < 2 {
		return "", false
	}
	for i, part := range parts {
		id, ok := FromText(part)
		if !ok {
			return "", false
		}
		parts[i] = id
	}
	return strings.Join(parts, " "+OperatorOr+" "), true
}

// rewriteOperands maps each operand of an expression onto SPDX, leaving the
// operators in place and normalizing their spelling.
func rewriteOperands(expr string) string {
	operands := infixOperator.Split(expr, -1)
	operators := infixOperator.FindAllString(expr, -1)

	var b strings.Builder
	for i, operand := range operands {
		if i > 0 {
			b.WriteString(" " + strings.ToUpper(strings.TrimSpace(operators[i-1])) + " ")
		}
		b.WriteString(canonicalOperand(operand))
	}
	return b.String()
}

// canonicalOperand maps one operand onto an SPDX identifier where the mapping
// is unambiguous.
//
// A WITH form is left alone: the exception clause binds tighter than the
// operators split on here, and SPDX's name data describes licenses rather than
// license-plus-exception pairs, so there is nothing to look it up in.
func canonicalOperand(operand string) string {
	trimmed := strings.TrimSpace(operand)
	if trimmed == "" || withClause.MatchString(trimmed) {
		return trimmed
	}
	if id, ok := FromText(trimmed); ok {
		return id
	}
	return trimmed
}
