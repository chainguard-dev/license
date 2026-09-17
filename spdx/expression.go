/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package spdx

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// Expression is a parsed SPDX license expression.
//
// It is opaque because the two questions consumers ask of an expression are
// Identifiers and Satisfies, and both are easy to get wrong from the outside:
// an exposure view that drops OR branches understates what a consumer is
// subject to, and an evaluation that treats OR as AND rejects an expression the
// consumer accepts.
type Expression struct {
	root node
}

// node is one term of an expression: a leaf identifier or a binary operator.
type node struct {
	// id is set on a leaf, and holds the whole identifier including any WITH
	// exception and any trailing "+".
	id string
	// op is "AND" or "OR" on an interior node, and empty on a leaf.
	op          string
	left, right *node
}

// Operators are the SPDX expression keywords.
const (
	OperatorAnd  = "AND"
	OperatorOr   = "OR"
	OperatorWith = "WITH"
)

// identifierRe matches an SPDX identifier or exception: alphanumerics, dots,
// and hyphens, with an optional trailing "+" for the deprecated or-later form.
// A LicenseRef is included, and a DocumentRef prefix carries one colon.
var identifierRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.\-]*(:[A-Za-z0-9][A-Za-z0-9.\-]*)?\+?$`)

// Parse reads an SPDX license expression.
//
// Operator precedence follows the specification: "+" binds tightest, then WITH,
// then AND, then OR, with parentheses grouping. Identifiers are checked for
// shape but not for membership of the license list, because a valid expression
// may name a LicenseRef this package has never heard of, and because refusing
// an unlisted identifier here would leave the caller with no way to read an
// expression it still has to record faithfully.
//
// Callers holding ecosystem metadata rather than an expression should run
// Canonicalize first: a pom naming "The Apache Software License, Version 2.0"
// is not an expression and will not parse.
func Parse(expr string) (Expression, error) {
	tokens, err := tokenize(expr)
	if err != nil {
		return Expression{}, err
	}
	p := &parser{tokens: tokens}
	root, err := p.parseOr()
	if err != nil {
		return Expression{}, err
	}
	if p.pos != len(p.tokens) {
		return Expression{}, fmt.Errorf("spdx: unexpected %q in %q", p.tokens[p.pos], expr)
	}
	return Expression{root: *root}, nil
}

// String renders the expression, parenthesizing only where precedence requires
// it, so that re-parsing the result yields the same tree.
func (e Expression) String() string { return e.root.String() }

// Identifiers returns the identifiers the expression exposes a consumer to,
// sorted and deduplicated.
//
// Every OR branch contributes, because this package does not elect a branch:
// which branch a consumer relies on is their choice to record, and an exposure
// view that guessed one would hide the terms of the other. A WITH form stays a
// single identifier for the same reason - "GPL-2.0-only WITH
// Classpath-exception-2.0" is not GPL-2.0-only, and splitting it would report
// an obligation the exception removes.
func (e Expression) Identifiers() []string {
	set := map[string]struct{}{}
	e.root.collect(set)
	return slices.Sorted(maps.Keys(set))
}

// Satisfies reports whether the expression is met when accept holds for an
// identifier.
//
// An OR is satisfied by any one branch and an AND by all of them. accept is
// called with the whole identifier, WITH exception included, so a caller that
// accepts a license only under an exception can say so.
func (e Expression) Satisfies(accept func(id string) bool) bool {
	return e.root.satisfies(accept)
}

// Identifiers returns the identifiers a license expression names.
//
// It prefers a parse, and falls back to reading the identifiers out of the
// string when it is not valid SPDX. That fallback is what makes the function
// usable on declared metadata, which is frequently not an expression at all:
// the identifiers a malformed declaration names are still worth comparing
// against what was detected, and refusing to read them would report every such
// component as declaring nothing.
//
// The fallback reads tokens rather than structure, so a WITH pair inside an
// otherwise malformed string comes back as two identifiers instead of one.
// Run Canonicalize first where that matters: an expression that parses keeps
// its exception attached.
func Identifiers(expr string) []string {
	if e, err := Parse(expr); err == nil {
		return e.Identifiers()
	}
	set := map[string]struct{}{}
	for tok := range strings.FieldsSeq(expressionPunctuation.Replace(expr)) {
		switch strings.ToUpper(tok) {
		case "", OperatorAnd, OperatorOr, OperatorWith:
			continue
		}
		set[tok] = struct{}{}
	}
	return slices.Sorted(maps.Keys(set))
}

// grantSuffixRe matches the version-grant suffixes, which are the part of a
// GPL-family identifier that no license text can establish.
var grantSuffixRe = regexp.MustCompile(`-(only|or-later)\b`)

// WithoutGrant returns an identifier with any version grant removed.
//
// It exists for the comparison a consumer cannot otherwise make honestly. The
// license text of GPL-2.0-only and GPL-2.0-or-later is byte-identical, so a
// classifier can never produce the suffix; when a declaration states one and
// detection could not, the two are not in conflict, and comparing them
// verbatim reports a disagreement that is not there. Removing the grant from
// both sides is what makes them comparable.
//
// A WITH exception is kept, because an exception is not a grant: it changes
// what the license permits rather than which versions of it apply.
func WithoutGrant(id string) string {
	license, exception, hasException := strings.Cut(strings.TrimSpace(id), " "+OperatorWith+" ")
	stripped := grantSuffixRe.ReplaceAllString(license, "")
	if hasException {
		return stripped + " " + OperatorWith + " " + exception
	}
	return stripped
}

// expressionPunctuation are the separators that carry no identifier content.
//
// "/" is here because Cargo's deprecated syntax writes a choice of licenses as
// "MIT/Apache-2.0". Left untokenized it reads as one unknown identifier, which
// makes every crate still using it look like it disagrees with itself: the
// declared expression matches nothing detected, so the component reads as
// divergent. No SPDX identifier contains a slash.
var expressionPunctuation = strings.NewReplacer("(", " ", ")", " ", ",", " ", "/", " ")

// collect adds every identifier in the subtree to set.
func (n *node) collect(set map[string]struct{}) {
	if n.op == "" {
		set[n.id] = struct{}{}
		return
	}
	n.left.collect(set)
	n.right.collect(set)
}

// satisfies evaluates the subtree against accept.
func (n *node) satisfies(accept func(string) bool) bool {
	switch n.op {
	case "":
		return accept(n.id)
	case OperatorAnd:
		return n.left.satisfies(accept) && n.right.satisfies(accept)
	default:
		return n.left.satisfies(accept) || n.right.satisfies(accept)
	}
}

// String renders the subtree, bracketing an OR nested inside an AND because
// AND binds tighter and the brackets are what preserve the grouping.
func (n *node) String() string {
	if n.op == "" {
		return n.id
	}
	render := func(child *node) string {
		if n.op == OperatorAnd && child.op == OperatorOr {
			return "(" + child.String() + ")"
		}
		return child.String()
	}
	return render(n.left) + " " + n.op + " " + render(n.right)
}

// parser holds the token stream and the position within it.
type parser struct {
	tokens []string
	pos    int
}

// parseOr reads a sequence of AND terms separated by OR, the loosest binding.
func (p *parser) parseOr() (*node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peekOperator(OperatorOr) {
		p.pos++
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &node{op: OperatorOr, left: left, right: right}
	}
	return left, nil
}

// parseAnd reads a sequence of atoms separated by AND.
func (p *parser) parseAnd() (*node, error) {
	left, err := p.parseAtom()
	if err != nil {
		return nil, err
	}
	for p.peekOperator(OperatorAnd) {
		p.pos++
		right, err := p.parseAtom()
		if err != nil {
			return nil, err
		}
		left = &node{op: OperatorAnd, left: left, right: right}
	}
	return left, nil
}

// parseAtom reads a parenthesized expression or a leaf identifier, together
// with any WITH exception applying to it.
func (p *parser) parseAtom() (*node, error) {
	if p.pos >= len(p.tokens) {
		return nil, fmt.Errorf("spdx: expression ends where a license identifier was expected")
	}
	tok := p.tokens[p.pos]
	if tok == "(" {
		p.pos++
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.pos >= len(p.tokens) || p.tokens[p.pos] != ")" {
			return nil, fmt.Errorf("spdx: unbalanced parenthesis")
		}
		p.pos++
		return inner, nil
	}
	if tok == ")" {
		return nil, fmt.Errorf("spdx: unbalanced parenthesis")
	}
	if isOperatorToken(tok) {
		return nil, fmt.Errorf("spdx: operator %q where a license identifier was expected", tok)
	}
	if !identifierRe.MatchString(tok) {
		return nil, fmt.Errorf("spdx: %q is not a license identifier", tok)
	}
	p.pos++

	if !p.peekOperator(OperatorWith) {
		return &node{id: tok}, nil
	}
	p.pos++
	if p.pos >= len(p.tokens) {
		return nil, fmt.Errorf("spdx: WITH names no exception")
	}
	exception := p.tokens[p.pos]
	if isOperatorToken(exception) || !identifierRe.MatchString(exception) {
		return nil, fmt.Errorf("spdx: %q is not a license exception", exception)
	}
	p.pos++
	// The exception is part of the identifier rather than an operator over it:
	// what a consumer is subject to is the pair, and no consumer of this tree
	// should have to reassemble it.
	return &node{id: tok + " " + OperatorWith + " " + exception}, nil
}

// peekOperator reports whether the next token is the named operator, matched
// case-insensitively so that a declaration written "MIT or Apache-2.0" parses.
func (p *parser) peekOperator(op string) bool {
	return p.pos < len(p.tokens) && strings.EqualFold(p.tokens[p.pos], op)
}

// isOperatorToken reports whether a token is any SPDX operator.
func isOperatorToken(tok string) bool {
	switch strings.ToUpper(tok) {
	case OperatorAnd, OperatorOr, OperatorWith:
		return true
	}
	return false
}

// tokenize splits an expression into identifiers, operators and parentheses.
func tokenize(expr string) ([]string, error) {
	if strings.TrimSpace(expr) == "" {
		return nil, fmt.Errorf("spdx: empty license expression")
	}
	var tokens []string
	var current strings.Builder
	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, current.String())
			current.Reset()
		}
	}
	for _, r := range expr {
		switch r {
		case '(', ')':
			flush()
			tokens = append(tokens, string(r))
		case ' ', '\t', '\n', '\r':
			flush()
		default:
			current.WriteRune(r)
		}
	}
	flush()
	if len(tokens) == 0 {
		return nil, fmt.Errorf("spdx: empty license expression")
	}
	return tokens, nil
}
