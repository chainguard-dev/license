/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package gen

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"go/format"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// exceptionSlug maps the exception part of a deprecated
// "<license>-with-<slug>" identifier onto the SPDX exception identifier, keyed
// by the base license because the same slug names different exception versions
// under different GPL versions (GCC-exception-2.0 against GPL-2.0,
// GCC-exception-3.1 against GPL-3.0).
//
// This is the one hand-written table here, and it is bounded: the classifier
// emits exactly these forms.
var exceptionSlug = map[[2]string]string{
	{"GPL-2.0", "classpath-exception"}: "Classpath-exception-2.0",
	{"GPL-2.0", "GCC-exception"}:       "GCC-exception-2.0",
	{"GPL-2.0", "autoconf-exception"}:  "Autoconf-exception-2.0",
	{"GPL-2.0", "bison-exception"}:     "Bison-exception-2.2",
	{"GPL-2.0", "font-exception"}:      "Font-exception-2.0",
	{"GPL-3.0", "GCC-exception"}:       "GCC-exception-3.1",
	{"GPL-3.0", "autoconf-exception"}:  "Autoconf-exception-3.0",
	{"GPL-3.0", "bison-exception"}:     "Bison-exception-2.2",
}

// handMapped are classifier names that resolve to an SPDX identifier no
// mechanical rule finds, because the classifier spells them differently from
// SPDX and the two names share no derivable relationship.
var handMapped = map[string]string{
	"BSD-0-Clause":               "0BSD",
	"BSD-2-Clause-FreeBSD":       "BSD-2-Clause-Views",
	"BSD-2-Clause-NetBSD":        "BSD-2-Clause",
	"Apache-with-LLVM-Exception": "Apache-2.0 WITH LLVM-exception",
	"OpenLDAP":                   "OLDAP-2.8",
	"PNG":                        "libpng-2.0",
}

type spdxList struct {
	Version  string `json:"licenseListVersion"`
	Licenses []struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Deprecated bool   `json:"deprecated"`
	} `json:"licenses"`
}

// orLaterRe detects a grant of later versions in a header notice. Safe here in
// a way it is not against a full license text: header variants are short
// notices that do not carry the GPL's own "how to apply these terms" appendix.
var orLaterRe = regexp.MustCompile(`(?is)any later version|version [\d.]+ or later`)

// Generate produces the contents of tables.go.
func Generate(spdxPath, assets string) ([]byte, error) {
	raw, err := os.ReadFile(spdxPath)
	if err != nil {
		return nil, fmt.Errorf("reading SPDX list: %w", err)
	}
	var list spdxList
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("parsing SPDX list: %w", err)
	}
	current := map[string]string{}
	byName := map[string]string{}
	for _, l := range list.Licenses {
		if l.Deprecated {
			continue
		}
		current[l.ID] = l.ID
		byName[normalizeText(l.Name)] = l.ID
	}

	if assets == "" {
		if assets, err = findAssets(); err != nil {
			return nil, err
		}
	}

	names, err := dirNames(filepath.Join(assets, "License"))
	if err != nil {
		return nil, fmt.Errorf("reading classifier license assets: %w", err)
	}

	type entry struct{ name, id, base, only, orLater, ref string }
	var entries []entry
	for _, n := range names {
		if _, ok := current[n]; ok {
			continue // already a current SPDX identifier; no table row needed
		}
		e := entry{name: n}
		switch {
		case handMapped[n] != "":
			e.id = handMapped[n]
		case strings.Contains(n, "-with-"):
			base, slug, _ := strings.Cut(n, "-with-")
			exc := exceptionSlug[[2]string{base, slug}]
			only, later := base+"-only", base+"-or-later"
			if exc != "" && current[only] != "" && current[later] != "" {
				e.base, e.only, e.orLater = base, only+" WITH "+exc, later+" WITH "+exc
			} else {
				e.ref = n
			}
		default:
			only, later := n+"-only", n+"-or-later"
			if current[only] != "" && current[later] != "" {
				e.base, e.only, e.orLater = n, only, later
			} else if id := byName[normalizeText(n)]; id != "" {
				e.id = id
			} else if id := caseInsensitive(current, n); id != "" {
				e.id = id
			} else {
				e.ref = n
			}
		}
		entries = append(entries, e)
	}

	// Header variants: which wording of a GPL notice states a later-version
	// grant. The classifier files every wording under the license name alone,
	// so the variant is the only thing that distinguishes them.
	type hdr struct{ name, variant, id string }
	var headers []hdr
	hdrNames, err := dirNames(filepath.Join(assets, "Header"))
	if err != nil {
		return nil, fmt.Errorf("reading classifier header assets: %w", err)
	}
	hdrRoot, err := os.OpenRoot(filepath.Join(assets, "Header"))
	if err != nil {
		return nil, fmt.Errorf("opening classifier header root: %w", err)
	}
	defer hdrRoot.Close()
	for _, n := range hdrNames {
		base, only, later := n, n+"-only", n+"-or-later"
		var exc string
		if strings.Contains(n, "-with-") {
			b, slug, _ := strings.Cut(n, "-with-")
			if e := exceptionSlug[[2]string{b, slug}]; e != "" {
				base, exc = b, e
				only, later = b+"-only WITH "+e, b+"-or-later WITH "+e
			}
		}
		if current[base+"-only"] == "" || current[base+"-or-later"] == "" {
			continue // not a family with a version grant
		}
		_ = exc
		varDir, err := hdrRoot.Open(n)
		if err != nil {
			return nil, err
		}
		variants, err := varDir.ReadDir(-1)
		varDir.Close()
		if err != nil {
			return nil, err
		}
		for _, v := range variants {
			if v.IsDir() {
				continue
			}
			f, err := hdrRoot.Open(n + "/" + v.Name())
			if err != nil {
				return nil, err
			}
			body, err := io.ReadAll(f)
			f.Close()
			if err != nil {
				return nil, err
			}
			id := only
			if orLaterRe.Match(body) {
				id = later
			}
			headers = append(headers, hdr{name: n, variant: v.Name(), id: id})
		}
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, `/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Code generated by internal/gen. DO NOT EDIT.
//
// Derived from SPDX license list %s and the licenseclassifier asset
// vocabulary. Regenerate with 'go generate ./...' after upgrading either.

package spdx

// headerKey identifies one wording of a license notice in the classifier's
// header corpus.
type headerKey struct{ Name, Variant string }

// classifierNames maps every license name the classifier can emit that is not
// already a current SPDX identifier. Names absent from this table are current
// SPDX identifiers and pass through unchanged.
var classifierNames = map[string]Resolution{
`, list.Version)
	slices.SortFunc(entries, func(a, b entry) int { return strings.Compare(a.name, b.name) })
	for _, e := range entries {
		switch {
		case e.id != "":
			fmt.Fprintf(&b, "\t%q: {ID: %q},\n", e.name, e.id)
		case e.base != "":
			fmt.Fprintf(&b, "\t%q: {GrantBase: %q, Only: %q, OrLater: %q},\n", e.name, e.base, e.only, e.orLater)
		default:
			fmt.Fprintf(&b, "\t%q: {Ref: %q},\n", e.name, e.ref)
		}
	}
	fmt.Fprintf(&b, "}\n\n// headerVariants records which wording of a GPL-family notice grants later\n// versions, so a header match can resolve the suffix the license text cannot.\nvar headerVariants = map[headerKey]string{\n")
	slices.SortFunc(headers, func(a, b hdr) int {
		return cmp.Or(strings.Compare(a.name, b.name), strings.Compare(a.variant, b.variant))
	})
	for _, h := range headers {
		fmt.Fprintf(&b, "\t{%q, %q}: %q,\n", h.name, h.variant, h.id)
	}
	fmt.Fprintln(&b, "}")

	src, err := format.Source(b.Bytes())
	if err != nil {
		return nil, fmt.Errorf("formatting generated source: %w", err)
	}
	return src, nil
}

// findAssets locates the licenseclassifier asset directory, preferring a
// vendored copy so a vendored build generates the same tables as a module one.
func findAssets() (string, error) {
	const mod = "github.com/google/licenseclassifier/v2"
	if wd, err := os.Getwd(); err == nil {
		for dir := wd; dir != "/" && dir != "."; dir = filepath.Dir(dir) {
			v := filepath.Join(dir, "vendor", mod, "assets")
			if _, err := os.Stat(filepath.Join(v, "License")); err == nil {
				return v, nil
			}
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				break
			}
		}
	}
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", mod).Output()
	if err != nil {
		return "", fmt.Errorf("locating %s: %w", mod, err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		// go list prints an empty Dir with exit 0 when the module is in the
		// build list but not extracted in the local module cache — nothing on
		// this module's build path imports the classifier, so a cold cache is
		// a reachable state (the main canary hit it: joining "assets" onto ""
		// degraded to a relative path and an "open assets/License" failure).
		// Download the module and resolve again.
		if msg, err := exec.Command("go", "mod", "download", mod).CombinedOutput(); err != nil {
			return "", fmt.Errorf("downloading %s: %w: %s", mod, err, msg)
		}
		out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", mod).Output()
		if err != nil {
			return "", fmt.Errorf("locating %s after download: %w", mod, err)
		}
		if dir = strings.TrimSpace(string(out)); dir == "" {
			return "", fmt.Errorf("locating %s: no local directory after download", mod)
		}
	}
	return filepath.Join(dir, "assets"), nil
}

func dirNames(root string) ([]string, error) {
	es, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range es {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	slices.Sort(out)
	return out, nil
}

func caseInsensitive(m map[string]string, name string) string {
	for k, v := range m {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

func normalizeText(s string) string {
	return strings.Trim(nonAlnum.ReplaceAllString(strings.ToLower(s), " "), " ")
}
