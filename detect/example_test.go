/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package detect_test

import (
	"context"
	"fmt"
	"testing/fstest"

	"chainguard.dev/license/detect"
)

// mit is the MIT license text, which is what a classifier needs to see in order
// to recognize it. Abbreviating it would make the examples wrong rather than
// shorter.
const mit = `MIT License

Copyright (c) 2026 Example

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
`

// Detect and Conclude are the two calls a consumer makes: find and classify the
// license files, then ask what they settle.
func ExampleDetect() {
	fsys := fstest.MapFS{
		"LICENSE":            &fstest.MapFile{Data: []byte(mit)},
		"vendor/dep/LICENSE": &fstest.MapFile{Data: []byte("Apache License Version 2.0")},
	}

	res, err := detect.Detect(context.Background(), detect.Request{FS: fsys})
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(res.Conclude(detect.GrantEvidence{}).Expression)
	// Output: MIT
}

// A vendored license belongs to the component that vendored it, so it is
// reported with a reason rather than counted as the project's own.
func ExampleFind() {
	fsys := fstest.MapFS{
		"LICENSE":                 &fstest.MapFile{Data: []byte(mit)},
		"vendor/dep/LICENSE":      &fstest.MapFile{Data: []byte(mit)},
		"testdata/corpus/LICENSE": &fstest.MapFile{Data: []byte(mit)},
	}

	found, err := detect.Find(fsys, detect.ScopeTree)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	for _, f := range found.Candidates {
		fmt.Printf("%-25s %q\n", f.Path, f.Excluded)
	}
	// Output:
	// LICENSE                   ""
	// testdata/corpus/LICENSE   "test-fixture"
	// vendor/dep/LICENSE        "vendored"
}

// IsLicenseFile answers the filename question on its own, which is what the
// license-content hash needs: no depth rule, no directory rule.
func ExampleIsLicenseFile() {
	for _, name := range []string{"LICENSE", "COPYING.md", "LICENSE-MIT", "license.go", "README.md"} {
		is, weight := detect.IsLicenseFile(name)
		fmt.Printf("%-12s %v %.2f\n", name, is, weight)
	}
	// Output:
	// LICENSE      true 1.00
	// COPYING.md   true 0.85
	// LICENSE-MIT  true 0.70
	// license.go   false 0.00
	// README.md    false 0.00
}

// Notices and Grants settle the one thing a license text cannot state: whether
// a GPL-family license grants later versions.
func ExampleGrants() {
	fsys := fstest.MapFS{
		"main.c": &fstest.MapFile{Data: []byte("/* SPDX-License-Identifier: GPL-2.0-or-later */\nint main(void){return 0;}\n")},
	}

	notices, sampled := detect.Notices(fsys)
	for _, g := range detect.Grants(nil, notices) {
		fmt.Printf("%s from %s (%d of %d files)\n", g.Expression, g.Source, g.Files, sampled)
	}
	// Output: GPL-2.0-or-later from spdx-tag (1 of 1 files)
}

// Prose is where upstreams that ship no license file state their licensing, and
// where a choice between several licenses is usually spelled out.
func ExampleProse() {
	fsys := fstest.MapFS{
		"README.md": &fstest.MapFile{Data: []byte("# Example\n\nDual-licensed under MIT or Apache-2.0 at your option.\n")},
	}

	for _, hint := range detect.Prose(fsys) {
		fmt.Printf("%s:%d %s\n", hint.Path, hint.Line, hint.Excerpt)
	}
	// Output: README.md:3 Dual-licensed under MIT or Apache-2.0 at your option.
}

// ClassifyExclusion says whether a discovered file describes the component
// itself, and if not, why.
func ExampleClassifyExclusion() {
	for _, path := range []string{"LICENSE", "docs/LICENSE", "vendor/x/LICENSE", "PATENTS", "melange-out/pkg/LICENSE"} {
		fmt.Printf("%-24s %q\n", path, detect.ClassifyExclusion(path))
	}
	// Output:
	// LICENSE                  ""
	// docs/LICENSE             ""
	// vendor/x/LICENSE         "vendored"
	// PATENTS                  "supplementary"
	// melange-out/pkg/LICENSE  "build-output"
}

// A classifier can be built explicitly when one classifier should answer every
// question in a run, which is also what keeps a supplemented corpus from being
// silently bypassed.
func ExampleNewClassifier() {
	c, err := detect.NewClassifier()
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	matches, err := c.Identify(fstest.MapFS{"LICENSE": &fstest.MapFile{Data: []byte(mit)}}, "LICENSE")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(matches[0].Name, matches[0].Confidence >= detect.ConfidenceThreshold)
	// Output: MIT true
}

func ExampleConclusion_UnrecognizedText() {
	// A conclusion reached without Request.RetainText knows a license text was
	// there but does not hold it, so it cannot be named.
	withoutText := detect.Conclusion{
		Reason:       detect.ReasonUnrecognized,
		Unrecognized: []detect.File{{Path: "LICENSE.txt", SizeBytes: 4096}},
	}
	if _, err := withoutText.UnrecognizedText(); err != nil {
		fmt.Println("not named:", err)
	}

	withText := detect.Conclusion{
		Reason:       detect.ReasonUnrecognized,
		Unrecognized: []detect.File{{Path: "LICENSE.txt", SizeBytes: 26, Text: "Bespoke terms, all rights."}},
	}
	text, err := withText.UnrecognizedText()
	if err != nil {
		fmt.Println("unexpected:", err)
		return
	}
	fmt.Println("named from:", text)

	// Output:
	// not named: license text at "LICENSE.txt" was not retained: naming it needs Request.RetainText
	// named from: Bespoke terms, all rights.
}
