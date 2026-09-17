/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package evidence_test

import (
	"context"
	"fmt"
	"testing/fstest"

	"chainguard.dev/license/component"
	"chainguard.dev/license/evidence"
)

// mitText is the MIT license, in full: a classifier has to see the whole text
// to recognize it, so abbreviating it would make the example wrong.
const mitText = `MIT License

Copyright (c) 2026 Example

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
`

// subject describes what is being collected about. Trees is the subject for a
// caller that has done its own acquisition.
func subject(source fstest.MapFS) *evidence.Trees {
	return &evidence.Trees{
		Description: evidence.Description{
			Package: "example",
			Version: "1.2.3",
			Source: component.Source{
				Name:       "example",
				Version:    "1.2.3",
				Repository: "https://github.com/example/project",
				Commit:     "0123456789abcdef0123456789abcdef01234567",
			},
			Origin: "example.yaml",
		},
		SourceFS: source,
	}
}

// Collect records what a tree contained and reaches no conclusion about whether
// the licensing is acceptable.
func ExampleCollect() {
	bundle, err := evidence.Collect(context.Background(), subject(fstest.MapFS{
		"LICENSE":      &fstest.MapFile{Data: []byte(mitText)},
		"package.json": &fstest.MapFile{Data: []byte(`{"name":"example","license":"MIT"}`)},
	}), evidence.Options{})
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("schema", bundle.SchemaVersion)
	fmt.Println("concluded", bundle.Conclusion.Expression)
	fmt.Printf("score %.2f\n", bundle.Assessment.Score)
	fmt.Println("first component", bundle.Components[0].Kind)
	// Output:
	// schema 1
	// concluded MIT
	// score 1.00
	// first component package-source
}

// A subject that cannot supply a tree records the failure, because an
// incomplete bundle has to stay distinguishable from a clean one: the same
// empty result means opposite things in the two.
func ExampleBundle_Complete() {
	bundle, err := evidence.Collect(context.Background(), &evidence.Trees{
		Description: evidence.Description{Package: "example", Version: "1.2.3"},
	}, evidence.Options{})
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println(bundle.Complete(), bundle.Assessment.Unknown)
	for _, gap := range bundle.Gaps {
		fmt.Println(gap.Kind)
	}
	// Output:
	// false true
	// source
	// no-installed-trees
}

// Bundles are content-addressed, so identical observations have to encode to
// identical bytes: rebuilding unchanged source is then a storage no-op.
func ExampleBundle_Digest() {
	tree := fstest.MapFS{"LICENSE": &fstest.MapFile{Data: []byte(mitText)}}

	first, err := evidence.Collect(context.Background(), subject(tree), evidence.Options{})
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	second, err := evidence.Collect(context.Background(), subject(tree), evidence.Options{})
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	a, err := first.Digest()
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	b, err := second.Digest()
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(a == b)
	// Output: true
}
