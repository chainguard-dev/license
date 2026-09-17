/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package component_test

import (
	"context"
	"fmt"
	"testing/fstest"

	"chainguard.dev/license/component"
)

// EnumerateSource reads component identities out of the manifests and lockfiles
// in a source tree: coordinates and a content digest, with no toolchain, no
// network and no dependency sources needed.
func ExampleEnumerateSource() {
	fsys := fstest.MapFS{
		"go.mod": &fstest.MapFile{Data: []byte("module example.com/project\n")},
		"go.sum": &fstest.MapFile{Data: []byte(
			"github.com/google/uuid v1.6.0 h1:NIvaJDMOsjJZ2wPCH3sHXTKbA==\n" +
				"github.com/google/uuid v1.6.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=\n")},
	}

	enumerated := component.EnumerateSource(context.Background(), fsys)
	for _, c := range enumerated.Components {
		fmt.Printf("%s %s=%s\n", c.PURL, c.DigestAlgo, c.Digest)
	}
	fmt.Println(len(enumerated.Notes), "note(s) about the fidelity of the result")
	// Output:
	// pkg:golang/github.com/google/uuid@v1.6.0 h1=h1:NIvaJDMOsjJZ2wPCH3sHXTKbA==
	// 1 note(s) about the fidelity of the result
}

// EnumerateInstalled reads the components that exist nowhere else: a Python
// application's resolved dependency versions do not exist until pip has run.
func ExampleEnumerateInstalled() {
	tree := component.Tree{
		Name: "melange-out/example",
		FS: fstest.MapFS{
			"usr/lib/python3.13/site-packages/requests-2.32.3.dist-info/METADATA": &fstest.MapFile{
				Data: []byte("Name: requests\nVersion: 2.32.3\nLicense-Expression: Apache-2.0\n\nbody\n"),
			},
		},
	}

	enumerated := component.EnumerateInstalled(context.Background(), []component.Tree{tree}, "py3-example")
	for _, c := range enumerated.Components {
		fmt.Println(c.PURL, c.Linkage)
	}
	// Output: pkg:pypi/requests@2.32.3 bundled
}

// The purl constructors are exported because every producer has to derive the
// same identity for one component. The spellings are not interchangeable as map
// keys, so they are not left to each call site.
func ExampleNpmPURL() {
	fmt.Println(component.GoPURL("github.com/google/uuid", "v1.6.0"))
	fmt.Println(component.CargoPURL("serde", "1.0.219"))
	fmt.Println(component.NpmPURL("@babel/core", "7.24.0"))
	fmt.Println(component.PyPIPURL("zope.interface", "8.0.1"))
	fmt.Println(component.MavenPURL("com.google.guava", "guava", "33.0.0-jre"))
	// Output:
	// pkg:golang/github.com/google/uuid@v1.6.0
	// pkg:cargo/serde@1.0.219
	// pkg:npm/@babel/core@7.24.0
	// pkg:pypi/zope-interface@8.0.1
	// pkg:maven/com.google.guava/guava@33.0.0-jre
}

// SourceComponent names the thing a package is built from. No purl identifies
// upstream source with our patches applied, so the identity is a locator plus a
// digest over the patches: a revision-only rebuild keeps the same identity.
func ExampleSourceComponent() {
	source := component.Source{
		Name:       "example",
		Version:    "1.2.3",
		Repository: "https://github.com/example/project.git",
		Commit:     "0123456789abcdef0123456789abcdef01234567",
		Patches:    []component.Patch{{Name: "fix-build.patch", Digest: "sha256:abc"}},
	}

	c := component.SourceComponent(source)
	fmt.Println(c.PURL)
	fmt.Println(c.Kind, c.DigestAlgo)
	// Output:
	// pkg:generic/github.com/example/project@0123456789abcdef0123456789abcdef01234567
	// package-source patch-set
}

// DeclaredLicense reads what a component's own authors claim, which is a
// declaration rather than a conclusion. Maven's several license entries mean a
// choice, which is the opposite of the usual default.
func ExampleDeclaredLicense() {
	fsys := fstest.MapFS{
		component.POMName(0): &fstest.MapFile{Data: []byte(
			`<project><licenses>` +
				`<license><name>EPL-2.0</name></license>` +
				`<license><name>GPL-2.0-only WITH Classpath-exception-2.0</name></license>` +
				`</licenses></project>`)},
	}

	fmt.Println(component.DeclaredLicense(fsys, component.EcosystemMaven))
	// Output: EPL-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0
}

// Manifests reports every declaration at the root of a tree, for evidence that
// records what was claimed as well as what was found.
func ExampleManifests() {
	fsys := fstest.MapFS{
		"package.json": &fstest.MapFile{Data: []byte(`{"name":"example","license":"MIT"}`)},
		"Cargo.toml":   &fstest.MapFile{Data: []byte("[package]\nlicense = \"MIT OR Apache-2.0\"\n")},
	}

	for _, m := range component.Manifests(fsys) {
		fmt.Printf("%-14s %-6s %s\n", m.Path, m.Ecosystem, m.License)
	}
	// Output:
	// Cargo.toml     cargo  MIT OR Apache-2.0
	// package.json   npm    MIT
}

// SourceEcosystems and InstalledEcosystems say what can be enumerated from
// where, so a consumer measuring coverage can tell a gap in this module from a
// gap in the package it scanned.
func ExampleSourceEcosystems() {
	fmt.Println(component.SourceEcosystems())
	fmt.Println(component.InstalledEcosystems())
	// Output:
	// [golang cargo npm]
	// [pypi maven]
}
