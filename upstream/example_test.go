/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package upstream_test

import (
	"context"
	"fmt"

	"chainguard.dev/license/component"
	"chainguard.dev/license/upstream"
)

// A resolver set fetches the published content of a component so that its
// license can be concluded from the bytes upstream actually shipped. The
// component's own digest, from a lockfile, is what the fetch is checked
// against.
func ExampleDefaultSet() {
	resolvers := upstream.DefaultSet(nil)
	fmt.Println(len(resolvers.Ecosystems()), "ecosystems can be fetched")

	// An ecosystem with no resolver is a coverage gap to report rather than a
	// failure to retry.
	_, err := resolvers.Fetch(context.Background(), component.Component{
		Ecosystem: "nuget",
		Name:      "Newtonsoft.Json",
		Version:   "13.0.3",
	})
	fmt.Println(err)
	// Output:
	// 5 ecosystems can be fetched
	// no resolver for ecosystem: nuget
}

// ValidateURL refuses the internal targets a URL chosen by something untrusted
// could aim at. There is no way to fetch through this package without it.
func ExampleValidateURL() {
	for _, url := range []string{
		"http://proxy.golang.org/example.com/@v/v1.0.0.zip",
		"https://169.254.169.254/latest/meta-data",
		"https://metadata.google.internal/computeMetadata/v1/",
		"https://user:secret@github.com/example/project",
	} {
		fmt.Println(upstream.ValidateURL(context.Background(), url))
	}
	// Output:
	// unsupported URL scheme: only https is allowed, got "http://proxy.golang.org/example.com/@v/v1.0.0.zip"
	// URL "https://169.254.169.254/latest/meta-data": IP-literal hosts are not allowed
	// URL "https://metadata.google.internal/computeMetadata/v1/": internal hosts are not allowed
	// URL must not contain userinfo credentials
}

// RedactURL is for the caller that has to name the URL it was given in a log
// line or a tool result.
func ExampleRedactURL() {
	fmt.Println(upstream.RedactURL("https://user:secret@github.com/example/project"))
	// Output: https://github.com/example/project
}

// AuthEnv carries a credential to git through the environment rather than the
// command line, and offers it only to the hosts allowed for the request.
func ExampleAuthEnv() {
	token := func(context.Context) (string, error) { return "hunter2", nil }

	fmt.Println(len(upstream.AuthEnv(context.Background(), "https://github.com/example/project", token)))
	fmt.Println(len(upstream.AuthEnv(context.Background(), "https://gitlab.example.com/example/project", token)))
	// Output:
	// 1
	// 0
}

// Retain is the filter that makes large artifacts readable at all: some crates
// ship tens of megabytes of generated bindings, while the licensing evidence in
// them is a handful of kilobyte-sized files.
func ExampleRetain() {
	for _, path := range []string{"LICENSE", "Cargo.toml", "README.md", "src/generated.rs"} {
		fmt.Printf("%-18s %v\n", path, upstream.Retain(path))
	}
	// Output:
	// LICENSE            true
	// Cargo.toml         true
	// README.md          true
	// src/generated.rs   false
}
