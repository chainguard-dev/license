/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package component

import (
	"strings"
	"testing"
)

// lockV3 is the flat layout npm 7 and later write.
const lockV3 = `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0"},
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="
    },
    "node_modules/@babel/core": {
      "version": "7.24.0",
      "resolved": "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz",
      "integrity": "sha512-fakebabelhash=="
    },
    "node_modules/jest": {
      "version": "29.7.0",
      "resolved": "https://registry.npmjs.org/jest/-/jest-29.7.0.tgz",
      "integrity": "sha512-fakejesthash==",
      "dev": true
    },
    "node_modules/nested-dep/node_modules/ms": {
      "version": "2.1.3",
      "resolved": "https://registry.npmjs.org/ms/-/ms-2.1.3.tgz",
      "integrity": "sha512-fakemshash=="
    },
    "packages/ui": {"name": "@app/ui", "version": "1.0.0"},
    "node_modules/@app/ui": {"resolved": "packages/ui", "link": true},
    "node_modules/from-git": {
      "version": "1.0.0",
      "resolved": "git+ssh://git@github.com/example/from-git.git#abc123"
    }
  }
}`

func TestEnumerateNpmComponentsFlatLockfile(t *testing.T) {
	fsys := tree(map[string]string{"package-lock.json": lockV3})
	comps, notes := split(enumerateNpm(t.Context(), fsys))
	got := byPURL(comps)

	// A scope stays a literal "@scope/name", which is the spelling the rest of
	// the fleet emits and the one sentinel's storage layer canonicalizes to; the
	// two spellings are not interchangeable as determination keys.
	for _, want := range []string{
		"pkg:npm/lodash@4.17.21",
		"pkg:npm/@babel/core@7.24.0",
		"pkg:npm/ms@2.1.3",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s; got %v", want, comps)
		}
	}
	if len(comps) != 3 {
		t.Errorf("components: got = %d (%v), want = 3", len(comps), comps)
	}

	// The integrity hash is the lockfile's independent witness to the content.
	if c := got["pkg:npm/lodash@4.17.21"]; !strings.HasPrefix(c.Digest, "sha512-") || c.DigestAlgo != "npm-integrity" {
		t.Errorf("digest: got = %q/%q, want the recorded integrity", c.Digest, c.DigestAlgo)
	}

	if !hasNoteContaining(notes, "development dependencies excluded") {
		t.Errorf("notes: got = %v, want the dev exclusion recorded", notes)
	}
	if !hasNoteContaining(notes, "workspace or non-registry") {
		t.Errorf("notes: got = %v, want the workspace and git entries recorded", notes)
	}
}

// TestEnumerateNpmComponentsNestedLockfile covers the version 1 layout, which
// records only a nested tree and no flat map.
func TestEnumerateNpmComponentsNestedLockfile(t *testing.T) {
	const lockV1 = `{
	  "lockfileVersion": 1,
	  "dependencies": {
	    "express": {
	      "version": "4.18.2",
	      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
	      "integrity": "sha1-fakeexpress=",
	      "dependencies": {
	        "cookie": {
	          "version": "0.5.0",
	          "resolved": "https://registry.npmjs.org/cookie/-/cookie-0.5.0.tgz",
	          "integrity": "sha512-fakecookie=="
	        }
	      }
	    },
	    "mocha": {
	      "version": "10.0.0",
	      "resolved": "https://registry.npmjs.org/mocha/-/mocha-10.0.0.tgz",
	      "dev": true
	    }
	  }
	}`
	fsys := tree(map[string]string{"package-lock.json": lockV1})
	comps, _ := split(enumerateNpm(t.Context(), fsys))
	got := byPURL(comps)
	for _, want := range []string{"pkg:npm/express@4.18.2", "pkg:npm/cookie@0.5.0"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s; got %v", want, comps)
		}
	}
	if _, ok := got["pkg:npm/mocha@10.0.0"]; ok {
		t.Error("a development dependency was enumerated")
	}
}

// TestEnumerateNpmComponentsPrefersShrinkwrap pins the precedence npm itself
// applies when a project ships both.
func TestEnumerateNpmComponentsPrefersShrinkwrap(t *testing.T) {
	fsys := tree(map[string]string{
		"package-lock.json": lockV3,
		"npm-shrinkwrap.json": `{"lockfileVersion": 3, "packages": {
		  "node_modules/only-in-shrinkwrap": {"version": "1.0.0",
		    "resolved": "https://registry.npmjs.org/only-in-shrinkwrap/-/only-in-shrinkwrap-1.0.0.tgz"}
		}}`,
	})
	comps, _ := split(enumerateNpm(t.Context(), fsys))
	if len(comps) != 1 || comps[0].Name != "only-in-shrinkwrap" {
		t.Errorf("got = %v, want only the shrinkwrap's entry", comps)
	}
}

func TestEnumerateNpmComponentsNoLockfile(t *testing.T) {
	fsys := tree(map[string]string{"package.json": `{"name": "app"}`})
	comps, notes := split(enumerateNpm(t.Context(), fsys))
	if len(comps) != 0 || len(notes) != 0 {
		t.Errorf("got = %v / %v, want nothing without a lockfile", comps, notes)
	}
}

func TestEnumerateNpmComponentsMalformedLockfile(t *testing.T) {
	fsys := tree(map[string]string{"package-lock.json": "{ not json"})
	enumerated := enumerateNpm(t.Context(), fsys)
	if got := enumerated.Components; len(got) != 0 {
		t.Errorf("components: got = %v, want none", got)
	}
	// A lockfile that could not be parsed is a failure rather than a note,
	// because a consumer has to be able to tell it from a package with no
	// dependencies.
	if len(enumerated.Failures) == 0 {
		t.Error("failures: got none, want the parse failure recorded rather than swallowed")
	}
	for _, f := range enumerated.Failures {
		if f.Path != "package-lock.json" || f.Ecosystem != EcosystemNpm {
			t.Errorf("failure: got = %+v, want it attributed to the npm lockfile", f)
		}
	}
}

func TestNpmPURL(t *testing.T) {
	for _, tt := range []struct{ name, version, want string }{
		{name: "lodash", version: "4.17.21", want: "pkg:npm/lodash@4.17.21"},
		{name: "@babel/core", version: "7.24.0", want: "pkg:npm/@babel/core@7.24.0"},
		{name: "@types/node", version: "20.0.0", want: "pkg:npm/@types/node@20.0.0"},
		{name: "lodash", version: "", want: "pkg:npm/lodash"},
	} {
		t.Run(tt.name+"@"+tt.version, func(t *testing.T) {
			if got := NpmPURL(tt.name, tt.version); got != tt.want {
				t.Errorf("got = %q, want = %q", got, tt.want)
			}
		})
	}
}

func TestNpmNameFromPath(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{in: "node_modules/lodash", want: "lodash"},
		{in: "node_modules/@babel/core", want: "@babel/core"},
		{in: "node_modules/a/node_modules/b", want: "b"},
		{in: "packages/ui", want: ""},
	} {
		t.Run(tt.in, func(t *testing.T) {
			if got := npmNameFromPath(tt.in); got != tt.want {
				t.Errorf("got = %q, want = %q", got, tt.want)
			}
		})
	}
}

// TestEnumerateNpmComponentsVersion2PrefersTheFlatLayout covers the schema that
// carries both layouts for backward compatibility. The flat one is preferred
// because it states the dev flag per entry, which the nested one does not, and
// reading the nested one would ship development dependencies into the closure.
func TestEnumerateNpmComponentsVersion2PrefersTheFlatLayout(t *testing.T) {
	fsys := tree(map[string]string{"package-lock.json": `{
	  "lockfileVersion": 2,
	  "packages": {
	    "": {"name": "app", "version": "1.0.0"},
	    "node_modules/left-pad": {
	      "version": "1.3.0",
	      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
	      "integrity": "sha512-flat"
	    },
	    "node_modules/mocha": {
	      "version": "10.0.0",
	      "resolved": "https://registry.npmjs.org/mocha/-/mocha-10.0.0.tgz",
	      "integrity": "sha512-dev",
	      "dev": true
	    }
	  },
	  "dependencies": {
	    "left-pad": {
	      "version": "1.2.0",
	      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.2.0.tgz",
	      "integrity": "sha512-nested"
	    },
	    "mocha": {
	      "version": "10.0.0",
	      "resolved": "https://registry.npmjs.org/mocha/-/mocha-10.0.0.tgz",
	      "integrity": "sha512-dev"
	    }
	  }
	}`})

	comps, notes := split(enumerateNpm(t.Context(), fsys))
	got := byPURL(comps)
	if len(comps) != 1 {
		t.Fatalf("components: got = %v, want only the shipped dependency", comps)
	}
	// The version from the flat layout, not the one the nested copy records.
	left, ok := got["pkg:npm/left-pad@1.3.0"]
	if !ok {
		t.Fatalf("components: got = %v, want the flat layout's version", got)
	}
	if left.Digest != "sha512-flat" {
		t.Errorf("digest: got = %q, want the flat layout's integrity", left.Digest)
	}
	if !hasNoteContaining(notes, "development dependencies excluded") {
		t.Errorf("notes: got = %v, want the excluded dev dependency accounted for", notes)
	}
}

// TestEnumerateNpmNamesNoAlgorithmWithoutAnIntegrity covers a registry-resolved
// entry with no integrity hash, which is what a private registry that does not
// serve one produces. A scheme recorded beside an empty digest claims a
// verification nobody can perform.
func TestEnumerateNpmNamesNoAlgorithmWithoutAnIntegrity(t *testing.T) {
	const noIntegrity = `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0"},
    "node_modules/internal-lib": {
      "version": "2.0.0",
      "resolved": "https://npm.internal.example.com/internal-lib/-/internal-lib-2.0.0.tgz"
    }
  }
}`

	comps, _ := split(enumerateNpm(t.Context(), tree(map[string]string{"package-lock.json": noIntegrity})))
	if len(comps) != 1 {
		t.Fatalf("components: got = %+v, want one", comps)
	}
	if comps[0].Digest != "" || comps[0].DigestAlgo != "" {
		t.Errorf("got digest %q algo %q, want both empty; the lockfile records no integrity", comps[0].Digest, comps[0].DigestAlgo)
	}
}
