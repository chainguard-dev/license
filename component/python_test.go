/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package component

import (
	"strings"
	"testing"
	"testing/fstest"
)

// metadata renders the leading headers of a dist-info METADATA file, followed by
// the long description every real one carries.
func metadata(name, version string) string {
	return strings.Join([]string{
		"Metadata-Version: 2.1",
		"Name: " + name,
		"Version: " + version,
		"Summary: a package",
		"",
		"Long description, which is usually the whole README and must not be read.",
	}, "\n")
}

func TestEnumeratePythonComponents(t *testing.T) {
	// The venv path is deliberate: py3-cassandra-medusa installs into
	// /home/cassandra/.venv rather than usr/lib/python3.X, so a hardcoded
	// interpreter path would find nothing.
	tree := Tree{
		Name: "melange-out/py3-app",
		FS: fstest.MapFS{
			"home/app/.venv/lib/python3.11/site-packages/requests-2.32.3.dist-info/METADATA": {
				Data: []byte(metadata("requests", "2.32.3")),
			},
			"home/app/.venv/lib/python3.11/site-packages/zope_interface-8.0.1.dist-info/METADATA": {
				Data: []byte(metadata("zope.interface", "8.0.1")),
			},
			"home/app/.venv/lib/python3.11/site-packages/requests/api.py": {Data: []byte("pass")},
		},
	}

	comps, notes := split(enumeratePython(t.Context(), []Tree{tree}, "py3-app"))
	if len(comps) != 2 {
		t.Fatalf("components: got = %d, want = 2 (%v)", len(comps), comps)
	}

	got := byPURL(comps)
	// PEP 503 normalization is what makes "zope.interface" and "zope_interface"
	// one determination rather than three.
	want := map[string]struct{ name, version string }{
		"pkg:pypi/requests@2.32.3":      {"requests", "2.32.3"},
		"pkg:pypi/zope-interface@8.0.1": {"zope.interface", "8.0.1"},
	}
	for purl, w := range want {
		c, ok := got[purl]
		if !ok {
			t.Errorf("missing %s; got %v", purl, comps)
			continue
		}
		if c.Name != w.name || c.Version != w.version {
			t.Errorf("%s: got = %q@%q, want = %q@%q", purl, c.Name, c.Version, w.name, w.version)
		}
		if c.Ecosystem != "pypi" || c.Kind != KindEcosystem {
			t.Errorf("%s: got ecosystem/kind = %q/%q, want = pypi/%s", purl, c.Ecosystem, c.Kind, KindEcosystem)
		}
		// No digest is available from an installed tree, and inventing one would
		// make every component look like it diverged from its published release.
		if c.Digest != "" {
			t.Errorf("%s: got digest = %q, want empty", purl, c.Digest)
		}
		if !strings.HasPrefix(c.DiscoveredFrom, "melange-out/py3-app/") {
			t.Errorf("%s: got discovered_from = %q, want it to trace back to the tree", purl, c.DiscoveredFrom)
		}
	}
	if len(notes) == 0 {
		t.Error("notes: got none, want the enumerated count recorded")
	}
}

// TestEnumeratePythonComponentsExcludesOwnProject covers the shape every Python
// apk has: the project it packages is installed beside its dependencies, and is
// already covered by the package-source component.
func TestEnumeratePythonComponentsExcludesOwnProject(t *testing.T) {
	for _, tt := range []struct {
		pkgName string
		dist    string
	}{
		{pkgName: "py3-cassandra-medusa", dist: "cassandra_medusa"},
		{pkgName: "py3.11-cassandra-medusa", dist: "cassandra-medusa"},
		{pkgName: "py3-zope-interface", dist: "zope.interface"},
	} {
		t.Run(tt.pkgName, func(t *testing.T) {
			tree := Tree{
				Name: "melange-out/" + tt.pkgName,
				FS: fstest.MapFS{
					"usr/lib/python3.11/site-packages/own-0.25.1.dist-info/METADATA": {
						Data: []byte(metadata(tt.dist, "0.25.1")),
					},
					"usr/lib/python3.11/site-packages/requests-2.32.3.dist-info/METADATA": {
						Data: []byte(metadata("requests", "2.32.3")),
					},
				},
			}
			comps, _ := split(enumeratePython(t.Context(), []Tree{tree}, tt.pkgName))
			if len(comps) != 1 || comps[0].Name != "requests" {
				t.Errorf("got = %v, want only requests; the package's own project is not its own dependency", comps)
			}
		})
	}
}

// TestEnumeratePythonComponentsKeepsUnrelatedNames pins the conservative
// direction of the own-project match: dropping a real dependency loses it from
// the audit entirely, while keeping one costs a duplicate determination.
func TestEnumeratePythonComponentsKeepsUnrelatedNames(t *testing.T) {
	tree := Tree{
		Name: "melange-out/py3-app",
		FS: fstest.MapFS{
			"site-packages/app_core-1.0.dist-info/METADATA": {Data: []byte(metadata("app-core", "1.0"))},
		},
	}
	comps, _ := split(enumeratePython(t.Context(), []Tree{tree}, "py3-app"))
	if len(comps) != 1 {
		t.Errorf("got = %v, want app-core kept; it is not the same project as app", comps)
	}
}

func TestEnumeratePythonComponentsUnreadableMetadata(t *testing.T) {
	tree := Tree{
		Name: "melange-out/py3-app",
		FS: fstest.MapFS{
			// A dist-info with no METADATA at all.
			"site-packages/broken-1.0.dist-info/RECORD": {Data: []byte("")},
			// One whose METADATA has no Name.
			"site-packages/headerless-1.0.dist-info/METADATA": {Data: []byte("Version: 1.0\n")},
			"site-packages/good-1.0.dist-info/METADATA":       {Data: []byte(metadata("good", "1.0"))},
		},
	}
	enumerated := enumeratePython(t.Context(), []Tree{tree}, "py3-app")
	if got := enumerated.Components; len(got) != 1 || got[0].Name != "good" {
		t.Errorf("components: got = %v, want only good", got)
	}
	// A distribution that ships and was not enumerated is a gap in the
	// closure, so it is reported as a failure rather than a remark about one.
	if !hasFailureContaining(enumerated.Failures, "no readable METADATA") {
		t.Errorf("failures: got = %v, want the unreadable metadata recorded", enumerated.Failures)
	}
}

func TestEnumeratePythonComponentsAcrossTrees(t *testing.T) {
	// A config produces many apks, and the same dependency is routinely
	// installed into more than one of them.
	trees := []Tree{
		{Name: "melange-out/py3.11-app", FS: fstest.MapFS{
			"site-packages/requests-2.32.3.dist-info/METADATA": {Data: []byte(metadata("requests", "2.32.3"))},
		}},
		{Name: "melange-out/py3.12-app", FS: fstest.MapFS{
			"site-packages/requests-2.32.3.dist-info/METADATA": {Data: []byte(metadata("requests", "2.32.3"))},
			"site-packages/urllib3-2.2.1.dist-info/METADATA":   {Data: []byte(metadata("urllib3", "2.2.1"))},
		}},
	}
	comps, _ := split(EnumerateInstalled(t.Context(), trees, "py3-app"))
	if len(comps) != 2 {
		t.Errorf("got = %d components (%v), want = 2; one identity is one component however many apks ship it", len(comps), comps)
	}
}

func TestEnumerateOutputComponentsNoTrees(t *testing.T) {
	comps, notes := split(EnumerateInstalled(t.Context(), nil, "py3-app"))
	if len(comps) != 0 || len(notes) != 0 {
		t.Errorf("got = %v / %v, want nothing; Collect reports the absence, not the enumerators", comps, notes)
	}
}

func TestReadDistMetadataStopsAtTheBody(t *testing.T) {
	// A long description can repeat header-shaped lines; reading past the blank
	// line would let the README rename the distribution.
	fsys := fstest.MapFS{
		"METADATA": {Data: []byte("Metadata-Version: 2.1\nName: real\nVersion: 1.0\n\nName: fake\nVersion: 9.9\n")},
	}
	name, version, err := readDistMetadata(fsys, "METADATA")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "real" || version != "1.0" {
		t.Errorf("got = %q@%q, want = real@1.0", name, version)
	}
}

func TestReadDistMetadataSkipsFoldedLines(t *testing.T) {
	fsys := fstest.MapFS{
		"METADATA": {Data: []byte("Summary: a summary\n continued: onto another line\nName: real\nVersion: 1.0\n\n")},
	}
	name, version, err := readDistMetadata(fsys, "METADATA")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "real" || version != "1.0" {
		t.Errorf("got = %q@%q, want = real@1.0", name, version)
	}
}

func TestNormalizePyPIName(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{in: "requests", want: "requests"},
		{in: "zope.interface", want: "zope-interface"},
		{in: "zope_interface", want: "zope-interface"},
		{in: "Zope--Interface", want: "zope-interface"},
		{in: "  ruamel.yaml.clib  ", want: "ruamel-yaml-clib"},
	} {
		t.Run(tt.in, func(t *testing.T) {
			if got := NormalizePyPIName(tt.in); got != tt.want {
				t.Errorf("got = %q, want = %q", got, tt.want)
			}
		})
	}
}

func hasNoteContaining(notes []string, substr string) bool {
	for _, n := range notes {
		if strings.Contains(n, substr) {
			return true
		}
	}
	return false
}

// TestEnumeratePythonComponentsIncludesNestedVendored pins that the source
// tree's location rules do not carry over to an installed tree. setuptools
// vendors sixteen distributions into py3-cassandra-medusa, and every one of them
// ships.
func TestEnumeratePythonComponentsIncludesNestedVendored(t *testing.T) {
	tree := Tree{
		Name: "melange-out/py3-app",
		FS: fstest.MapFS{
			"site-packages/setuptools-75.0.dist-info/METADATA":                {Data: []byte(metadata("setuptools", "75.0"))},
			"site-packages/setuptools/_vendor/zipp-3.19.2.dist-info/METADATA": {Data: []byte(metadata("zipp", "3.19.2"))},
		},
	}
	comps, _ := split(enumeratePython(t.Context(), []Tree{tree}, "py3-app"))
	got := byPURL(comps)
	if _, ok := got["pkg:pypi/zipp@3.19.2"]; !ok {
		t.Errorf("got = %v, want the vendored distribution kept; it ships and its license applies", comps)
	}
	if len(comps) != 2 {
		t.Errorf("components: got = %d, want = 2", len(comps))
	}
}
