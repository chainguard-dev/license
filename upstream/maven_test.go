/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package upstream

import (
	"crypto/sha1" //nolint:gosec // mirroring the checksum Maven Central publishes.
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"chainguard.dev/license/component"
)

// mavenRepo serves a repository laid out the way Central is: files addressed by
// group path, artifact and version, with a .sha1 beside each.
func mavenRepo(t *testing.T, files map[string][]byte) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := files[r.URL.Path]; ok {
			w.Write(body)
			return
		}
		if base, cut := strings.CutSuffix(r.URL.Path, ".sha1"); cut {
			if body, ok := files[base]; ok {
				sum := sha1.Sum(body) //nolint:gosec // matching Central's scheme.
				fmt.Fprintf(w, "%s  %s\n", hex.EncodeToString(sum[:]), base)
				return
			}
		}
		http.NotFound(w, r)
	}))
}

func pom(licenses, parent string) []byte {
	return []byte(`<?xml version="1.0"?><project>` + parent + licenses + `</project>`)
}

const apacheLicense = `<licenses><license><name>Apache License, Version 2.0</name><url>https://www.apache.org/licenses/LICENSE-2.0.txt</url></license></licenses>`

func TestMavenResolverFetchesPomAndJar(t *testing.T) {
	jar := makeWheel(t, map[string]string{
		"META-INF/LICENSE.txt": "Apache License Version 2.0",
		"META-INF/maven/commons-beanutils/commons-beanutils/pom.properties": "groupId=commons-beanutils\n",
		"org/apache/commons/beanutils/BeanUtils.class":                      "not really bytecode",
	})
	srv := mavenRepo(t, map[string][]byte{
		"/commons-beanutils/commons-beanutils/1.11.0/commons-beanutils-1.11.0.pom": pom(apacheLicense, ""),
		"/commons-beanutils/commons-beanutils/1.11.0/commons-beanutils-1.11.0.jar": jar,
	})
	defer srv.Close()

	r := &MavenResolver{client: serverClient(t, srv), base: serverURL()}
	art, err := r.Fetch(t.Context(), component.Component{
		Name: "commons-beanutils:commons-beanutils", Version: "1.11.0", Ecosystem: "maven",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !art.Matched {
		t.Error("Matched: got false, want the jar to verify against the published .sha1")
	}
	if _, err := fs.Stat(art.FS, "pom.xml"); err != nil {
		t.Errorf("pom.xml in artifact filesystem: got err = %v, want the file to be present", err)
	}
	if _, err := fs.Stat(art.FS, "META-INF/LICENSE.txt"); err != nil {
		t.Errorf("META-INF/LICENSE.txt: got err = %v, want the jar's license file to be retained", err)
	}
	// The retention filter keeps evidence, not bytecode.
	if _, err := fs.Stat(art.FS, "org/apache/commons/beanutils/BeanUtils.class"); err == nil {
		t.Error("class files should not survive expansion")
	}
}

// TestMavenResolverFollowsParentChain is the majority case: of the 65 POMs in a
// representative package, 36 declare licenses only through a parent.
func TestMavenResolverFollowsParentChain(t *testing.T) {
	const childParent = `<parent><groupId>org.apache</groupId><artifactId>apache</artifactId><version>31</version></parent>`
	const midParent = `<parent><groupId>org.apache</groupId><artifactId>apache-root</artifactId><version>4</version></parent>`

	srv := mavenRepo(t, map[string][]byte{
		"/org/example/widget/1.0/widget-1.0.pom":      pom("", childParent),
		"/org/apache/apache/31/apache-31.pom":         pom("", midParent),
		"/org/apache/apache-root/4/apache-root-4.pom": pom(apacheLicense, ""),
	})
	defer srv.Close()

	r := &MavenResolver{client: serverClient(t, srv), base: serverURL()}
	art, err := r.Fetch(t.Context(), component.Component{Name: "org.example:widget", Version: "1.0", Ecosystem: "maven"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// Nearest first, so the grandparent that actually declares is the third.
	for _, want := range []string{"pom.xml", "pom-parent-1.xml", "pom-parent-2.xml"} {
		if _, err := fs.Stat(art.FS, want); err != nil {
			t.Errorf("%s in chain: got err = %v, want the file to be present", want, err)
		}
	}
}

// TestMavenResolverStopsAtTheFirstDeclaration pins that inheritance is not
// walked further than it needs to be: a parent cannot override a child.
func TestMavenResolverStopsAtTheFirstDeclaration(t *testing.T) {
	const parent = `<parent><groupId>org.example</groupId><artifactId>root</artifactId><version>1</version></parent>`
	srv := mavenRepo(t, map[string][]byte{
		"/org/example/widget/1.0/widget-1.0.pom": pom(apacheLicense, parent),
		"/org/example/root/1/root-1.pom":         pom(`<licenses><license><name>MIT</name></license></licenses>`, ""),
	})
	defer srv.Close()

	r := &MavenResolver{client: serverClient(t, srv), base: serverURL()}
	art, err := r.Fetch(t.Context(), component.Component{Name: "org.example:widget", Version: "1.0", Ecosystem: "maven"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if _, err := fs.Stat(art.FS, "pom-parent-1.xml"); err == nil {
		t.Error("the parent was fetched even though the child declares a license")
	}
}

// TestMavenResolverSurvivesAMissingJar covers packaging=pom artifacts and
// anything published under another extension: the declaration still resolves,
// which for Java is the load-bearing half.
func TestMavenResolverSurvivesAMissingJar(t *testing.T) {
	srv := mavenRepo(t, map[string][]byte{
		"/org/example/bom/1.0/bom-1.0.pom": pom(apacheLicense, ""),
	})
	defer srv.Close()

	r := &MavenResolver{client: serverClient(t, srv), base: serverURL()}
	art, err := r.Fetch(t.Context(), component.Component{Name: "org.example:bom", Version: "1.0", Ecosystem: "maven"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if _, err := fs.Stat(art.FS, "pom.xml"); err != nil {
		t.Errorf("pom.xml: got err = %v, want the POM present despite the absent jar", err)
	}
	if art.Matched {
		t.Error("nothing was verified, so Canonical must be false")
	}
}

func TestMavenResolverMissingArtifactIsGone(t *testing.T) {
	srv := mavenRepo(t, nil)
	defer srv.Close()

	r := &MavenResolver{client: serverClient(t, srv), base: serverURL()}
	_, err := r.Fetch(t.Context(), component.Component{Name: "org.example:nope", Version: "1.0", Ecosystem: "maven"})
	if !errors.Is(err, ErrGone) {
		t.Errorf("got = %v, want ErrGone", err)
	}
}

// TestMavenResolverBoundsACyclicParentChain pins that a POM naming itself as its
// own parent terminates rather than fetching forever.
func TestMavenResolverBoundsACyclicParentChain(t *testing.T) {
	const selfParent = `<parent><groupId>org.example</groupId><artifactId>loop</artifactId><version>1.0</version></parent>`
	srv := mavenRepo(t, map[string][]byte{
		"/org/example/loop/1.0/loop-1.0.pom": pom("", selfParent),
	})
	defer srv.Close()

	r := &MavenResolver{client: serverClient(t, srv), base: serverURL()}
	art, err := r.Fetch(t.Context(), component.Component{Name: "org.example:loop", Version: "1.0", Ecosystem: "maven"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if _, err := fs.Stat(art.FS, "pom-parent-1.xml"); err == nil {
		t.Error("a self-referential parent was followed")
	}
}

func TestMavenResolverRejectsIncompleteCoordinates(t *testing.T) {
	r := NewMavenResolver(nil)
	for _, c := range []component.Component{
		{Name: "no-colon", Version: "1.0"},
		{Name: "org.example:widget"},
		{Name: ":widget", Version: "1.0"},
	} {
		if _, err := r.Fetch(t.Context(), c); err == nil {
			t.Errorf("Fetch(%+v): got nil error, want one for incomplete coordinates", c)
		}
	}
}

// TestMavenResolverGonePOMStillFetchesTheJar covers coordinates the registry
// holds a jar for but no POM.
//
// The jar ships the license files, so writing the component off would discard
// the evidence it does carry. A note records that nothing declared a license.
func TestMavenResolverGonePOMStillFetchesTheJar(t *testing.T) {
	jar := makeZip(t, "META-INF", map[string]string{"LICENSE": "Apache-2.0 license text"})
	srv := mavenRepo(t, map[string][]byte{"/org/example/widget/1.0/widget-1.0.jar": jar})
	defer srv.Close()

	r := &MavenResolver{client: serverClient(t, srv), base: serverURL()}
	art, err := r.Fetch(t.Context(), component.Component{Name: "org.example:widget", Version: "1.0", Ecosystem: "maven"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if _, err := fs.Stat(art.FS, "META-INF/LICENSE"); err != nil {
		t.Errorf("META-INF/LICENSE: got err = %v, want the jar's license file to be present", err)
	}
	if !slices.ContainsFunc(art.Notes, func(n string) bool { return strings.Contains(n, "no POM") }) {
		t.Errorf("notes: got = %v, want one recording that no POM was fetched", art.Notes)
	}
}

// TestMavenResolverTransientAncestorFailureIsReported covers an ancestor POM
// the registry answers with a 500 rather than a 404.
//
// Treating it as the end of the chain would resolve the component as declaring
// nothing, with no error to retry and no record that anything went wrong, when
// the ancestor that declares the license was merely unreachable.
func TestMavenResolverTransientAncestorFailureIsReported(t *testing.T) {
	child := []byte(`<project><parent><groupId>org.example</groupId><artifactId>parent</artifactId><version>1.0</version></parent></project>`)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/org/example/widget/1.0/widget-1.0.pom":
			w.Write(child)
		case "/org/example/parent/1.0/parent-1.0.pom":
			http.Error(w, "upstream unavailable", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	r := &MavenResolver{client: serverClient(t, srv), base: serverURL()}
	_, err := r.Fetch(t.Context(), component.Component{Name: "org.example:widget", Version: "1.0", Ecosystem: "maven"})
	if err == nil {
		t.Fatal("Fetch: got nil error, want an unreachable ancestor to be reported")
	}
	if errors.Is(err, ErrGone) {
		t.Errorf("got ErrGone for a transient failure: %v; the caller must be able to retry", err)
	}
}
