/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package upstream

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
	"testing/fstest"

	"chainguard.dev/license/component"
	"chainguard.dev/license/detect"
)

const (
	// maxArchiveEntries bounds how many members an archive may declare, so a
	// pathological index cannot make expansion unbounded before any member is
	// even read.
	maxArchiveEntries = 100_000

	// MaxDecompressedBytes bounds how much a tarball may decompress to in
	// total, members this package discards included.
	//
	// It is a separate and much looser bound than MaxExpandedBytes, which
	// covers only the members retained. The two are not the same guard: a tar
	// is read as a stream, so reaching the next member's header means
	// decompressing the one before it whether or not it is kept. Without this,
	// a gzip bomb whose members are all named payload.bin would decompress
	// without end while retaining nothing at all.
	//
	// The value has to clear the real artifacts. Some published archives are
	// genuinely large - a crate of generated bindings, a repository at a
	// revision - and refusing them would be refusing real dependencies, which
	// is the mistake an earlier download cap already made.
	MaxDecompressedBytes = 1 << 30
)

// Retain reports whether a file inside a published artifact can bear on
// licensing, and is therefore worth expanding.
//
// The point is to expand only what licensing needs. Some published artifacts
// are enormous - the windows crate ships tens of megabytes of generated
// bindings, which exceeded the expansion limit and cost the whole component --
// while the evidence in them is a handful of kilobyte-sized files. Retaining
// that handful turns an artifact that could not be read at all into one that
// can.
//
// The retained set is a superset of what classification reads, so filtering can
// never drop a text that would have been classified: license files by the
// shared discovery rule, plus the manifests a declared license is read from and
// the prose files a relationship statement is read from.
//
// What is lost is the license headers in source files, which a deeper analysis
// could otherwise have read. That is a smaller loss than having no content at
// all.
func Retain(p string) bool {
	if is, _ := detect.IsLicenseFile(p); is {
		return true
	}
	base := path.Base(p)
	return component.IsManifestFile(base) || detect.IsProseFile(base)
}

// zipFS expands a zip archive into an in-memory filesystem, retaining only the
// members that can bear on licensing.
//
// Published archives nest their contents under a single directory - module
// zips under "<module>@<version>/", which itself contains slashes - so the
// caller passes the exact prefix to remove rather than having a segment count
// guessed. What happens to a member outside that prefix depends on whether the
// prefix matched anything at all; see members.
func zipFS(r io.ReaderAt, size int64, prefix string) (fstest.MapFS, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("reading zip: %w", err)
	}
	if len(zr.File) > maxArchiveEntries {
		return nil, fmt.Errorf("zip declares %d entries, over the %d limit", len(zr.File), maxArchiveEntries)
	}

	var found members
	var total int64
	for _, f := range zr.File {
		// Only regular files. A symlink entry's data is its target path, and
		// retaining one would record a path as though it were license text --
		// which then reads as a divergence from the checkout that resolves it.
		if !f.FileInfo().Mode().IsRegular() {
			continue
		}
		name, inside := memberName(f.Name, prefix)
		if name == "" {
			continue
		}
		// Before the filter, so a prefix holding only source files counts as
		// matched.
		found.note(inside)
		if !Retain(name) || found.skip(inside) {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("opening %q in zip: %w", f.Name, err)
		}
		content, err := readMember(rc, &total)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("reading %q in zip: %w", f.Name, err)
		}
		if err := found.add(name, inside, &fstest.MapFile{Data: content, Mode: f.Mode()}); err != nil {
			return nil, err
		}
	}
	return found.resolve(), nil
}

// tarGzFS expands a gzipped tarball into an in-memory filesystem, with the same
// prefix handling as zipFS: a .crate archive nests everything under
// "<name>-<version>/".
func tarGzFS(r io.Reader, prefix string) (fstest.MapFS, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("reading gzip: %w", err)
	}
	defer gz.Close()

	var found members
	var total int64
	bounded := &boundedReader{r: gz, remaining: MaxDecompressedBytes}
	tr := tar.NewReader(bounded)
	for entries := 0; ; entries++ {
		if entries > maxArchiveEntries {
			return nil, fmt.Errorf("tar exceeds the %d entry limit", maxArchiveEntries)
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name, inside := memberName(hdr.Name, prefix)
		if name == "" {
			continue
		}
		// Before the filter, so a prefix holding only source files counts as
		// matched.
		found.note(inside)
		if !Retain(name) || found.skip(inside) {
			continue
		}

		content, err := readMember(tr, &total)
		if err != nil {
			return nil, fmt.Errorf("reading %q in tar: %w", hdr.Name, err)
		}
		if err := found.add(name, inside, &fstest.MapFile{Data: content, Mode: hdr.FileInfo().Mode()}); err != nil {
			return nil, err
		}
	}
	return found.resolve(), nil
}

// boundedReader stops a stream after a fixed number of bytes, with an error
// that says so.
//
// io.LimitReader would report the limit as a clean end of file, which tar
// reports in turn as a truncated archive - indistinguishable from a genuinely
// truncated one. A stream that hit the bound is a different finding from a
// stream that ended early, and only one of them is somebody attacking the
// expansion.
type boundedReader struct {
	r         io.Reader
	remaining int64
}

func (b *boundedReader) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, fmt.Errorf("archive decompresses to more than the %d byte limit", MaxDecompressedBytes)
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.r.Read(p)
	b.remaining -= int64(n)
	return n, err
}

// readMember reads one archive member, holding the running total across the
// whole archive under MaxExpandedBytes so that a highly compressible archive
// cannot expand without bound.
func readMember(r io.Reader, total *int64) ([]byte, error) {
	remaining := MaxExpandedBytes - *total
	if remaining <= 0 {
		return nil, fmt.Errorf("expanded archive exceeds the %d byte limit", MaxExpandedBytes)
	}
	content, err := io.ReadAll(io.LimitReader(r, remaining+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > remaining {
		return nil, fmt.Errorf("expanded archive exceeds the %d byte limit", MaxExpandedBytes)
	}
	*total += int64(len(content))
	return content, nil
}

// sanitizeArchivePath normalizes an archive member name and refuses anything
// that would resolve outside the archive root.
//
// Nothing here is written to disk, so this is not a write-traversal guard. It
// is an attribution guard: a member named "../../LICENSE" would otherwise place
// a license file somewhere it is not, and a determination would be drawn from
// evidence attributed to the wrong component.
func sanitizeArchivePath(name string) string {
	name = path.Clean(strings.ReplaceAll(name, `\`, "/"))
	name = strings.TrimPrefix(name, "./")
	if name == "." || name == "/" || path.IsAbs(name) {
		return ""
	}
	for seg := range strings.SplitSeq(name, "/") {
		if seg == ".." {
			return ""
		}
	}
	return name
}

// memberName returns the name to store an archive member under, and whether it
// was found inside the caller's prefix. The prefix directory itself, and
// anything sanitizing rejected, yield the empty string.
//
// A name outside the prefix keeps its full path rather than being stripped,
// because whether to keep it at all is not decidable one member at a time. See
// members.
func memberName(raw, prefix string) (name string, inside bool) {
	name = sanitizeArchivePath(raw)
	if name == "" {
		return "", false
	}
	if prefix == "" {
		return name, true
	}
	prefix = strings.TrimSuffix(prefix, "/")
	if name == prefix {
		return "", false
	}
	if rest, ok := strings.CutPrefix(name, prefix+"/"); ok {
		return rest, true
	}
	return name, false
}

// members accumulates the retained members of one archive, keeping those found
// inside the caller's prefix apart from those outside it.
//
// A member outside the prefix means one of two things. A prefix that matched
// nothing was mispredicted: a PyPI sdist's prefix comes from the filename the
// index served, and project-name normalization means the directory inside can
// differ, so keeping those members unstripped is what lets the fetch return a
// license at all.
//
// A prefix that did match is correct, so a member outside it belongs to a
// second root. Retaining that root's license files attributes them to this
// component, which sanitizeArchivePath refuses for ".." and a sibling
// directory reaches without a traversal.
type members struct {
	// prefixSeen records that a member was found inside the prefix. It is
	// separate from inside because Retain discards members that establish the
	// prefix: an archive whose prefix holds only source files has matched it
	// and carries no evidence there.
	prefixSeen bool
	inside     fstest.MapFS
	outside    fstest.MapFS
}

// note records that a member was seen, before any filtering decides whether to
// keep it.
func (m *members) note(inside bool) {
	if inside {
		m.prefixSeen = true
	}
}

// skip reports whether an out-of-prefix member can be discarded without being
// read.
//
// The answer is settled once anything has matched the prefix, so the expansion
// budget is spent only on out-of-prefix members preceding the first match.
func (m *members) skip(inside bool) bool { return !inside && m.prefixSeen }

// add records a member under the name it will be read as, and refuses an
// archive that declares one name twice with different contents.
//
// Both formats permit a duplicate, and normalization can produce one from two
// names that differed. Keeping the last drops a license text: a publisher can
// put the restrictive text first and the permissive one after. Renaming the
// second is not available, because the license-content hash covers these names
// and an invented name gives two producers different digests for one archive.
func (m *members) add(name string, inside bool, f *fstest.MapFile) error {
	target := &m.outside
	if inside {
		target = &m.inside
	}
	if *target == nil {
		*target = fstest.MapFS{}
	}
	if prior, clash := (*target)[name]; clash {
		if bytes.Equal(prior.Data, f.Data) {
			return nil
		}
		return fmt.Errorf("archive declares %q twice with different contents", name)
	}
	(*target)[name] = f
	return nil
}

// resolve returns the filesystem to hand back: what was inside the prefix, or
// everything when the prefix matched nothing.
//
// A prefix that was found but holds no evidence yields nothing. The assessment
// records that as unknown, where a second root's license would be a wrong
// answer.
func (m *members) resolve() fstest.MapFS {
	if m.prefixSeen {
		if m.inside == nil {
			return fstest.MapFS{}
		}
		return m.inside
	}
	if m.outside != nil {
		return m.outside
	}
	return fstest.MapFS{}
}

// Expand reads an archive into a filesystem, choosing the format from the
// filename.
//
// It is exported for the caller holding an archive this package did not fetch:
// a published jar or wheel handed to it directly, or an apk downloaded by a
// backfill sweep. prefix is the single directory the archive nests its contents
// under, or empty when it has none.
func Expand(name string, r io.ReaderAt, size int64, prefix string) (fs.FS, error) {
	switch {
	case strings.HasSuffix(name, ".zip"), strings.HasSuffix(name, ".jar"),
		strings.HasSuffix(name, ".whl"), strings.HasSuffix(name, ".crate.zip"):
		return zipFS(r, size, prefix)
	case strings.HasSuffix(name, ".tar.gz"), strings.HasSuffix(name, ".tgz"),
		strings.HasSuffix(name, ".crate"):
		return tarGzFS(io.NewSectionReader(r, 0, size), prefix)
	}
	return nil, fmt.Errorf("unsupported archive format %q", name)
}
