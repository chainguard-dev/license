/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package detect

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

// readFixture returns the bytes of a license fixture under testdata.
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading testdata %q: %v", name, err)
	}
	return data
}

// unreadable wraps a filesystem and adds one license file that fails to open,
// which is how a per-file collection failure is exercised without a filesystem
// that has to be broken on disk.
type unreadable struct {
	fstest.MapFS
	name string
}

var _ fs.FS = (*unreadable)(nil)

func (u unreadable) Open(name string) (fs.File, error) {
	if name == u.name {
		return nil, errors.New("permission denied")
	}
	return u.MapFS.Open(name)
}

func (u unreadable) Stat(name string) (fs.FileInfo, error) {
	if name == u.name {
		return nil, errors.New("permission denied")
	}
	return fs.Stat(u.MapFS, name)
}

// ReadDir reports the failing file as present, so discovery selects it and the
// failure happens where a real one would: at the read.
func (u unreadable) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := u.MapFS.ReadDir(name)
	if err != nil {
		return nil, err
	}
	if name != "." {
		return entries, nil
	}
	return append(entries, brokenEntry{name: u.name}), nil
}

// brokenEntry is the directory entry for the file that cannot be read.
type brokenEntry struct{ name string }

func (e brokenEntry) Name() string      { return e.name }
func (e brokenEntry) IsDir() bool       { return false }
func (e brokenEntry) Type() fs.FileMode { return 0 }
func (e brokenEntry) Info() (fs.FileInfo, error) {
	return nil, errors.New("permission denied")
}

// textTree builds an in-memory filesystem from a map of path to text, for the
// tests whose fixtures are source files rather than license bytes.
func textTree(files map[string]string) fstest.MapFS {
	fsys := make(fstest.MapFS, len(files))
	for name, content := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(content)}
	}
	return fsys
}

// endless is a filesystem holding one file far larger than any license, which
// is what an untrusted source tree naming a multi-gigabyte file LICENSE looks
// like. It counts the bytes handed out so a test can assert the read was
// bounded, and it does stop, so an unbounded reader fails the assertion
// instead of hanging.
type endless struct {
	name string
	size int64
	read *int64
}

var _ fs.FS = (*endless)(nil)

func (e endless) Open(name string) (fs.File, error) {
	if name != e.name {
		return nil, fs.ErrNotExist
	}
	return &endlessFile{owner: e}, nil
}

type endlessFile struct {
	owner  endless
	served int64
}

func (f *endlessFile) Stat() (fs.FileInfo, error) { return nil, errors.New("no stat") }
func (f *endlessFile) Close() error               { return nil }

func (f *endlessFile) Read(p []byte) (int, error) {
	if f.served >= f.owner.size {
		return 0, io.EOF
	}
	n := min(int64(len(p)), f.owner.size-f.served)
	for i := range p[:n] {
		p[i] = 'a'
	}
	f.served += n
	*f.owner.read += n
	return int(n), nil
}

// unreadableDir wraps a filesystem and makes one directory fail to list, which
// is what a permission-denied subtree looks like to a walk.
type unreadableDir struct {
	fstest.MapFS
	dir string
}

var _ fs.ReadDirFS = (*unreadableDir)(nil)

func (u unreadableDir) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == u.dir {
		return nil, errors.New("permission denied")
	}
	return u.MapFS.ReadDir(name)
}
