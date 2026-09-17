/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package upstream

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"unicode"

	"github.com/chainguard-dev/clog"
)

// ErrNotFound means the repository or the ref does not exist, which is a
// permanent answer rather than something to retry.
var ErrNotFound = errors.New("repository or ref not found")

// TokenFunc mints a credential for authenticating a checkout. Returning an
// error degrades to an anonymous clone rather than failing the checkout, since
// public upstreams clone fine without one.
//
// The module takes a function rather than an OAuth token source so that it
// depends on no particular credential library, and so that a token is minted
// at the moment of use rather than held.
type TokenFunc func(ctx context.Context) (string, error)

// Runner observes a git operation.
//
// It exists so that a caller in an instrumented environment keeps its
// instrumentation. A caller that emits a log line and a metric per git
// operation would otherwise lose both for every license checkout, because this
// package shells out itself. A runner is handed the operation's name and a
// function that performs it, and it must call that function.
//
// It is deliberately not handed the command. The environment carries the
// credential, so a hook that could read it could log it, and the invariant
// that a credential never reaches a log should not rest on every caller's hook
// being careful.
type Runner func(ctx context.Context, op string, run func() error) error

// Checkout describes a repository revision to acquire.
type Checkout struct {
	// RepoURL is the full https URL of the repository.
	RepoURL string
	// Ref is the tag or branch to check out. A tag is the usual case: the
	// license of a version is whatever that version shipped, so a floating
	// branch answers a different question.
	Ref string
	// Token authenticates the clone. It is optional, and is offered only to
	// the hosts AuthHosts allows.
	Token TokenFunc
	// AuthHosts are the hosts a credential may be offered to. Empty means
	// DefaultAuthHosts.
	AuthHosts []string
	// Run observes the git operation, defaulting to just performing it.
	Run Runner
}

// DefaultAuthHosts returns the hosts a credential may be offered to when a
// request names none of its own.
//
// An allowlist rather than a policy of sending the token wherever the URL
// points: the token is a GitHub token, and a URL chosen by something untrusted
// must not be able to make git present it to a host of the attacker's choosing.
// It is a function returning a fresh slice rather than a variable, so that the
// allowlist cannot be widened process-wide by anything that imports this
// package.
func DefaultAuthHosts() []string { return []string{"github.com"} }

// Tree is a checked-out repository.
type Tree struct {
	// FS is the checkout's contents. Path resolution is bounded to the
	// checkout, so a symlink inside it that points outside fails to resolve
	// rather than reading the host filesystem.
	FS fs.FS
	// Ref and RepoURL are what was checked out.
	Ref     string
	RepoURL string

	root  *os.Root
	close func()
}

// Close releases the checkout and removes it from disk. Every successful
// CheckoutRef must be closed.
func (t *Tree) Close() error {
	var err error
	if t.root != nil {
		err = t.root.Close()
	}
	if t.close != nil {
		t.close()
	}
	return err
}

// CheckoutRef shallow-clones a repository at a ref and returns a filesystem
// over it.
//
// The URL is validated immediately before the clone, so there is no way to
// reach this without the host checks in ValidateURL. The clone is depth-1 and
// single-branch: it fetches the tree at the revision whose license is in
// question and nothing else.
//
// The returned filesystem is rooted with os.Root, which bounds path resolution
// to the checkout. Repositories commonly symlink LICENSE to the real text, so
// links have to be followed; bounding resolution is what keeps a link pointing
// at /etc from being read as a license.
func CheckoutRef(ctx context.Context, req Checkout) (*Tree, error) {
	if err := ValidateURL(ctx, req.RepoURL); err != nil {
		return nil, err
	}
	if req.Ref == "" {
		return nil, errors.New("upstream: a ref is required")
	}

	dir, cleanup, err := clone(ctx, req)
	if err != nil {
		return nil, err
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("opening checkout root: %w", err)
	}
	return &Tree{
		FS:      root.FS(),
		Ref:     req.Ref,
		RepoURL: req.RepoURL,
		root:    root,
		close:   cleanup,
	}, nil
}

// clone shallow-clones the repository into a temporary directory and returns
// its path. The caller must invoke the returned cleanup, which removes the
// clone; on error no cleanup is needed.
func clone(ctx context.Context, req Checkout) (string, func(), error) {
	dir, err := os.MkdirTemp("", "license-checkout-*")
	if err != nil {
		return "", nil, fmt.Errorf("creating temp directory: %w", err)
	}
	cleanup := func() {
		if err := os.RemoveAll(dir); err != nil {
			clog.WarnContext(ctx, "Failed to remove temporary git checkout", "dir", dir, "error", err)
		}
	}

	// Cloning an upstream repository means running git against a URL and a ref
	// the caller chose, which is the point of the operation rather than a
	// weakness in it. What bounds it: the URL has passed ValidateURL, "--"
	// separates the options from it so a URL beginning with "-" cannot be read
	// as a flag, the ref is the value of --branch and so cannot be read as one
	// either, and there is no shell, so nothing here is word-split or expanded.
	args := cloneArgs(req, dir)
	cmd := exec.CommandContext(ctx, args[0], args[1:]...) //nolint:gosec // see above: validated URL, no shell, options terminated
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Env = cloneEnv(ctx, req)

	run := req.Run
	if run == nil {
		run = func(_ context.Context, _ string, perform func() error) error { return perform() }
	}
	if err := run(ctx, "clone", cmd.Run); err != nil {
		cleanup()
		return "", nil, cloneError(err, stderr.String())
	}
	return dir, cleanup, nil
}

// maxStderrChars bounds how much of git's stderr an error carries.
//
// A failed clone says what went wrong in a line or two. Past this the remote is
// filling our logs rather than telling us anything, and the message travels
// beyond this package, into a caller's logs and sometimes into a model's
// context, so its size is not only ours to spend.
const maxStderrChars = 2048

// ansiEscape matches the terminal control sequences git emits when it believes
// it is talking to a terminal, and that a remote can emit regardless.
//
// Only the two forms with a defined terminator are matched: a control sequence
// and an operating system command. A lone escape byte is deliberately left to
// the control-byte mapping below, because a catch-all for "escape and whatever
// follows" consumes a real character - it turns "not<esc>found" into
// "not ound", which is the one string this must not damage.
var ansiEscape = regexp.MustCompile("\x1b\\[[0-9;?]*[ -/]*[@-~]|\x1b\\][^\x07\x1b]*(?:\x07|\x1b\\\\)")

// sanitizeStderr renders what a remote said fit to put in an error string.
//
// A remote controls this text completely, and the error it lands in is read by
// people and by machines: a bare newline lets a remote forge a second log
// entry, and a cursor escape lets it rewrite what an operator sees above it.
// Control bytes become spaces rather than disappearing, because deleting them
// would glue two words together and change what the classification below
// reads: "not\x1bfound" must not become "notfound".
func sanitizeStderr(s string) string {
	s = ansiEscape.ReplaceAllString(s, " ")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if runes := []rune(s); len(runes) > maxStderrChars {
		s = string(runes[:maxStderrChars]) + " [truncated]"
	}
	return s
}

// cloneError classifies a failed clone from what git said on stderr.
//
// The distinction is worth making because it decides whether a caller retries:
// a tag that does not exist will not start existing, while a network failure
// is worth another attempt. git says which of the two happened only in prose,
// so this reads the prose in one place rather than at every call site.
//
// The prose is quoted rather than interpolated bare, so that a reader can tell
// where our description of the failure ends and the remote's begins.
func cloneError(err error, stderr string) error {
	detail := sanitizeStderr(stderr)
	for _, permanent := range []string{"not found", "does not exist", "Remote branch"} {
		if strings.Contains(detail, permanent) {
			return fmt.Errorf("%w: %q", ErrNotFound, detail)
		}
	}
	return fmt.Errorf("git clone failed: %q: %w", detail, err)
}

// cloneArgs builds the command line for a shallow checkout of one ref.
//
// It is separate so that what reaches the process can be asserted without
// running git, which matters for two properties: the credential is not in it,
// and the options that keep the clone from reaching anything but the named
// repository are.
func cloneArgs(req Checkout, dir string) []string {
	return []string{
		"git", "clone",
		// git's HTTP transport follows redirects itself, after ValidateURL has
		// run and the subprocess has started, so a redirect toward link-local
		// space reaches a target nothing checked. git cannot call back here to
		// validate a hop, so redirects are refused. A renamed repository has
		// to be cloned from its current URL.
		"-c", "http.followRedirects=false",
		// A proxy resolves the target inside CONNECT, so it reaches an address
		// ValidateURL never saw. cloneEnv drops the proxy environment
		// variables; this covers a proxy set in a gitconfig file.
		"-c", "http.proxy=",
		"--depth", "1",
		"--branch", req.Ref,
		"--single-branch",
		// A submodule is a different repository at a URL this package never
		// validated, so it is not fetched. A submodule's licensing belongs to
		// the component it is, determined in its own right.
		"--no-recurse-submodules",
		"--",
		req.RepoURL,
		dir,
	}
}

// cloneEnv builds the environment for a checkout: the inherited environment,
// the refusal to prompt, and any credential.
//
// A clone must never wait on a terminal. A repository that asks for
// credentials should fail immediately rather than hang a sweep on a prompt
// nobody is there to answer.
func cloneEnv(ctx context.Context, req Checkout) []string {
	env := make([]string, 0, len(os.Environ())+1)
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		if _, proxy := proxyVars[key]; proxy {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "GIT_TERMINAL_PROMPT=0")
	return append(env, AuthEnv(ctx, req.RepoURL, req.Token, req.AuthHosts...)...)
}

// proxyVars are the environment variables that would send the clone through a
// proxy.
//
// A proxy resolves the target inside CONNECT, so every address ValidateURL
// checked is replaced by one it never saw. The variables are dropped rather
// than trusted, and cloneArgs clears http.proxy so a system or user gitconfig
// cannot set one either.
var proxyVars = map[string]struct{}{
	"HTTP_PROXY": {}, "HTTPS_PROXY": {}, "ALL_PROXY": {}, "NO_PROXY": {},
	"http_proxy": {}, "https_proxy": {}, "all_proxy": {}, "no_proxy": {},
}

// AuthEnv returns the environment variables that authenticate a clone with a
// minted token.
//
// The credential travels as an Authorization header injected through git's
// GIT_CONFIG_PARAMETERS mechanism - the variable git itself uses to propagate
// -c config to child processes - so it appears in neither the process command
// line, which is world-readable through /proc, nor in any log. Any
// GIT_CONFIG_PARAMETERS already in the environment is preserved, and git
// resolves the last value for a single-valued key.
//
// The config key is scoped to the specific host, so git never offers the header
// to another one, and the host has to be allowed before a token is minted at
// all.
//
// Authentication is an enhancement here - it buys rate limit and private
// repositories, and public upstreams clone fine without it - so a mint failure
// degrades to an anonymous clone rather than failing the checkout.
//
// It is exported because the guarantee it makes is worth testing directly.
func AuthEnv(ctx context.Context, repoURL string, token TokenFunc, hosts ...string) []string {
	if token == nil {
		return nil
	}
	u, err := url.Parse(repoURL)
	if err != nil {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	if !authorizedHost(host, hosts) {
		return nil
	}
	value, err := token(ctx)
	if err != nil {
		clog.WarnContext(ctx, "Failed to mint a token for a license checkout, cloning anonymously",
			"host", host, "error", err)
		return nil
	}
	if value == "" {
		return nil
	}

	encoded := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + value))
	// Neither the key nor the base64 value can contain a single quote, so no
	// escaping is needed inside the quoted segments.
	param := "'http.https://" + host + "/.extraHeader'='Authorization: Basic " + encoded + "'"
	if existing := os.Getenv("GIT_CONFIG_PARAMETERS"); existing != "" {
		param = existing + " " + param
	}
	return []string{"GIT_CONFIG_PARAMETERS=" + param}
}

// authorizedHost reports whether a credential may be offered to a host.
//
// A quote in the host would land inside the single-quoted git config parameter
// AuthEnv builds, so it is refused here rather than escaped: no real host has
// one, and the check keeps the quoting of that string a local property.
func authorizedHost(host string, hosts []string) bool {
	if strings.ContainsAny(host, "'\\") {
		return false
	}
	if len(hosts) == 0 {
		hosts = DefaultAuthHosts()
	}
	for _, allowed := range hosts {
		if strings.EqualFold(host, allowed) {
			return true
		}
	}
	return false
}
