/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package upstream

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// staticToken mints a fixed credential.
func staticToken(value string) TokenFunc {
	return func(context.Context) (string, error) { return value, nil }
}

// failingToken cannot mint one.
func failingToken() TokenFunc {
	return func(context.Context) (string, error) { return "", errors.New("mint failed") }
}

// authParam is the GIT_CONFIG_PARAMETERS entry expected for a minted token.
func authParam(host, token string) string {
	return "'http.https://" + host + "/.extraHeader'='Authorization: Basic " +
		base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token)) + "'"
}

func TestAuthEnv(t *testing.T) {
	t.Setenv("GIT_CONFIG_PARAMETERS", "")

	for _, tt := range []struct {
		name  string
		url   string
		token TokenFunc
		want  []string
	}{
		{
			// The header travels in GIT_CONFIG_PARAMETERS, never as a -c
			// argument, so the credential is absent from the process command
			// line, which is world-readable through /proc.
			name:  "an authorized host gets a scoped header",
			url:   "https://github.com/istio/istio",
			token: staticToken("hunter2"),
			want:  []string{"GIT_CONFIG_PARAMETERS=" + authParam("github.com", "hunter2")},
		},
		{
			// The token must never be offered to a host it does not belong to,
			// and a URL chosen by something untrusted must not be able to
			// change that.
			name:  "another host gets no credential",
			url:   "https://gitlab.freedesktop.org/xorg/lib/libx11",
			token: staticToken("hunter2"),
		},
		{
			name: "no token source clones anonymously",
			url:  "https://github.com/istio/istio",
		},
		{
			// Public upstreams clone fine anonymously, so a mint failure
			// degrades rather than failing the checkout.
			name:  "a mint failure degrades to anonymous",
			url:   "https://github.com/istio/istio",
			token: failingToken(),
		},
		{
			name:  "an empty token is not a credential",
			url:   "https://github.com/istio/istio",
			token: staticToken(""),
		},
		{
			name:  "an unparseable URL gets no credential",
			url:   "://not a url",
			token: staticToken("hunter2"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := AuthEnv(t.Context(), tt.url, tt.token)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("AuthEnv (-want, +got):\n%s", diff)
			}
		})
	}
}

// TestAuthEnvPreservesExistingParameters verifies config already carried in
// GIT_CONFIG_PARAMETERS survives, with the auth entry appended: git resolves
// the last value for a single-valued key, so appending is what makes the header
// win without discarding the caller's own settings.
func TestAuthEnvPreservesExistingParameters(t *testing.T) {
	t.Setenv("GIT_CONFIG_PARAMETERS", "'protocol.allow'='never'")

	got := AuthEnv(t.Context(), "https://github.com/istio/istio", staticToken("hunter2"))
	want := []string{"GIT_CONFIG_PARAMETERS='protocol.allow'='never' " + authParam("github.com", "hunter2")}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("AuthEnv (-want, +got):\n%s", diff)
	}
}

// TestCheckoutRefValidatesBeforeCloning verifies there is no way to reach a
// clone without the host checks. The runner records whether it was called, so a
// refused URL is distinguishable from one that failed later.
func TestCheckoutRefValidatesBeforeCloning(t *testing.T) {
	stubDNS(t, map[string][]string{"github.com": {"140.82.112.3"}})

	for _, tt := range []struct {
		name    string
		req     Checkout
		wantRun bool
	}{
		{
			name: "a private address is refused before git runs",
			req:  Checkout{RepoURL: "https://169.254.169.254/repo", Ref: "v1"},
		},
		{
			name: "cleartext is refused before git runs",
			req:  Checkout{RepoURL: "http://github.com/x/y", Ref: "v1"},
		},
		{
			name: "a credentialed URL is refused before git runs",
			req:  Checkout{RepoURL: "https://user:pass@github.com/x/y", Ref: "v1"},
		},
		{
			name: "a missing ref is refused before git runs",
			req:  Checkout{RepoURL: "https://github.com/x/y"},
		},
		{
			name:    "a valid request reaches git",
			req:     Checkout{RepoURL: "https://github.com/x/y", Ref: "v1"},
			wantRun: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ran := false
			req := tt.req
			req.Run = func(context.Context, string, func() error) error {
				ran = true
				return errors.New("clone not attempted in a test")
			}
			if _, err := CheckoutRef(t.Context(), req); err == nil {
				t.Fatal("CheckoutRef: got nil error, want one")
			}
			if ran != tt.wantRun {
				t.Errorf("git invoked = %v, want = %v", ran, tt.wantRun)
			}
		})
	}
}

// TestCloneArgsKeepCredentialsOutOfArgv is the argv half of the credential
// invariant: whatever else the command carries, the token is not in it. It also
// pins the options that keep a clone from reaching anything but the named
// repository.
func TestCloneArgsKeepCredentialsOutOfArgv(t *testing.T) {
	req := Checkout{
		RepoURL: "https://github.com/x/y",
		Ref:     "v1.2.3",
		Token:   staticToken("hunter2"),
	}

	joined := strings.Join(cloneArgs(req, "/tmp/checkout"), " ")
	if strings.Contains(joined, "hunter2") {
		t.Errorf("the credential is in the command line: %s", joined)
	}
	for _, want := range []string{
		"--depth 1",
		"--single-branch",
		"--branch v1.2.3",
		"--no-recurse-submodules",
		// git follows redirects itself, after the URL was validated and the
		// subprocess started, so a redirect would reach a target nothing
		// checked.
		"-c http.followRedirects=false",
		// A proxy resolves the target inside CONNECT, reaching an address
		// ValidateURL never saw.
		"-c http.proxy=",
		// The URL separated from the options, so a repository name starting
		// with "-" cannot be read as a flag.
		"-- https://github.com/x/y",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("command %q is missing %q", joined, want)
		}
	}
}

// TestCloneEnvCarriesTheCredential is the other half: the credential does
// travel, in the environment, where git is asked to read it from, and it is
// scoped to the one host.
func TestCloneEnvCarriesTheCredential(t *testing.T) {
	t.Setenv("GIT_CONFIG_PARAMETERS", "")

	env := cloneEnv(t.Context(), Checkout{
		RepoURL: "https://github.com/x/y",
		Ref:     "v1.2.3",
		Token:   staticToken("hunter2"),
	})

	var scoped, noPrompt bool
	for _, entry := range env {
		if strings.HasPrefix(entry, "GIT_CONFIG_PARAMETERS=") && strings.Contains(entry, "github.com") {
			scoped = true
		}
		if entry == "GIT_TERMINAL_PROMPT=0" {
			noPrompt = true
		}
	}
	if !scoped {
		t.Error("the auth header did not reach the environment")
	}
	if !noPrompt {
		t.Error("the clone would be free to wait on a terminal prompt")
	}
}

// TestRunnerNeverSeesTheCredential pins the reason the hook takes a function
// rather than the command: a hook that could read the environment could log it,
// and that invariant should not rest on every caller's hook being careful.
func TestRunnerNeverSeesTheCredential(t *testing.T) {
	stubDNS(t, map[string][]string{"github.com": {"140.82.112.3"}})

	var observed string
	_, err := CheckoutRef(t.Context(), Checkout{
		RepoURL: "https://github.com/x/y",
		Ref:     "v1.2.3",
		Token:   staticToken("hunter2"),
		Run: func(_ context.Context, op string, _ func() error) error {
			observed = op
			return errors.New("clone not attempted in a test")
		},
	})
	if err == nil {
		t.Fatal("CheckoutRef: got nil error, want the stubbed failure")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("the credential is in the error: %v", err)
	}
	if observed != "clone" {
		t.Errorf("the hook was told the operation is %q, want %q", observed, "clone")
	}
}

// TestCloneErrorReportsAMissingRef maps git's own messages onto ErrNotFound, so
// a caller can tell a tag that never existed from a network failure worth
// retrying.
func TestCloneErrorReportsAMissingRef(t *testing.T) {
	for _, tt := range []struct {
		name     string
		stderr   string
		wantGone bool
	}{
		{
			name:     "a tag that does not exist",
			stderr:   "fatal: Remote branch v9.9.9 not found in upstream origin\n",
			wantGone: true,
		},
		{
			name:     "a repository that does not exist",
			stderr:   "remote: Repository not found.\nfatal: repository 'https://github.com/x/y/' not found\n",
			wantGone: true,
		},
		{
			// Worth retrying, so it must not be reported as permanent.
			name:   "a network failure",
			stderr: "fatal: unable to access 'https://github.com/x/y/': Could not resolve host: github.com\n",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := cloneError(errors.New("exit status 128"), tt.stderr)
			if got := errors.Is(err, ErrNotFound); got != tt.wantGone {
				t.Errorf("ErrNotFound: got = %v, want = %v (%v)", got, tt.wantGone, err)
			}
		})
	}
}

// TestSanitizeStderrNeutralizesWhatARemoteSays covers the bytes a remote can
// put in git's stderr, all of which reach an error string this package builds.
//
// The error is read by people and by machines. A newline lets a remote forge a
// second log entry, a cursor escape lets it rewrite what an operator already
// saw, and an unbounded message lets it fill the log instead of explaining the
// failure.
func TestSanitizeStderrNeutralizesWhatARemoteSays(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stderr string
		want   string
	}{{
		name:   "colour codes",
		stderr: "remote: \x1b[31mfatal\x1b[0m: access denied",
		want:   "remote: fatal : access denied",
	}, {
		name:   "cursor movement",
		stderr: "cloning\x1b[2K\x1b[1Gnothing to see",
		want:   "cloning nothing to see",
	}, {
		name:   "forged log line",
		stderr: "fatal: no\nlevel=INFO msg=\"all clear\"",
		want:   "fatal: no level=INFO msg=\"all clear\"",
	}, {
		name:   "operating system command",
		stderr: "fatal: \x1b]0;retitled\x07done",
		want:   "fatal: done",
	}, {
		name:   "carriage returns and tabs",
		stderr: "fatal:\tcould not read\r\nfrom remote",
		want:   "fatal: could not read from remote",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeStderr(tc.stderr); got != tc.want {
				t.Errorf("sanitizeStderr: got = %q, want = %q", got, tc.want)
			}
		})
	}
}

// TestSanitizeStderrBoundsTheMessage keeps a remote from spending our log
// budget instead of telling us what failed.
func TestSanitizeStderrBoundsTheMessage(t *testing.T) {
	got := sanitizeStderr(strings.Repeat("a", maxStderrChars*2))
	if len(got) <= maxStderrChars {
		t.Fatalf("len: got = %d, want the bound plus a truncation marker", len(got))
	}
	if !strings.HasSuffix(got, "[truncated]") {
		t.Errorf("got = %q..., want it marked as truncated", got[:64])
	}
	if trimmed := strings.TrimSuffix(got, " [truncated]"); len(trimmed) != maxStderrChars {
		t.Errorf("kept: got = %d characters, want = %d", len(trimmed), maxStderrChars)
	}
}

// TestCloneErrorClassifiesThroughControlBytes pins why sanitizing replaces
// control bytes rather than dropping them: deleting the escape below would
// leave "notfound", and a permanent failure would read as one worth retrying.
func TestCloneErrorClassifiesThroughControlBytes(t *testing.T) {
	err := cloneError(errors.New("exit status 128"), "remote: Repository not\x1bfound")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("ErrNotFound: got = %v, want the failure classified as permanent", err)
	}
	if strings.ContainsRune(err.Error(), '\x1b') {
		t.Errorf("error carries a raw escape byte: %q", err.Error())
	}
}

// TestCloneEnvDropsProxyVariables covers the proxy path into a clone. git
// resolves nothing itself when a proxy is set: the proxy resolves the target
// inside CONNECT, so every address ValidateURL checked is replaced by one it
// never saw.
func TestCloneEnvDropsProxyVariables(t *testing.T) {
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "NO_PROXY"} {
		t.Setenv(name, "http://proxy.invalid:3128")
	}
	env := cloneEnv(t.Context(), Checkout{RepoURL: "https://github.com/x/y", Ref: "v1"})
	for _, kv := range env {
		key, _, _ := strings.Cut(kv, "=")
		if _, proxy := proxyVars[key]; proxy {
			t.Errorf("the clone environment carries %s", key)
		}
	}
	// The rest of the environment still travels, including the prompt guard.
	if !slices.Contains(env, "GIT_TERMINAL_PROMPT=0") {
		t.Error("GIT_TERMINAL_PROMPT=0 was dropped along with the proxy variables")
	}
}
