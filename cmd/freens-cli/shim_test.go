// shim_test.go — smoke tests for the freens-cli compat shim: its own
// -version intercept and the pass-through to the shared cli dispatch.
package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

// captureStdout swaps os.Stdout for a pipe while fn runs.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	saved := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = saved
	var buf strings.Builder
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestShimVersionIntercept(t *testing.T) {
	for _, verb := range []string{"version", "-version", "--version"} {
		out := captureStdout(t, func() {
			if code := shimMain([]string{"freens-cli", verb}); code != 0 {
				t.Errorf("%s exit = %d, want 0", verb, code)
			}
		})
		if !strings.HasPrefix(out, "freens-cli ") {
			t.Errorf("%s output = %q, want the shim's own stamp", verb, out)
		}
	}
}

func TestShimDispatch(t *testing.T) {
	// Unknown verbs pass through to cli.Main's usage error (exit 1).
	if code := shimMain([]string{"freens-cli", "definitely-not-a-verb"}); code != 1 {
		t.Errorf("unknown verb exit = %d, want 1", code)
	}
	// No verb: usage, exit 1 (the classic behavior).
	if code := shimMain([]string{"freens-cli"}); code != 1 {
		t.Errorf("no-verb exit = %d, want 1", code)
	}
	// A real subcommand runs end to end: gen-key with zero flags prints a key.
	var out string
	var code int
	out = captureStdout(t, func() { code = shimMain([]string{"freens-cli", "gen-key"}) })
	if code != 0 {
		t.Errorf("gen-key exit = %d, want 0", code)
	}
	if !strings.Contains(out, "seed=") || !strings.Contains(out, "tld_id_b32=") {
		t.Errorf("gen-key output missing key lines:\n%s", out)
	}
	// help exits 0 through the shared dispatch.
	if code := shimMain([]string{"freens-cli", "help"}); code != 0 {
		t.Errorf("help exit = %d, want 0", code)
	}
}
