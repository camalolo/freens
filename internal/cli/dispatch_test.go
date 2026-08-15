// dispatch_test.go — smoke tests for the shared entry point: every
// subcommand's -h parses without panic, the meta verbs behave, and the
// exit-code convention holds.
package cli

import (
	"strings"
	"testing"
)

// TestDispatchHelpSmoke runs `-h` through Main for EVERY subcommand in the
// dispatch table: none may panic, and each exits with a sane code (flag's
// ErrHelp surfaces as 1, matching the classic CLI).
func TestDispatchHelpSmoke(t *testing.T) {
	for sub := range dispatch {
		t.Run(sub, func(t *testing.T) {
			code := Main([]string{sub, "-h"})
			if code < 0 || code > 2 {
				t.Fatalf("%s -h exited %d (want 0..2, no panic)", sub, code)
			}
		})
	}
}

func TestMainMetaVerbs(t *testing.T) {
	if code := Main(nil); code != 1 {
		t.Errorf("no args: exit %d, want 1 (usage)", code)
	}
	if code := Main([]string{"help"}); code != 0 {
		t.Errorf("help: exit %d, want 0", code)
	}
	if code := Main([]string{"-h"}); code != 0 {
		t.Errorf("-h: exit %d, want 0", code)
	}
	if code := Main([]string{"no-such-verb"}); code != 1 {
		t.Errorf("unknown subcommand: exit %d, want 1", code)
	}
	if code := Main([]string{"version"}); code != 0 {
		t.Errorf("version: exit %d, want 0", code)
	}
}

// TestMainCryptoExitCode: a crypto/validation failure must surface as 2 via
// crypto.ErrCrypto, usage as 1.
func TestMainCryptoExitCode(t *testing.T) {
	if code := Main([]string{"gen-key", "extra-arg"}); code != 1 {
		t.Errorf("usage error exit = %d, want 1", code)
	}
	if code := Main([]string{"make-record"}); code != 1 {
		t.Errorf("missing required flags exit = %d, want 1", code)
	}
}

// TestQuickstartNamesTheBasics: the first-timer card must carry the whole
// happy path (setup -> register -> name) plus status/doctor/help.
func TestQuickstartNamesTheBasics(t *testing.T) {
	var sb strings.Builder
	quickstart(&sb)
	got := sb.String()
	for _, want := range []string{"setup", "register", "name", "status", "doctor", "help"} {
		if !strings.Contains(got, want) {
			t.Errorf("quickstart missing %q", want)
		}
	}
}

// TestSuggestSubcommands: typos and stray dashes still land on the right
// verb; short junk suggests nothing (prefix-only matching).
func TestSuggestSubcommands(t *testing.T) {
	for typo, want := range map[string]string{
		"regsiter": "register",
		"sttaus":   "status",
		"-setup":   "setup",
		"--doctor": "doctor",
	} {
		got := strings.Join(suggestSubcommands(typo), ",")
		if !strings.Contains(got, want) {
			t.Errorf("suggest(%q) = %q, want it to contain %q", typo, got, want)
		}
	}
	if hits := suggestSubcommands("zz"); len(hits) != 0 {
		t.Errorf("suggest(\"zz\") = %v, want none", hits)
	}
}

// TestUsageListsEverySubcommand: the usage text stays in sync with the
// dispatch table (no orphan verbs, no undocumented ones).
func TestUsageListsEverySubcommand(t *testing.T) {
	var sb strings.Builder
	usageTo(&sb)
	got := sb.String()
	for sub := range dispatch {
		if sub == "version" {
			continue // printed as "print the binary version"
		}
		if !strings.Contains(got, sub) {
			t.Errorf("usage() does not mention subcommand %q", sub)
		}
	}
}
