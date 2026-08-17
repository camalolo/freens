// passphrase_policy_test.go — locks the keyfile passphrase policy (audit
// F1): a non-terminal may only produce a plaintext keyfile behind the
// explicit FREENS_ALLOW_PLAINTEXT_KEY=1 opt-in, and a failed confirmation
// aborts instead of silently writing plaintext. The interactive half
// (x/term prompts) is exercised manually; everything decidable without a
// TTY is decided here.
package cli

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/term"
)

// TestMain opts the (non-interactive) test binary into plaintext keyfiles:
// the register end-to-end tests mint fresh owner keys with no terminal
// attached — the pre-policy behavior they were written against. This is
// test-harness only; production binaries are unaffected.
func TestMain(m *testing.M) {
	os.Setenv(EnvAllowPlaintextKey, "1")
	os.Exit(m.Run())
}

// TestPlaintextKeyPolicy: a terminal passes (the caller prompts), any
// other context needs exactly FREENS_ALLOW_PLAINTEXT_KEY=1, and the
// refusal names both safe options.
func TestPlaintextKeyPolicy(t *testing.T) {
	for _, c := range []struct {
		isTTY   bool
		env     string
		wantErr bool
	}{
		{true, "", false},   // terminal: prompt instead
		{true, "0", false},  // terminal wins even with a junk env value
		{false, "1", false}, // explicit opt-in
		{false, "", true},   // silent default: refuse
		{false, "0", true},  // exactly "1", not any truthy-looking value
		{false, "yes", true},
		{false, "true", true},
	} {
		err := plaintextKeyPolicy(c.isTTY, c.env)
		if (err != nil) != c.wantErr {
			t.Fatalf("plaintextKeyPolicy(isTTY=%v, env=%q) = %v, wantErr=%v", c.isTTY, c.env, err, c.wantErr)
		}
		if err != nil {
			for _, want := range []string{EnvAllowPlaintextKey, "terminal"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q must name %q (the two safe options)", err, want)
				}
			}
		}
	}
}

// TestConfirmNewPassphrase: Enter-twice stays the plaintext default, equal
// entries become the passphrase, differing entries ABORT (the old flow
// printed a warning and proceeded with a plaintext keyfile).
func TestConfirmNewPassphrase(t *testing.T) {
	if got, err := confirmNewPassphrase("s3cret", "s3cret"); err != nil || got != "s3cret" {
		t.Errorf("matching entries = (%q, %v), want (s3cret, nil)", got, err)
	}
	if got, err := confirmNewPassphrase("", "whatever"); err != nil || got != "" {
		t.Errorf("empty first entry = (%q, %v), want the plaintext default", got, err)
	}
	got, err := confirmNewPassphrase("s3cret", "typo")
	if err == nil {
		t.Fatalf("differing entries = (%q, nil), want an abort error", got)
	}
	if got != "" {
		t.Errorf("differing entries returned passphrase %q; nothing may be written", got)
	}
	for _, want := range []string{"differ", "re-run"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("mismatch error %q must tell the user to %q", err, want)
		}
	}
}

// TestPromptNewPassphraseEnvPassphraseWins: FREENS_PASSPHRASE short-
// circuits before any TTY check, so it works headless.
func TestPromptNewPassphraseEnvPassphraseWins(t *testing.T) {
	t.Setenv(EnvPassphrase, "env-pass")
	got, err := promptNewPassphrase()
	if err != nil || got != "env-pass" {
		t.Fatalf("promptNewPassphrase = (%q, %v), want (env-pass, nil)", got, err)
	}
}

// TestPromptNewPassphraseNonTTYFollowsPolicy: with no terminal and no
// FREENS_PASSPHRASE, promptNewPassphrase applies plaintextKeyPolicy —
// "" plaintext only under the explicit opt-in, otherwise the guidance
// error (never a silent "").
func TestPromptNewPassphraseNonTTYFollowsPolicy(t *testing.T) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		t.Skip("stdin is a terminal — the interactive prompt path applies")
	}
	// Save/restore both knobs (TestMain keeps EnvAllowPlaintextKey=1 for
	// the rest of the suite).
	oldAllow, hadAllow := os.LookupEnv(EnvAllowPlaintextKey)
	oldPass, hadPass := os.LookupEnv(EnvPassphrase)
	defer func() {
		if hadAllow {
			os.Setenv(EnvAllowPlaintextKey, oldAllow)
		} else {
			os.Unsetenv(EnvAllowPlaintextKey)
		}
		if hadPass {
			os.Setenv(EnvPassphrase, oldPass)
		} else {
			os.Unsetenv(EnvPassphrase)
		}
	}()
	os.Unsetenv(EnvPassphrase)

	for _, c := range []struct {
		name    string
		allow   string
		wantErr bool
	}{
		{"no opt-in errors", "", true},
		{"opt-in allows plaintext", "1", false},
		{"junk opt-in value errors", "yes", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			os.Setenv(EnvAllowPlaintextKey, c.allow)
			got, err := promptNewPassphrase()
			if (err != nil) != c.wantErr {
				t.Fatalf("promptNewPassphrase = (%q, %v), wantErr=%v", got, err, c.wantErr)
			}
			if c.wantErr {
				if got != "" {
					t.Errorf("error path returned passphrase %q; must never proceed", got)
				}
				if !strings.Contains(err.Error(), EnvAllowPlaintextKey) {
					t.Errorf("error %q must name %q", err, EnvAllowPlaintextKey)
				}
			} else if got != "" || err != nil {
				t.Errorf("opt-in = (%q, %v), want the plaintext \"\"", got, err)
			}
		})
	}
}
