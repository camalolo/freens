// passphrase.go — the interactive passphrase policy, one place:
//
//	generating keys:  FREENS_PASSPHRASE env wins; else a TTY prompt asks
//	                  twice (empty twice = plaintext, the compatible
//	                  default); no TTY = plaintext only with an explicit
//	                  FREENS_ALLOW_PLAINTEXT_KEY=1 opt-in — otherwise a
//	                  usage error (never a silent plaintext keyfile)
//	unlocking keys:    FREENS_PASSPHRASE env wins; else a TTY prompt asks
//	                  once; no TTY = a clear error (never a silent
//	                  fallback to brute force or plaintext)
package cli

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// EnvPassphrase lets scripts/services supply the keyfile passphrase
// non-interactively (documented escape hatch: it lives in the unit file /
// CI secret, so it trades file-at-rest protection for process-env exposure
// — the daemon's auto-renew uses it).
const EnvPassphrase = "FREENS_PASSPHRASE"

// EnvAllowPlaintextKey is the explicit non-interactive opt-in for plaintext
// keyfiles: exactly "1" lets key generation proceed with no terminal
// attached (scripts, CI). Non-TTY generation used to silently produce
// plaintext keyfiles — now it refuses without this.
const EnvAllowPlaintextKey = "FREENS_ALLOW_PLAINTEXT_KEY"

// plaintextKeyPolicy decides whether THIS context may fall back to a
// plaintext keyfile instead of prompting (the pure, testable core of the
// policy): a terminal is fine (the caller prompts), any other context
// needs FREENS_ALLOW_PLAINTEXT_KEY=1 and otherwise gets the error naming
// both safe options.
func plaintextKeyPolicy(isTTY bool, envValue string) error {
	if isTTY || envValue == "1" {
		return nil
	}
	return usageErr("no terminal and no passphrase source — refusing to silently write a plaintext key file; run from a terminal to be prompted, or set %s=1 to explicitly opt into plaintext key files", EnvAllowPlaintextKey)
}

// promptNewPassphrase returns the passphrase for NEW keyfiles ("" = write
// plaintext) or a usage error telling the caller to retry. See the file
// comment for the exact precedence.
func promptNewPassphrase() (string, error) {
	if p, ok := os.LookupEnv(EnvPassphrase); ok {
		return p, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		// Non-interactive generation: plaintext only by explicit opt-in.
		return "", plaintextKeyPolicy(false, os.Getenv(EnvAllowPlaintextKey))
	}
	fmt.Print("Passphrase for the new key file (Enter twice = no passphrase): ")
	p1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		// A failed read must ABORT, never degrade to "": an empty result
		// here flows into the plaintext-keyfile path and silently writes
		// the owner key unencrypted (found in the 2026-09-04 audit —
		// directly against this file's stated policy).
		return "", fmt.Errorf("reading passphrase: %w (nothing was written; re-run to try again)", err)
	}
	fmt.Print("Repeat passphrase: ")
	p2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("reading passphrase (repeat): %w (nothing was written; re-run to try again)", err)
	}
	return confirmNewPassphrase(string(p1), string(p2))
}

// confirmNewPassphrase is the pure verdict over the two typed entries:
// Enter-twice stays plaintext (the compatible interactive default), but
// differing entries ABORT — the old flow printed a warning and proceeded
// to write a plaintext keyfile anyway.
func confirmNewPassphrase(p1, p2 string) (string, error) {
	if len(p1) == 0 {
		return "", nil
	}
	if p1 != p2 {
		return "", usageErr("the two passphrase entries differ — nothing was written; re-run to try again (press Enter twice for no passphrase)")
	}
	return p1, nil
}

// passphraseForUnlock returns the passphrase for an ENCRYPTED keyfile, or
// a usage error explaining the two non-interactive options.
func passphraseForUnlock() (string, error) {
	if p, ok := os.LookupEnv(EnvPassphrase); ok {
		return p, nil
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Print("Keyfile passphrase: ")
		p, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", usageErr("could not read the passphrase: %v", err)
		}
		return string(p), nil
	}
	return "", usageErr("the keyfile is passphrase-encrypted and this is not a terminal — set %s or run from a terminal", EnvPassphrase)
}
