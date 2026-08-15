// passphrase.go — the interactive passphrase policy, one place:
//
//	generating keys:  FREENS_PASSPHRASE env wins; else a TTY prompt asks
//	                  twice (empty twice = plaintext, the compatible
//	                  default); no TTY = plaintext (scripts keep working)
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

// promptNewPassphrase returns the passphrase for NEW keyfiles ("" = write
// plaintext). See the file comment for the exact precedence.
func promptNewPassphrase() string {
	if p, ok := os.LookupEnv(EnvPassphrase); ok {
		return p
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "" // non-interactive generation: plaintext (compatible)
	}
	fmt.Print("Passphrase for the new key file (Enter twice = no passphrase): ")
	p1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return ""
	}
	fmt.Print("Repeat passphrase: ")
	p2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil || len(p1) == 0 {
		return ""
	}
	if string(p1) != string(p2) {
		fmt.Println("passphrases differ — writing WITHOUT a passphrase; re-run to retry")
		return ""
	}
	return string(p1)
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
