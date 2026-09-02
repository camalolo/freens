package cli

// keys.go — `freens keys`: the local keychain inventory on the terminal,
// the same table the web UI's Keys page renders (keychain.Inventory).
// Read-only; shows what would be renewed/revoked/backed up, and flags
// passphrase-encrypted keys (the daemon cannot auto-renew those without
// FREENS_PASSPHRASE).

import (
	"flag"
	"fmt"

	"github.com/camalolo/freens/internal/home"
	"github.com/camalolo/freens/internal/keychain"
)

func cmdKeys(args []string) error {
	fs := flag.NewFlagSet("keys", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageErr("keys takes no arguments (it lists the keychain of this machine's FREENS_HOME)")
	}
	inv := keychain.Inventory(home.KeysDir())
	if len(inv) == 0 {
		fmt.Printf("no keys in %s yet — `freens register <name>` creates one\n", home.KeysDir())
		return nil
	}
	fmt.Printf("keychain: %s (%d keyfiles)\n", home.KeysDir(), len(inv))
	for _, k := range inv {
		enc := ""
		if k.Encrypted {
			enc = " · passphrase-encrypted"
		}
		fmt.Printf("  %-24s %-8s %6d B  %s%s\n",
			k.Name, k.Kind, k.Size, k.ModTime.Format("2006-01-02 15:04"), enc)
	}
	return nil
}
