// forget.go — `freens forget <name>`: the cleanup verb. `revoke` alone
// stops a name from resolving but leaves the keychain files behind, so the
// name keeps showing up in status/doctor and the key material keeps
// existing on disk. forget is the whole dance in one safe order: the
// tombstone is signed and published FIRST (the key must be alive to sign
// it), and only then are the key files pruned:
//
//	<alias>.key       the owner key (signs every future record)
//	<alias>.recN.key  the §8.4 recovery keys
//	<alias>.claim.json  the parked §7.3 claim (register retries)
//
// A revoked name stays revoked: the renewal path refuses revoked records
// ("deliberate death"), so nothing resurrects while the files delete.
// Un-forgetting is the documented un-revoke path — republish with the SAME
// key (`freens name <name>`), which only works if you still hold it; hence
// the key deletion is the one-way part and needs -yes in scripts.
//
// Scope note: forgetting an apex tombstones the APEX only. Sub-names
// (www.<alias> etc.) are separate records at separate keys; they keep
// resolving until their own leases lapse (or revoke them explicitly).
package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/home"
	"github.com/camalolo/freens/internal/keychain"
	"github.com/camalolo/freens/internal/naming"
)

func cmdForget(args []string) error {
	fs := flag.NewFlagSet("forget", flag.ContinueOnError)
	keepKeys := fs.Bool("keep-keys", false, "revoke the name but KEEP the keychain files (the `revoke` behavior)")
	peersCSV := fs.String("peers", "", "comma-separated bootstrap peers as ip:port#<64-hex-pubkey> (standalone mode; default: the running daemon)")
	yes := fs.Bool("yes", false, "do not ask for confirmation (REQUIRED in non-interactive sessions: forget deletes key material)")
	// Leading positional (the README form), like register/name/revoke.
	var lead string
	rest := args
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		lead, rest = rest[0], rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	pos := fs.Args()
	if lead != "" {
		pos = append([]string{lead}, pos...)
	}
	if len(pos) != 1 {
		return usageErr("forget takes one name: <label>.<alias> or <alias> (e.g. www.alice, or alice for the whole namespace apex)")
	}
	displayName := pos[0]
	labels, alias, err := naming.DecomposeName(displayName)
	if err != nil {
		return usageErr("invalid name %q: %v", displayName, err)
	}

	// The owner key must exist: it signs the tombstone, and its location is
	// what gets pruned.
	keyPath := ownerKeyPath(alias)
	if _, err := os.Stat(keyPath); err != nil {
		avail := keychainAliases()
		if len(avail) == 0 {
			return usageErr("no owner key for alias %q and the keychain is empty — nothing to forget", alias)
		}
		return usageErr("no owner key for alias %q; keychain has: %s", alias, strings.Join(avail, ", "))
	}
	kp, err := seedKeypair("@"+keyPath, "-owner")
	if err != nil {
		return err
	}
	tldID, err := crypto.TldID(kp.Public())
	if err != nil {
		return err
	}
	wireName, err := naming.EncodeWireName(labels, alias, tldID)
	if err != nil {
		return usageErr("invalid name %q: %v", displayName, err)
	}
	nameKey, err := dht.KeyForWireName(wireName)
	if err != nil {
		return err
	}

	// Destructive gate: unlike revoke (which only touches the network),
	// forget deletes key material. A non-interactive run MUST pass -yes.
	if !*yes && !sysIsTerminal() {
		return usageErr("non-interactive session: forget deletes key material — re-run with -yes (or -keep-keys)")
	}

	tr, err := pickTransport(*peersCSV)
	if err != nil {
		return err
	}
	cur, err := discoverEnvelope(tr, nameKey)
	if err != nil {
		return err
	}

	action := "nothing to revoke"
	switch {
	case cur == nil:
		fmt.Printf("%s: nothing published — pruning the keychain files\n", displayName)
	case cur.IsRevoked():
		fmt.Printf("%s: already revoked — pruning the keychain files\n", displayName)
	default:
		if !*yes && sysIsTerminal() {
			fmt.Printf("forget %s — revokes the name EVERYWHERE and DELETES the owner + recovery keys from this machine (un-revoke later needs the key you are deleting).\nProceed? [y/N] ", displayName)
			var answer string
			if _, err := fmt.Scanln(&answer); err != nil || (answer != "y" && answer != "Y" && answer != "yes") {
				return usageErr("forget aborted")
			}
		}
		seq := cur.Record.Sequence + 1
		if err := publishRevokedAt(tr, wireName, kp, seq); err != nil {
			// Keys are deliberately NOT pruned when the tombstone fails:
			// the name still resolves; losing the keys now would strand it.
			return fmt.Errorf("revoke failed — key files KEPT: %w", err)
		}
		action = fmt.Sprintf("revoked at sequence %d", seq)
	}

	pruned := 0
	if !*keepKeys {
		n, err := pruneKeychainFiles(alias)
		if err != nil {
			return fmt.Errorf("%s: %s, but pruning the key files failed: %w", displayName, action, err)
		}
		pruned = n
	}

	fmt.Printf("FORGOTTEN. %s: %s; key files removed: %d\n", displayName, action, pruned)
	if *keepKeys {
		fmt.Println("keys kept (-keep-keys); the name stays revoked — un-revoke by republishing (`freens name <name>`)")
	} else {
		fmt.Printf("to ever use %s again: restore the key (freens backup -restore) and republish (`freens name %s` or register)\n", displayName, displayName)
	}
	fmt.Println("note: sub-names (www.<alias> …) are separate records — they lapse on their own leases unless revoked too.")
	return nil
}

// pruneKeychainFiles removes alias' owner key, recovery keys, and parked
// claim state from the keychain, returning how many files went away.
func pruneKeychainFiles(alias string) (int, error) {
	keysDir := home.KeysDir()
	files := []string{
		keychain.OwnerKeyPath(keysDir, alias),
		keychain.ClaimStatePath(keysDir, alias),
	}
	recs, err := filepath.Glob(filepath.Join(keysDir, alias+".rec*.key"))
	if err != nil {
		return 0, err
	}
	files = append(files, recs...)
	removed := 0
	for _, f := range files {
		if err := os.Remove(f); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return removed, err
		}
		removed++
	}
	return removed, nil
}
