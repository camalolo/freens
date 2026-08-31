// revoke.go — `freens revoke <name>`: §9.5's tombstone as an easy button.
//
// A revocation is an ordinary record update that kills the name instead of
// re-pointing it: sequence = current+1, EMPTY RRset, revoke = true (field
// 12), signed by the owner key. The §6.4 winner rule installs it over the
// live record in every store; the resolver then NXDOMAINs the name at any
// hop that is revoked (§8.5 lines 708-713). Un-revoking = publishing any
// newer sequence (`freens name <name>` again).
//
// Like `name`, every default comes from live state: owner key from the
// keychain, sequence fetched from the network, publish via the running
// daemon (or -peers standalone).
package cli

import (
	"context"
	"encoding/base32"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

func cmdRevoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	peersCSV := fs.String("peers", "", "comma-separated bootstrap peers as ip:port#<64-hex-pubkey> (standalone mode; default: the running daemon)")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	// Leading positional (the README form), like register/name.
	var lead string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		lead, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	pos := fs.Args()
	if lead != "" {
		pos = append([]string{lead}, pos...)
	}
	if len(pos) != 1 {
		return usageErr("revoke takes one name: <label>.<alias> or <alias> (e.g. www.alice, or alice for the whole namespace)")
	}
	displayName := pos[0]
	labels, alias, err := naming.DecomposeName(displayName)
	if err != nil {
		return usageErr("invalid name %q: %v", displayName, err)
	}

	// Owner key from the keychain (register/name put it there).
	keyPath := ownerKeyPath(alias)
	if _, err := os.Stat(keyPath); err != nil {
		avail := keychainAliases()
		if len(avail) == 0 {
			return usageErr("no owner key for alias %q and the keychain is empty — only the owner can revoke", alias)
		}
		return usageErr("no owner key for alias %q; keychain has: %s", alias, strings.Join(avail, ", "))
	}
	ownerKP, err := seedKeypair("@"+keyPath, "-owner")
	if err != nil {
		return err
	}
	tldID, err := crypto.TldID(ownerKP.Public())
	if err != nil {
		return err
	}
	pin := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(tldID), "="))

	// Current state: the name's live sequence (1 for a name the network
	// has never seen — revoking an unregistered name is a no-op, refuse).
	// Sequence discovery fetches the envelope by key (tombstones included —
	// revoking an already-revoked name via /resolve would reset to 1 and
	// lose the winner race; same fix as the web UI's engine).
	tr, err := pickTransport(*peersCSV)
	if err != nil {
		return err
	}
	wireName, err := naming.EncodeWireName(labels, alias, tldID)
	if err != nil {
		return err
	}
	nameKey, err := dht.KeyForWireName(wireName)
	if err != nil {
		return err
	}
	// Network state: the name's terminal envelope (tombstones included —
	// revoking an already-revoked name via /resolve would reset to 1 and
	// lose the winner race; same fix as the web UI's engine).
	cur, err := discoverEnvelope(tr, nameKey)
	if err != nil {
		return err
	}
	var seq uint64 = 1
	if cur != nil && cur.Record != nil {
		seq = cur.Record.Sequence + 1
	}

	if !*yes && sysIsTerminal() {
		fmt.Printf("revoke %s — the name will STOP resolving everywhere (un-revoke = publish a newer record). Proceed? [y/N] ", displayName)
		var answer string
		if _, err := fmt.Scanln(&answer); err != nil || (answer != "y" && answer != "Y" && answer != "yes") {
			return usageErr("revocation aborted")
		}
	}

	if err := publishRevokedAt(tr, wireName, ownerKP, seq); err != nil {
		return err
	}

	fmt.Printf("REVOKED. %s no longer resolves (sequence %d; un-revoke with `%s name %s`)\n",
		displayName, seq, ProgName, displayName)
	fmt.Printf("tld_id_b32=%s\n", pin)
	fmt.Printf("k_name=%s\n", hex.EncodeToString(naming.DHTKeyName(wireName)))
	return nil
}

// discoverEnvelope fetches a name's terminal envelope via whichever
// transport was picked — the daemon's store-first GET, or an iterative
// walk from a one-shot node. Tombstones included (sequence discovery must
// see them); nil means nothing is reachable at this key.
func discoverEnvelope(tr *transport, key []byte) (*wire.SignedEnvelope, error) {
	if tr.daemon() {
		ctx, cancel := adminCtx()
		defer cancel()
		env, err := tr.client.Get(ctx, key)
		if err != nil {
			return nil, err
		}
		return env, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), cliTimeout)
	defer cancel()
	node, err := startCLINode(ctx, "", "", tr.peers)
	if err != nil {
		return nil, err
	}
	defer node.Close()
	env, err := node.IterativeGet(ctx, key)
	if err != nil {
		return nil, nil // a walk failure is "nothing reachable", same as the daemon's 404
	}
	return env, nil
}

// publishRevokedAt signs the §9.5 tombstone (empty RRset, revoke = true)
// at the given sequence and publishes it via whichever transport was
// picked. Shared by `revoke` and `forget`.
func publishRevokedAt(tr *transport, wireName []byte, ownerKP *crypto.Keypair, seq uint64) error {
	now := uint64(time.Now().Unix())
	rec, err := wire.NewRecord(wireName, ownerKP.Public(), seq, now, now+uint64(constants.RecordDefaultTTL))
	if err != nil {
		return err
	}
	rev := true
	rec.Revoke = &rev
	rec.RRset = nil // §9.5: "revoke = true and empty rrset"
	env, err := wire.SignRecord(rec, ownerKP)
	if err != nil {
		return err
	}

	if tr.daemon() {
		ctx, cancel := publishCtx()
		defer cancel()
		if _, err := tr.client.Publish(ctx, env); err != nil {
			return fmt.Errorf("publish (daemon): %w", err)
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), cliTimeout)
	defer cancel()
	node, err := startCLINode(ctx, "", "", tr.peers)
	if err != nil {
		return err
	}
	defer node.Close()
	if err := node.Publish(ctx, env); err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	return nil
}
