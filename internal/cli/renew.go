// renew.go — `freens renew [name…]`: the lease-extension button. Records
// expire by design (ownership = liveness, §4.4); renew re-signs at
// sequence+1 with a fresh 24 h window — owner-only, no PoW, no witnesses.
// No arguments: every keychain alias's apex.
package cli

import (
	"context"
	"encoding/base32"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/renewal"
	"github.com/camalolo/freens/internal/wire"
)

func cmdRenew(args []string) error {
	fs := flag.NewFlagSet("renew", flag.ContinueOnError)
	peersCSV := fs.String("peers", "", "comma-separated bootstrap peers as ip:port#<64-hex-pubkey> (standalone mode; default: the running daemon)")
	force := fs.Bool("force", false, "renew even when the record is still comfortably fresh")
	var lead []string
	rest := args
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		lead, rest = rest[:1], rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	names := append(lead, fs.Args()...)
	if len(names) == 0 {
		names = keychainAliases()
		if len(names) == 0 {
			return usageErr("no names given and the keychain is empty — register one first")
		}
	}

	tr, err := pickTransport(*peersCSV)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	failed := 0
	for _, display := range names {
		labels, alias, err := naming.DecomposeName(display)
		if err != nil {
			fmt.Printf("%s: invalid name: %v\n", display, err)
			failed++
			continue
		}
		if err := renewOne(tr, labels, alias, display, *force, now); err != nil {
			fmt.Printf("%s: %v\n", display, err)
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("renew: %d of %d name(s) failed", failed, len(names))
	}
	return nil
}

// renewOne extends one name's lease: load the owner key, fetch the current
// record, decide freshness, re-sign at seq+1, publish at every legitimate
// key (K_tld/K_name + K_claim when a claim rides along).
func renewOne(tr *transport, labels []string, alias, display string, force bool, now int64) error {
	keyPath := ownerKeyPath(alias)
	if _, err := os.Stat(keyPath); err != nil {
		return fmt.Errorf("no owner key in the keychain (only the owner can renew)")
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
		return err
	}
	key, err := dht.KeyForWireName(wireName)
	if err != nil {
		return err
	}

	// Fetch the CURRENT signed envelope (the network view of the lease).
	var prev *wire.SignedEnvelope
	if tr.daemon() {
		ctx, cancel := adminCtx()
		defer cancel()
		prev, _ = tr.client.Get(ctx, key)
	} else {
		nodeCtx, nodeCancel := context.WithTimeout(context.Background(), cliTimeout)
		defer nodeCancel()
		node, nerr := startCLINode(nodeCtx, "", "", tr.peers)
		if nerr != nil {
			return nerr
		}
		defer node.Close()
		prev, _ = node.IterativeGet(nodeCtx, key)
	}
	if prev == nil {
		return fmt.Errorf("no live record on the network — nothing to renew (register it)")
	}
	if prev.IsRevoked() {
		return fmt.Errorf("record is revoked (deliberate; un-revoke with register/name)")
	}
	if !force && !renewal.ShouldRenew(now, int64(prev.Record.Created), int64(prev.Record.Expires)) {
		remaining := time.Until(time.Unix(int64(prev.Record.Expires), 0)).Round(time.Minute)
		fmt.Printf("%s: fresh (%s left) — skipping (use -force)\n", display, remaining)
		return nil
	}

	env, err := renewal.RenewEnvelope(prev, kp, now)
	if err != nil {
		return err
	}

	// Publish at every legitimate key: the name key, and K_claim when the
	// record carries an embedded alias claim (register's two-key rule).
	if tr.daemon() {
		ctx, cancel := adminCtx()
		defer cancel()
		if _, err := tr.client.Publish(ctx, env); err != nil {
			return fmt.Errorf("publish: %w", err)
		}
		if len(env.Record.Claim) > 0 {
			if err := tr.client.PublishClaim(ctx, env); err != nil {
				return fmt.Errorf("publish (K_claim): %w", err)
			}
		}
	} else {
		nodeCtx, nodeCancel := context.WithTimeout(context.Background(), cliTimeout)
		defer nodeCancel()
		node, nerr := startCLINode(nodeCtx, "", "", tr.peers)
		if nerr != nil {
			return nerr
		}
		defer node.Close()
		if err := node.Publish(nodeCtx, env); err != nil {
			return fmt.Errorf("publish: %w", err)
		}
		if len(env.Record.Claim) > 0 {
			if err := node.PublishClaim(nodeCtx, env); err != nil {
				return fmt.Errorf("publish (K_claim): %w", err)
			}
		}
	}

	pin := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(tldID), "="))
	fmt.Printf("%s: RENEWED (sequence %d, fresh 24 h window) tld_id_b32=%s\n", display, env.Record.Sequence, pin)
	return nil
}
