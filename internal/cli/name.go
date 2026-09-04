// name.go — `name <label>.<alias>`: the "add a name under my alias" easy
// button. It is make-record + publish with every flag a normal user should
// not need removed and every default filled from live state:
//
//	owner key    <home>/keys/<alias>.key (register put it there)
//	sequence     current+1 (fetched from the network; 1 for a new name)
//	ip           the APEX's current A record (inherit), or -ip
//	publish      the running daemon (admin socket), or -peers standalone
//
// No -pin (derived from the owner key), no -out, no hex.
package cli

import (
	"context"
	"encoding/base32"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/naming"
	"github.com/camalolo/freens/internal/wire"
)

func cmdName(args []string) error {
	fs := flag.NewFlagSet("name", flag.ContinueOnError)
	ip := fs.String("ip", "", "IPv4 address for the A record (default: the apex's current A record)")
	ttl := fs.Uint64("ttl", 300, "A record TTL in seconds")
	peersCSV := fs.String("peers", "", "comma-separated bootstrap peers as ip:port#<64-hex-pubkey> (standalone mode; default: the running daemon)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 1 {
		return usageErr("name takes exactly one name: <label>.<alias> (e.g. www.alice)")
	}
	labels, alias, err := naming.DecomposeName(fs.Args()[0])
	if err != nil {
		return usageErr("invalid name %q: %v", fs.Args()[0], err)
	}
	if len(labels) == 0 {
		return usageErr("%q is the apex itself — register owns the apex; name adds <label>.<alias> sub-names", fs.Args()[0])
	}

	// --- owner key from the keychain ----------------------------------------
	keyPath := ownerKeyPath(alias)
	if _, err := os.Stat(keyPath); err != nil {
		avail := keychainAliases()
		if len(avail) == 0 {
			return usageErr("no owner key for alias %q (looked for %s) and the keychain is empty — register an alias first: %s register <%s>", alias, keyPath, ProgName, alias)
		}
		return usageErr("no owner key for alias %q (looked for %s); keychain has: %s", alias, keyPath, strings.Join(avail, ", "))
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

	// --- transport: daemon (admin socket) or standalone ---------------------
	tr, err := pickTransport(*peersCSV)
	if err != nil {
		return err
	}
	displayName := fs.Args()[0]

	// --- current state: this name's sequence + the apex's A record ----------
	// Sequence discovery fetches the envelope by key (tombstones included —
	// /resolve hides a revoked name's sequence, which broke un-revoke: a
	// post-revoke publish would reset to sequence 1 and lose the §6.4
	// winner race; found live, same fix as the web UI's engine).
	wireName, err := naming.EncodeWireName(labels, alias, tldID)
	if err != nil {
		return err
	}
	nameKey, err := dht.KeyForWireName(wireName)
	if err != nil {
		return err
	}
	var seq uint64 = 1
	apexIP := strings.TrimSpace(*ip)
	var node *dht.Node
	var nodeCtx context.Context
	var nodeCancel context.CancelFunc
	if tr.daemon() {
		ctx, cancel := adminCtx()
		defer cancel()
		cur, gerr := tr.client.Get(ctx, nameKey)
		if gerr != nil {
			// A failed discovery walk must not publish at seq 1: a
			// sub-name that already exists would silently lose the §6.4
			// winner race while the CLI prints PUBLISHED (the
			// phantom-sequence class; found in the 2026-09-04 audit).
			return fmt.Errorf("sequence discovery failed: %w (nothing published — retry)", gerr)
		}
		if cur != nil && cur.Record != nil {
			seq = cur.Record.Sequence + 1
		}
		if apexIP == "" {
			if r, err := tr.client.Resolve(ctx, alias); err == nil && r != nil {
				apexIP = firstAdminIP(r.RRset) // A first, AAAA fallback
			}
		}
	} else {
		nodeCtx, nodeCancel = context.WithTimeout(context.Background(), cliTimeout)
		defer nodeCancel()
		node, err = startCLINode(nodeCtx, "", "", tr.peers)
		if err != nil {
			return err
		}
		defer node.Close()
		// §6.2: warm the table toward the name key AND the apex key before
		// discovery — a store-hit get omits {nodes}, so a bootstrap peer's
		// stale copy alone would blind the walk (the phantom-sequence
		// class; same fix as register/renew, found in the 2026-09-04
		// audit).
		node.IterativeFindNode(nodeCtx, nameKey, constants.RReplication)
		if env, gerr := node.IterativeGet(nodeCtx, nameKey); gerr != nil {
			return fmt.Errorf("sequence discovery failed: %w (nothing published — retry)", gerr)
		} else if env != nil {
			seq = env.Record.Sequence + 1
		}
		if apexIP == "" {
			apexName, err := naming.EncodeWireName(nil, alias, tldID)
			if err != nil {
				return err
			}
			apexKey, err := dht.KeyForWireName(apexName)
			if err != nil {
				return err
			}
			node.IterativeFindNode(nodeCtx, apexKey, constants.RReplication)
			if env, err := node.IterativeGet(nodeCtx, apexKey); err == nil && env != nil {
				for _, rr := range env.Record.RRset {
					if rr.Type == wire.RRTypeA && len(rr.Rdata) == net.IPv4len {
						apexIP = net.IP(rr.Rdata).To4().String()
						break
					}
					if rr.Type == wire.RRTypeAAAA && len(rr.Rdata) == net.IPv6len && apexIP == "" {
						apexIP = net.IP(rr.Rdata).To16().String()
					}
				}
			}
		}
	}
	if apexIP == "" {
		return usageErr("no -ip given and the apex %s has no current A/AAAA record to inherit — pass -ip", alias)
	}

	// --- build + sign (the same builder make-record uses) -------------------
	expires := uint64(time.Now().Unix()) + uint64(constants.RecordDefaultTTL)
	ipRR, rrErr := addrRR(apexIP, *ttl)
	if rrErr != nil {
		return usageErr("%v", rrErr)
	}
	rec, wireName, err := buildRRRecord(displayName, tldID, ownerKP.Public(), ipRR, seq, expires)
	if err != nil {
		return err
	}
	env, err := wire.SignRecord(rec, ownerKP)
	if err != nil {
		return err
	}

	// --- publish ------------------------------------------------------------
	if tr.daemon() {
		ctx, cancel := publishCtx()
		defer cancel()
		if _, err := tr.client.Publish(ctx, env); err != nil {
			return fmt.Errorf("publish (daemon): %w", err)
		}
	} else {
		if err := node.Publish(nodeCtx, env); err != nil {
			return fmt.Errorf("publish: %w", err)
		}
	}

	kName := naming.DHTKeyName(wireName)
	fmt.Printf("name=%s\n", displayName)
	fmt.Printf("tld_id_b32=%s\n", pin)
	fmt.Printf("ip=%s\n", apexIP)
	fmt.Printf("ttl=%d\n", *ttl)
	fmt.Printf("sequence=%d\n", seq)
	fmt.Printf("k_name=%s\n", hex.EncodeToString(kName))
	fmt.Printf("PUBLISHED. %s -> %s (live now)\n", displayName, apexIP)
	return nil
}
