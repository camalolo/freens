package cli

// peers.go — `freens peers`: the daemon's routing table on the terminal,
// the same rows the web UI's Network page shows (the webui page predates
// the command; the operator asked where the CLI half was — found missing
// 2026-09-02). One row per multi-homed contact: display-ordered addresses
// (public first, LAN after, per dht.DisplayAddrs), the Node ID prefix the
// web UI shows, last direct exchange, and the honest state badge
// (confirmed = a verified exchange; advertised = re-taught by peers only).

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/camalolo/freens/internal/crypto"
	"github.com/camalolo/freens/internal/dht"
)

func cmdPeers(args []string) error {
	fs := flag.NewFlagSet("peers", flag.ContinueOnError)
	verbose := fs.Bool("v", false, "show full keys, node IDs and every stored address")
	asJSON := fs.Bool("json", false, "machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageErr("peers takes no positional arguments (the routing table lives in the running daemon)")
	}

	tr, err := pickTransport("")
	if err != nil {
		return err
	}
	if !tr.daemon() {
		return usageErr("peers shows the RUNNING daemon's routing table — start the daemon (or use `freens status`)")
	}
	peers, err := tr.client.Peers(context.Background())
	if err != nil {
		return err
	}
	if *asJSON {
		return printPeersJSON(peers, *verbose)
	}
	printPeersTable(peers, *verbose)
	return nil
}

// printPeersTable renders the web UI's Network-page rows on the terminal.
func printPeersTable(peers []dht.Peer, verbose bool) {
	if len(peers) == 0 {
		fmt.Println("no peers known yet — the daemon is an island until a seed or peer answers")
		return
	}
	now := time.Now().Unix()
	sort.SliceStable(peers, func(i, j int) bool { // confirmed first, then freshest
		if (peers[i].Confirmed > 0) != (peers[j].Confirmed > 0) {
			return peers[i].Confirmed > 0
		}
		return peers[i].Confirmed > peers[j].Confirmed
	})
	fmt.Printf("peers: %d\n", len(peers))
	for _, p := range peers {
		head, alts := dht.DisplayAddrs(p.Addr, p.Alts)
		fmt.Printf("\n  %s\n", head)
		for _, alt := range alts {
			fmt.Printf("      also %s\n", alt)
		}
		if verbose {
			fmt.Printf("      pk  %s\n", hex.EncodeToString(p.PublicKey))
			if id, err := crypto.NodeID(p.PublicKey); err == nil {
				fmt.Printf("      id  %s\n", hex.EncodeToString(id))
			}
		} else {
			fmt.Printf("      node %.12s…\n", hex.EncodeToString(p.PublicKey))
		}
		confAddr, confAt := dht.ConfirmedAddr(p)
		switch {
		case confAt > 0 && now-confAt < 3600:
			fmt.Printf("      confirmed · %dm ago (at %s)\n", (now-confAt)/60, confAddr)
		case confAt > 0:
			fmt.Printf("      confirmed · %s (at %s)\n", time.Unix(confAt, 0).Format("2006-01-02 15:04"), confAddr)
		default:
			fmt.Printf("      advertised (never confirmed directly)\n")
		}
		// The asymmetry that matters (found live: a friend's box whose
		// confirmations all rode ephemeral one-shot ports while its real
		// daemon never answered): name the addresses that have never been
		// confirmed — only when the contact IS confirmed elsewhere. The
		// scan runs over the DISPLAY set (non-literals already dropped).
		if confAt > 0 {
			var never []string
			for _, a := range append([]string{head}, alts...) {
				if a == confAddr || altConfirmedAt(p, a) > 0 {
					continue
				}
				never = append(never, shortSameHost(a, confAddr))
			}
			if len(never) > 0 {
				fmt.Printf("      never confirmed: %s\n", strings.Join(never, " "))
			}
		}
	}
}

// shortSameHost renders addr as ":port" when it shares the reference
// address's host (the common multi-homing shape), else in full.
func shortSameHost(addr, ref string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || ref == "" {
		return addr
	}
	refHost, _, err := net.SplitHostPort(ref)
	if err != nil || refHost != host {
		return addr
	}
	return ":" + port
}

func printPeersJSON(peers []dht.Peer, verbose bool) error {
	type altRow struct {
		Addr      string `json:"addr"`
		Confirmed bool   `json:"confirmed"`
	}
	type row struct {
		Addr        string   `json:"addr"`
		Alts        []altRow `json:"alts,omitempty"`
		Node        string   `json:"node_pk"`
		NodeID      string   `json:"node_id,omitempty"`
		Confirmed   int64    `json:"confirmed"`
		ConfirmedAt string   `json:"confirmed_addr,omitempty"`
	}
	out := make([]row, 0, len(peers))
	for _, p := range peers {
		head, alts := dht.DisplayAddrs(p.Addr, p.Alts)
		r := row{Addr: head, Node: hex.EncodeToString(p.PublicKey), Confirmed: p.Confirmed}
		for _, st := range p.Alts {
			if !isDisplayAlt(st.Addr, head, alts) {
				continue // dropped from display: same rule for the JSON
			}
			r.Alts = append(r.Alts, altRow{Addr: st.Addr, Confirmed: st.ConfirmedAt > 0})
		}
		if verbose {
			if id, err := crypto.NodeID(p.PublicKey); err == nil {
				r.NodeID = hex.EncodeToString(id)
			}
		}
		if ca, _ := dht.ConfirmedAddr(p); ca != "" {
			r.ConfirmedAt = ca
		}
		out = append(out, r)
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

// isDisplayAlt reports whether st.Addr survived DisplayAddrs (a literal IP
// distinct from the headline) — the JSON must match the table's rows.
func isDisplayAlt(addr, head string, alts []string) bool {
	if addr == head {
		return false
	}
	for _, a := range alts {
		if a == addr {
			return true
		}
	}
	return false
}

// altConfirmedAt returns a displayed address's own confirmation timestamp
// (0 when never confirmed — including the headline, whose confirmation is
// the contact-level field only when it is the preferred address).
func altConfirmedAt(p dht.Peer, addr string) int64 {
	if addr == p.Addr {
		return p.Confirmed
	}
	for _, st := range p.Alts {
		if st.Addr == addr {
			return st.ConfirmedAt
		}
	}
	return 0
}
