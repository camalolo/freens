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
	"sort"
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
		switch {
		case p.Confirmed > 0 && now-p.Confirmed < 3600:
			fmt.Printf("      confirmed · %dm ago\n", (now-p.Confirmed)/60)
		case p.Confirmed > 0:
			fmt.Printf("      confirmed · %s\n", time.Unix(p.Confirmed, 0).Format("2006-01-02 15:04"))
		default:
			fmt.Printf("      advertised (never confirmed directly)\n")
		}
	}
}

func printPeersJSON(peers []dht.Peer, verbose bool) error {
	type row struct {
		Addr      string   `json:"addr"`
		Alts      []string `json:"alts,omitempty"`
		Node      string   `json:"node_pk"`
		NodeID    string   `json:"node_id,omitempty"`
		Confirmed int64    `json:"confirmed"`
	}
	out := make([]row, 0, len(peers))
	for _, p := range peers {
		head, alts := dht.DisplayAddrs(p.Addr, p.Alts)
		r := row{Addr: head, Alts: alts, Node: hex.EncodeToString(p.PublicKey), Confirmed: p.Confirmed}
		if verbose {
			if id, err := crypto.NodeID(p.PublicKey); err == nil {
				r.NodeID = hex.EncodeToString(id)
			}
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
