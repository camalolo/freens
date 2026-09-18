package cli

// blacklist.go — the operator inventory for the proven-violation peer
// ledger (internal/blacklist): `freens blacklist ls [-json]` and
// `freens blacklist rm <nodeid-prefix>`. Same relationship to the ledger
// as `trust ls`/`trust remove`: a read/clear surface over daemon state —
// the DAEMON holds the in-memory ledger, so `rm` rewrites the file and
// the daemon's copy picks the removal up on its next merge-on-write (its
// in-memory flag survives until then, mirroring trust remove's documented
// behavior).

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/camalolo/freens/internal/blacklist"
	"github.com/camalolo/freens/internal/home"
)

func cmdBlacklist(args []string) error {
	fs := flag.NewFlagSet("blacklist", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return usageErr("usage: freens blacklist ls [-json] | freens blacklist rm <nodeid-prefix>")
	}
	switch fs.Arg(0) {
	case "ls":
		return blacklistLs(*jsonOut)
	case "rm":
		if fs.NArg() != 2 {
			return usageErr("blacklist rm takes one node id (full 64-hex or any unambiguous prefix)")
		}
		return blacklistRm(fs.Arg(1))
	default:
		return usageErr("unknown blacklist subcommand %q (want ls|rm)", fs.Arg(0))
	}
}

func openLedger() (*blacklist.Ledger, error) {
	return blacklist.Open(home.BlacklistPath())
}

func blacklistLs(jsonOut bool) error {
	l, err := openLedger()
	if err != nil {
		return err
	}
	entries := l.Entries()
	if jsonOut {
		data, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}
	if len(entries) == 0 {
		fmt.Println("no blacklisted peers (only cryptographically proven violations are ever recorded)")
		return nil
	}
	fmt.Printf("blacklist: %d flagged peer(s), entries decay 24h after their last violation\n", len(entries))
	for _, e := range entries {
		short := e.NodeID
		if len(short) > 16 {
			short = short[:16] + "…"
		}
		fmt.Printf("  %s  flagged %s  expires %s\n",
			short, e.FlaggedAt.Format("2006-01-02 15:04"), e.ExpiresAt.Format("2006-01-02 15:04"))
		for _, v := range e.Violations {
			proof := ""
			if v.Proof != "" {
				proof = "  proof " + v.Proof[:12] + "…"
			}
			fmt.Printf("      %-20s %s%s\n", string(v.Class), v.At.Format("15:04:05"), proof)
			if v.Detail != "" {
				fmt.Printf("      %s\n", v.Detail)
			}
		}
	}
	return nil
}

func blacklistRm(prefix string) error {
	l, err := openLedger()
	if err != nil {
		return err
	}
	prefix = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(prefix), "…"))
	entries := l.Entries()
	var match string
	for _, e := range entries {
		if strings.HasPrefix(e.NodeID, prefix) {
			if match != "" {
				return usageErr("prefix %q matches multiple entries — be more specific", prefix)
			}
			match = e.NodeID
		}
	}
	if match == "" {
		// Also accept a full 32-byte id given as raw hex (the ls output is
		// hex already, but a caller may pass the binary-derived form).
		if raw, derr := hex.DecodeString(prefix); derr == nil && len(raw) == 32 {
			if l.Remove(hex.EncodeToString(raw)) {
				fmt.Println("removed")
				return nil
			}
		}
		return fmt.Errorf("no live blacklist entry matches %q (freens blacklist ls)", prefix)
	}
	if !l.Remove(match) {
		return fmt.Errorf("entry expired before removal — nothing to do")
	}
	fmt.Printf("removed %s… — the peer recovers on the next ledger read (%s)\n",
		match[:16], time.Now().Format("15:04:05"))
	return nil
}
