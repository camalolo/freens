package cli

// store.go — `freens store`: the daemon's live envelope store on the
// terminal (GET /store) — the web UI's Store page. One row per stored
// envelope: decoded name, sequence, lease state, and the §7.4 claim flags.

import (
	"context"
	"flag"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/camalolo/freens/internal/admin"
)

func cmdStore(args []string) error {
	fs := flag.NewFlagSet("store", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageErr("store takes no positional arguments (it lists the running daemon's envelope store)")
	}
	tr, err := pickTransport("")
	if err != nil {
		return err
	}
	if !tr.daemon() {
		return usageErr("store lists the RUNNING daemon's envelope store — start the daemon")
	}
	out, err := tr.client.Store(context.Background())
	if err != nil {
		return err
	}
	if out == nil || len(out.Entries) == 0 {
		fmt.Println("store: empty (records appear when published or cached)")
		return nil
	}
	entries := out.Entries
	sort.SliceStable(entries, func(i, j int) bool { // expired/revoked last, then by name
		if entries[i].Revoked != entries[j].Revoked {
			return !entries[i].Revoked
		}
		return storeEntryName(entries[i]) < storeEntryName(entries[j])
	})
	fmt.Printf("store: %d envelopes\n", out.Count)
	now := time.Now().Unix()
	for _, e := range entries {
		state := "live"
		switch {
		case e.Revoked:
			state = "REVOKED"
		case int64(e.Expires) <= now:
			state = "lapsed"
		}
		flags := ""
		if e.Claim {
			flags += " claim"
		}
		if e.ClaimKey {
			flags += " K_claim"
		}
		fmt.Printf("  %-28s seq %-4d %-8s%s\n",
			storeEntryName(e), e.Sequence, state, flags)
		fmt.Printf("      expires %s · %d bytes · key %s…\n",
			time.Unix(int64(e.Expires), 0).Format("2006-01-02 15:04"), e.Bytes, shortKey(e.Key))
	}
	return nil
}

// storeEntryName renders the decoded display name (alias or
// label.alias under the namespace) when present, else the raw key.
func storeEntryName(e admin.StoreEntry) string {
	if e.Alias != "" && len(e.Labels) > 0 {
		return strings.Join(e.Labels, ".") + "." + e.Alias
	}
	if e.Alias != "" {
		return e.Alias
	}
	if len(e.Labels) > 0 {
		return strings.Join(e.Labels, ".")
	}
	return shortKey(e.Key)
}

func shortKey(k string) string {
	if len(k) > 12 {
		return k[:12] + "…"
	}
	return k
}
