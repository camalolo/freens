package home

// seeds.go — the zero-config bootstrap seed list (seeds.conf).
//
// seeds.conf is the "first boot" peer source: when a daemon is started with
// no -peers and no -peers-file, cmd/freens falls back to this file plus the
// learned peerbook (peers/book.json, refreshed every 60s from the routing
// table by SavePeerbook). The DEFAULT content pins the project's seed node
// so a fresh install joins the network with zero configuration; operators
// edit the file (or delete the entry) to peer elsewhere. Parsing is
// deliberately best-effort — seeds are hints, not config: anything that
// does not parse is skipped silently so one bad line never blocks startup.

import (
	"encoding/hex"
	"errors"
	"io/fs"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/camalolo/freens/internal/constants"
	"github.com/camalolo/freens/internal/dht"
)

// DefaultSeeds is the pinned seeds.conf content written by EnsureSeeds on
// first boot: comments explaining the format plus the project seed node.
// The seed advertises a HOSTNAME (DDNS-fronted, see contrib/README.md
// "Seed node: DDNS + hostname advertise") — peers re-resolve it, so the
// entry survives the seed's PPPoE address changes without edits here.
//
// SCAR (2026-09-19): this constant carried the seed's PRE-CLEANUP public
// key (780494a3…, replaced during the 2026-08-31 identity cleanup) while
// every fleet seeds.conf had been hand-fixed — so the compiled fallback
// pointed at a node that does not exist, and every verb run's seed entry
// (and every fresh install's first bootstrap) timed out against a live,
// healthy seed: "unreachable (context deadline exceeded)" with the seed
// answering on the very same address from a book entry with the right
// key. If the seed's identity EVER changes again, this constant and the
// fleet's seeds.conf files must move together.

// DefaultSeedLine is THE canonical seed entry — the single source of
// truth for the community seed. SCAR (2026-09-19): TWO copies of this
// line existed (here and in cli/setup.go) and had DIVERGED for weeks —
// this package carried a stale pubkey (780494a3…, an old keychain-era
// node) while cli/setup.go carried the live one. Every seeds.conf was
// therefore correct (setup reads cli's copy) while the upgrade verb's
// compiled-in entry — which reads THIS package — dialed a node that did
// not exist. Any seed identity change moves exactly this constant.
const DefaultSeedLine = "freens.camalolo.com:15353#38c5d5b399d3df19c33c7de69c06054f9b608b1a84782508879f8454b6195fd6"

func DefaultSeeds() string {
	return `# freens bootstrap seeds - one "host:port#<64-hex-node-pk>" per line.
# Blank lines and #-comment lines are ignored; malformed lines are skipped
# silently (seeds are best-effort hints, not config). Used only when the
# daemon is started with neither -peers nor -peers-file; learned peers are
# remembered separately in peers/book.json and boot alongside this file.
` + DefaultSeedLine + "\n"
}

// ParseSeeds reads the seed list at path: one "host:port#<64-hex-pk>" entry
// per line, blank/#-comment lines skipped, malformed lines skipped silently.
// A missing or unreadable file yields nil (no seeds — the caller falls back
// to the peerbook or runs as an island).
func ParseSeeds(path string) []dht.Peer {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []dht.Peer
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if p, ok := parseSeedEntry(line); ok {
			out = append(out, p)
		}
	}
	return out
}

// ParseSeedsText parses seed entries from a string (same format and
// tolerance as ParseSeeds) — used by the upgrade verb to fall back to the
// PINNED DEFAULT seed when the peerbook and the live daemon set are both
// empty (a fresh install or a cold restart had "checked 0" peers).
func ParseSeedsText(text string) []dht.Peer {
	var out []dht.Peer
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if p, ok := parseSeedEntry(line); ok {
			out = append(out, p)
		}
	}
	return out
}

// parseSeedEntry parses one "host:port#<64-hex-pk>" seed line. ok is false
// for a missing "#", a bad host:port shape, or a public key that is not
// 64 hex chars (32 bytes) — same tolerance as cmd/freens' -peers parsing.
func parseSeedEntry(s string) (dht.Peer, bool) {
	idx := strings.Index(s, "#")
	if idx <= 0 || idx == len(s)-1 {
		return dht.Peer{}, false
	}
	addr := s[:idx]
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil || host == "" || portStr == "" {
		return dht.Peer{}, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return dht.Peer{}, false
	}
	pk, err := hex.DecodeString(s[idx+1:])
	if err != nil || len(pk) != constants.Ed25519PublicKeyLen {
		return dht.Peer{}, false
	}
	return dht.Peer{Addr: addr, PublicKey: pk}, true
}

// EnsureSeeds writes the default seeds.conf (0600) IF ABSENT — idempotent:
// an existing file (operator-edited) is never touched. Parent directories
// are created as by Ensure.
func EnsureSeeds() error {
	p := SeedsPath()
	if _, err := os.Stat(p); err == nil {
		return nil // already there (possibly operator-edited): keep it
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := Ensure(); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(DefaultSeeds()), 0o600)
}
