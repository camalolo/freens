package home

// seeds.go — the zero-config bootstrap seed list (seeds.conf) and the
// routing-table → peerbook adapter.
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
func DefaultSeeds() string {
	return `# freens bootstrap seeds - one "host:port#<64-hex-node-pk>" per line.
# Blank lines and #-comment lines are ignored; malformed lines are skipped
# silently (seeds are best-effort hints, not config). Used only when the
# daemon is started with neither -peers nor -peers-file; learned peers are
# remembered separately in peers/book.json and boot alongside this file.
freens.camalolo.com:15353#780494a338d831d94b371c9a1d9351885753df071ba4e60e23283282d33fe2c7
`
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

// ContactsToPeers converts routing-table contacts (Node.RoutingTable().
// AllContacts()) into bootstrap Peer values so the daemon can persist them
// via SavePeerbook. The PK is the contact's node PUBLIC KEY (not the Node
// ID): AddPeer derives the recipient_id from the public key, so only the
// key round-trips into a dialable peerbook entry. The key bytes are copied
// so the peer does not alias routing-table memory. Contacts with an empty
// address or a malformed key are skipped (they cannot be bootstrapped
// from anyway).
func ContactsToPeers(contacts []*dht.NodeContact) []dht.Peer {
	out := make([]dht.Peer, 0, len(contacts))
	for _, c := range contacts {
		if c == nil || c.Addr == "" || len(c.PublicKey) != constants.Ed25519PublicKeyLen {
			continue
		}
		out = append(out, dht.Peer{
			Addr:      c.Addr,
			PublicKey: append([]byte(nil), c.PublicKey...),
		})
	}
	return out
}
