// Package home is freens' single state directory (~/.freens by default,
// %ProgramData%\freens on Windows, $FREENS_HOME to override): node
// identity, config, seed list, owner keychain, persisted store, learned
// peerbook, and the admin socket.
//
// The goal is the zero-configuration daemon: given no flags at all, `freens
// daemon` finds (or creates) everything here and just runs. Explicit flags
// and the [dht] config section override as before (flag > config > home
// default > built-in default).
package home

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/camalolo/freens/internal/atomicfile"
	"github.com/camalolo/freens/internal/dht"
)

// Dir returns the state directory root: $FREENS_HOME, else ~/.freens
// (Windows: %ProgramData%\freens — the daemon is machine infrastructure
// there: the SCM service runs as LocalSystem while every user's CLI must
// find the SAME keychain + admin socket, which a per-user profile would
// split; setup grants the installing user access).
func Dir() string {
	if d := os.Getenv("FREENS_HOME"); d != "" {
		return d
	}
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "freens")
		}
		return `C:\ProgramData\freens` // ProgramData is always defined in practice
	}
	hd, err := os.UserHomeDir()
	if err != nil || hd == "" {
		return ".freens" // last resort: relative (tests, containers)
	}
	return filepath.Join(hd, ".freens")
}

// ConfPath is the daemon config (INI: resolver sections + [dht]).
func ConfPath() string { return filepath.Join(Dir(), "freens.conf") }

func SeedsPath() string { return filepath.Join(Dir(), "seeds.conf") }

func StoreDir() string { return filepath.Join(Dir(), "store") }

func KeysDir() string { return filepath.Join(Dir(), "keys") }

// BlacklistPath is the proven-violation peer ledger (internal/blacklist),
// shared by the daemon and one-shot CLI verbs (merge-on-write).
func BlacklistPath() string { return filepath.Join(Dir(), "blacklist.json") }

func PeersDir() string { return filepath.Join(Dir(), "peers") }

func PeerbookPath() string { return filepath.Join(PeersDir(), "book.json") }

func AdminSock() string {
	// Windows ships AF_UNIX since Windows 10 1803 and Go supports it since
	// 1.17 — the same <home>/admin.sock filesystem path works on both ends
	// (daemon + CLI are both Go programs). No named-pipe special case needed.
	return filepath.Join(Dir(), "admin.sock")
}

// Ensure creates the state directory layout (0700 root, 0700 keys).
// Idempotent.
func Ensure() error {
	for _, d := range []string{Dir(), KeysDir(), StoreDir(), PeersDir()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("home: %s: %w", d, err)
		}
	}
	return nil
}

// peerbookJSON is the wire form of the learned-peerbook file.
type peerbookJSON struct {
	SavedAt int64      `json:"saved_at"`
	Peers   []peerJSON `json:"peers"`
}

// peerJSON is one persisted contact. Confirmed (unix seconds, 0 = never
// directly confirmed) carries the routing table's anti-ghost probation
// clock (issue #2) across restarts: without it, a daemon reload reset
// ghost contacts to fresh probation, and a host that restarts often
// enough (or a CLI one-shot re-running) could short-circuit its own
// eviction forever.
type peerJSON struct {
	Addr      string `json:"addr"`
	PK        string `json:"pk"`
	Confirmed int64  `json:"confirmed,omitempty"`
}

// SavePeerbook persists up to 32 of the node's routing-table contacts
// (closest to nothing in particular — the K most-recently-seen buckets
// order) so the NEXT boot does not depend on seeds being reachable.
// Best-effort: an error is returned but callers may ignore it (the book is
// an optimization, not state).
func SavePeerbook(peers []dht.Peer, now int64) error {
	if len(peers) > 32 {
		peers = peers[:32]
	}
	pj := peerbookJSON{SavedAt: now}
	for _, p := range peers {
		pj.Peers = append(pj.Peers, peerJSON{Addr: p.Addr, PK: fmt.Sprintf("%x", p.PublicKey), Confirmed: p.Confirmed})
	}
	b, err := json.MarshalIndent(pj, "", "  ")
	if err != nil {
		return err
	}
	if err := Ensure(); err != nil {
		return err
	}
	// atomicfile.Write (perm 0600 — the mode the hand-rolled tmp+rename
	// used): temp file in the target dir, fsync, rename, dir-fsync — no
	// half-written or orphaned book.json.tmp after a crash.
	return atomicfile.Write(PeerbookPath(), b, 0o600)
}

// LoadPeerbook reads the learned book (nil when absent/unreadable —
// callers fall back to seeds).
func LoadPeerbook() []dht.Peer {
	b, err := os.ReadFile(PeerbookPath())
	if err != nil {
		return nil
	}
	var pj peerbookJSON
	if err := json.Unmarshal(b, &pj); err != nil {
		return nil
	}
	var out []dht.Peer
	for _, p := range pj.Peers {
		pk, err := hex.DecodeString(p.PK)
		if err != nil || len(pk) != 32 || p.Addr == "" {
			continue
		}
		out = append(out, dht.Peer{Addr: p.Addr, PublicKey: pk, Confirmed: p.Confirmed})
	}
	return out
}
