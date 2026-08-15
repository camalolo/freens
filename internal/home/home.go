// Package home is freens' single state directory (~/.freens by default,
// $FREENS_HOME to override): node identity, config, seed list, owner
// keychain, persisted store, learned peerbook, and the admin socket.
//
// The goal is the zero-configuration daemon: given no flags at all, `freens
// daemon` finds (or creates) everything here and just runs. Explicit flags
// and the [dht] config section override as before (flag > config > home
// default > built-in default).
package home

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/laurent/freens/internal/dht"
)

// Dir returns the state directory root: $FREENS_HOME, else ~/.freens.
func Dir() string {
	if d := os.Getenv("FREENS_HOME"); d != "" {
		return d
	}
	hd, err := os.UserHomeDir()
	if err != nil || hd == "" {
		return ".freens" // last resort: relative (tests, containers)
	}
	return filepath.Join(hd, ".freens")
}

// ConfPath is the daemon config (INI: resolver sections + [dht]).
func ConfPath() string { return filepath.Join(Dir(), "freens.conf") }

// NodeKeyPath is the daemon's node identity keyfile (@keyfile form).

func SeedsPath() string { return filepath.Join(Dir(), "seeds.conf") }

func StoreDir() string { return filepath.Join(Dir(), "store") }

func KeysDir() string { return filepath.Join(Dir(), "keys") }

func PeersDir() string { return filepath.Join(Dir(), "peers") }

func PeerbookPath() string { return filepath.Join(PeersDir(), "book.json") }

func AdminSock() string {
	if runtime.GOOS == "windows" { // no unix sockets: named pipe is future work
		return `\\.\pipe\freens-admin`
	}
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

type peerJSON struct {
	Addr string `json:"addr"`
	PK   string `json:"pk"`
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
		pj.Peers = append(pj.Peers, peerJSON{Addr: p.Addr, PK: fmt.Sprintf("%x", p.PublicKey)})
	}
	b, err := json.MarshalIndent(pj, "", "  ")
	if err != nil {
		return err
	}
	if err := Ensure(); err != nil {
		return err
	}
	tmp := PeerbookPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, PeerbookPath())
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
		pk, err := hexDecode(p.PK)
		if err != nil || len(pk) != 32 || p.Addr == "" {
			continue
		}
		out = append(out, dht.Peer{Addr: p.Addr, PublicKey: pk})
	}
	return out
}

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd length")
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		hi := hexVal(s[2*i])
		lo := hexVal(s[2*i+1])
		if hi < 0 || lo < 0 {
			return nil, fmt.Errorf("bad hex")
		}
		out[i] = byte(hi<<4 | lo)
	}
	return out, nil
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}
