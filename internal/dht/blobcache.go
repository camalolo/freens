// blobcache.go — the daemon-side release-blob cache (v0.19.7): the
// storage half of chunked peer transfer. After a successful `freens
// upgrade` the downloaded tarball lands here (keyed by its whole-file
// SHA-256); the daemon then answers `blob.get` RPCs for it from disk.
// Bounded by design: at most maxCacheEntries archives (the newest win),
// each one release-tarball-sized — the fleet is the update CDN without
// becoming an unbounded mirror.
package dht

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// maxBlobCacheEntries bounds the cache dir (newest-mtime win). 8 = room
// for EVERY platform's archive of the current release (the first mover
// prefetches them all — see prefetchPeerTransferAssets — so any box can
// swarm any platform from the fleet; ~13 MB each).
const maxBlobCacheEntries = 8

// BlobCache is a directory of tarballs keyed by their whole-file SHA-256
// (hex). Safe for concurrent use.
type BlobCache struct {
	dir string
}

// NewBlobCache creates (if needed) and returns the cache rooted at dir.
func NewBlobCache(dir string) (*BlobCache, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("dht: blob cache: %w", err)
	}
	return &BlobCache{dir: dir}, nil
}

func blobCachePath(dir string, id []byte) string {
	return filepath.Join(dir, hex.EncodeToString(id)+".tar.gz")
}

// Store copies srcPath into the cache under id, then prunes to the newest
// maxBlobCacheEntries entries (a failed prune is non-fatal: an overfull
// cache still serves).
func (c *BlobCache) Store(id []byte, srcPath string) error {
	dst := blobCachePath(c.dir, id)
	if err := copyFileAtomic(dst, srcPath); err != nil {
		return err
	}
	c.prune()
	return nil
}

// Has reports whether id is cached.
func (c *BlobCache) Has(id []byte) bool {
	_, err := os.Stat(blobCachePath(c.dir, id))
	return err == nil
}

// Open returns a read-seeker over the cached blob and its size, or
// os.ErrNotExist when absent.
func (c *BlobCache) Open(id []byte) (*os.File, int64, error) {
	f, err := os.Open(blobCachePath(c.dir, id))
	if err != nil {
		return nil, 0, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, st.Size(), nil
}

func (c *BlobCache) prune() {
	entries, err := os.ReadDir(c.dir)
	if err != nil || len(entries) <= maxBlobCacheEntries {
		return
	}
	type named struct {
		name string
		mod  int64
	}
	var all []named
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		all = append(all, named{e.Name(), info.ModTime().UnixNano()})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].mod > all[j].mod })
	for _, e := range all[maxBlobCacheEntries:] {
		_ = os.Remove(filepath.Join(c.dir, e.name))
	}
}

func copyFileAtomic(dst, src string) error {
	tmp := dst + ".tmp"
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := out.ReadFrom(in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}
