// Package atomicfile provides crash-safe whole-file replacement.
//
// It is the single implementation of the temp+fsync+rename scheme that
// previously lived (with drift) in keychain, confedit, home, certmgr,
// trustsync, and the dht store/claims-pool persist paths: write a temp
// file in the SAME directory, fsync it, chmod it to the requested mode,
// rename it over the target, then fsync the directory so the rename
// itself survives a crash. Any failure before the rename removes the
// temp file (no litter, target untouched — the old bytes stay intact).
package atomicfile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

// Write atomically replaces path with data, creating the parent directory
// if missing (MkdirAll only creates MISSING dirs — an existing private
// 0700 dir is never loosened). perm is applied to the file even when it
// replaces a looser existing one (the keychain always-0600 rule).
//
// Durability note: Windows has no directory-sync concept — opening the
// dir succeeds but Sync fails with ERROR_ACCESS_DENIED (found live on the
// desktop test box during the v0.11.0 setup run) — so there the rename
// stays at the mercy of NTFS metadata journaling: the durable-rename
// guarantee is best-effort, the WRITE still succeeded.
func Write(path string, data []byte, perm os.FileMode) (err error) {
	if path == "" {
		return errors.New("atomicfile: empty path")
	}
	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.Remove(tmp.Name()) // best effort: no temp litter on failure
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Chmod(tmp.Name(), perm); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	d, derr := os.Open(dir)
	if derr != nil {
		if runtime.GOOS == "windows" {
			return nil
		}
		return derr
	}
	defer d.Close()
	if err = d.Sync(); err != nil {
		if runtime.GOOS == "windows" {
			return nil // see durability note above
		}
		return err
	}
	return nil
}
