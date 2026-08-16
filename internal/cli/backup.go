// backup.go — `freens backup`: the "never lose your name" button.
//
// register generates the owner key + (by default) 3 recovery keyfiles in
// the keychain — small files whose loss is permanent. backup bundles ALL of
// them (plus the reusable claim state) into ONE dated file the user can
// copy off-machine, with a RESTORE.txt inside explaining what it is:
//
//	freens backup                 -> freens-backup-20260815-142030.tar.gz (cwd)
//	freens backup -out usb.tar.gz
//	freens backup -restore f.tar.gz   (refuses to overwrite; -force)
//
// The restore side accepts ONLY plain keychain filenames (no paths), so a
// hostile archive cannot write outside the keychain.
package cli

import (
	"archive/tar"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"strings"

	"github.com/camalolo/freens/internal/home"
	"github.com/camalolo/freens/internal/keychain"
)

// backupEntryRe matches the only filenames a backup (or a restore) may
// carry: owner keys, register's recovery keyfiles, and the reusable claim
// state — bare names, no directories.
var backupEntryRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.rec[1-9][0-9]*)?(\.key|\.claim\.json)$`)

func cmdBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	out := fs.String("out", "", "backup file to write (default: freens-backup-<date>.tar.gz in the current directory)")
	restore := fs.String("restore", "", "restore a backup file into the keychain (instead of creating one)")
	force := fs.Bool("force", false, "with -restore: overwrite existing keychain files")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return usageErr("backup takes no positional arguments")
	}
	if *restore != "" {
		return backupRestore(*restore, *force)
	}
	if *force {
		return usageErr("-force only applies to -restore")
	}
	return backupCreate(*out)
}

// backupCreate bundles the keychain into one dated tar.gz.
func backupCreate(outPath string) error {
	if outPath == "" {
		outPath = "freens-backup-" + time.Now().Format("20060102-150405") + ".tar.gz"
	}
	abs, err := filepath.Abs(outPath)
	if err != nil {
		abs = outPath
	}
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("write %q: %w", outPath, err)
	}
	files, err := keychain.BuildBackup(f, home.KeysDir())
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	fmt.Printf("backup written: %s\n", abs)
	fmt.Printf("  %d file(s): %s\n", len(files), strings.Join(files, ", "))
	fmt.Println()
	fmt.Println("IMPORTANT — this file IS ownership of your name(s):")
	fmt.Println("  • copy it somewhere safe OFF this machine (USB stick, password manager, cloud drive you trust)")
	fmt.Println("  • keep it secret: anyone holding it can take over your names")
	fmt.Println("  • losing it AND the machine means losing the name forever")
	fmt.Printf("  • restore with: %s backup -restore %s\n", ProgName, outPath)
	return nil
}

func backupRestore(path string, force bool) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("read backup %q: %w", path, err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("%q is not a freens backup (gzip): %v", path, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	if err := home.Ensure(); err != nil {
		return err
	}
	var restored, skipped []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading backup: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || !backupEntryRe.MatchString(hdr.Name) {
			continue // RESTORE.txt and anything foreign: skip silently
		}
		name := filepath.Base(hdr.Name) // defenses-in-depth vs "../x.key"
		dst := filepath.Join(home.KeysDir(), name)
		if !force && fileExists(dst) {
			skipped = append(skipped, name)
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, 1<<20))
		if err != nil {
			return fmt.Errorf("reading %q from backup: %w", name, err)
		}
		if err := os.WriteFile(dst, b, 0o600); err != nil {
			return fmt.Errorf("writing %q: %w", dst, err)
		}
		restored = append(restored, name)
	}
	if len(restored) == 0 && len(skipped) == 0 {
		return usageErr("%q contains no freens key files", path)
	}
	for _, name := range restored {
		fmt.Printf("restored: %s\n", name)
	}
	for _, name := range skipped {
		fmt.Printf("kept existing (use -force to overwrite): %s\n", name)
	}
	fmt.Printf("done — check your names with `%s status`\n", ProgName)
	return nil
}

const backupReadmeTemplate = `freens key backup
=================

This file contains the private keys of your freens name(s). Whoever holds
it owns the names. Keep it secret; keep it somewhere safe OFF this machine.

Restore on any machine with:

    %s backup -restore <this file>

Contents:
  %s

File naming:
  <name>.key          the owner key — proves you own <name>
  <name>.recN.key     recovery key N — any 2 of 3 recover a lost owner key
  <name>.claim.json   reusable registration state (speeds up retries)

If you chose a passphrase at registration, the .key files are encrypted
(FREENSK1); unlocking needs the passphrase (prompted, or the
FREENS_PASSPHRASE environment variable). Without a passphrase they are
plain hex — protect the backup file itself.
`
