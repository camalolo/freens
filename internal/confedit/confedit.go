// Package confedit implements safe, comment-preserving edits to freens.conf
// — the one INI file the daemon, freens-web and the CLI all read (v0.14.0
// §9.6 DoH support, but shape-agnostic: any section/key).
//
// Design rules, each earned the hard way on this repo:
//
//   - NEVER regenerate the file from a parsed model. freens.conf is
//     hand-maintained (comments carry operator notes like the fleet's
//     "upnp = false" annotations); a round-trip through a model would
//     silently destroy them. Edits are line surgery on the original bytes.
//   - Atomic replace: write a temp file in the same directory, fsync, rename.
//     A half-written config would brick the next daemon restart.
//   - Original file mode is preserved (a 0600 conf must not become 0644).
//   - One rolling backup at <path>.pre-doh — "the file as it was just
//     before the last DoH-family edit" — mirroring the .pre-upgrade backup
//     convention so an operator always has one undo step.
//   - Same INI conventions as resolver.ParseConfig: '[' section ']'
//     headers, key = value (or key : value) lines, ';' / '#' full-line
//     comments only, case-insensitive sections and keys.
package confedit

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Get returns the LAST value of key under section (later assignments win,
// matching every INI consumer here), whether it was found, and any read
// error. Commented-out lines never match. A missing file is not an error —
// found is simply false.
func Get(path, section, key string) (value string, found bool, err error) {
	lines, err := readLines(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// A missing config is the "all defaults" state, not an error —
			// Get mirrors that: nothing found, nothing wrong.
			return "", false, nil
		}
		return "", false, err
	}
	wantSec := strings.ToLower(strings.TrimSpace(section))
	wantKey := strings.ToLower(strings.TrimSpace(key))
	cur := ""
	for _, line := range lines {
		t := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if t == "" || t[0] == ';' || t[0] == '#' {
			continue
		}
		if t[0] == '[' {
			if end := strings.IndexByte(t, ']'); end > 0 {
				cur = strings.ToLower(strings.TrimSpace(t[1:end]))
			}
			continue
		}
		if cur != wantSec {
			continue
		}
		if k, v, ok := splitKV(t); ok && strings.ToLower(strings.TrimSpace(k)) == wantKey {
			value = strings.TrimSpace(v)
			found = true
		}
	}
	return value, found, nil
}

// Set writes key = value under section, preserving every other line
// verbatim (comments, ordering, unknown sections, inline formatting).
// value == "" removes the key instead. When the section does not exist it
// is appended (with a separating blank line) at the end of the file; a
// missing key inside an existing section is appended at the END of that
// section's body (after its comments, before the next header).
//
// The file is replaced atomically and <path>.pre-doh holds the previous
// content when the file actually changed. No-op when the file already
// expresses exactly the requested state (no backup churn).
func Set(path, section, key, value string) error {
	lines, err := readLines(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	wantSec := strings.ToLower(strings.TrimSpace(section))
	wantKey := strings.ToLower(strings.TrimSpace(key))
	newLine := key + " = " + value

	// Locate the section header (its FIRST occurrence) and the (last) key
	// line within it, in one pass.
	secIdx, keyIdx := -1, -1
	cur := ""
	for i, line := range lines {
		t := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if t != "" && t[0] == '[' {
			if end := strings.IndexByte(t, ']'); end > 0 {
				name := strings.ToLower(strings.TrimSpace(t[1:end]))
				if name == wantSec && secIdx == -1 {
					secIdx = i
				}
				cur = name
			}
			continue
		}
		if t == "" || t[0] == ';' || t[0] == '#' {
			continue
		}
		if cur != wantSec {
			continue
		}
		if k, _, ok := splitKV(t); ok && strings.ToLower(strings.TrimSpace(k)) == wantKey {
			keyIdx = i
		}
	}

	switch {
	case value == "" && keyIdx >= 0:
		// Removal: drop the key line.
		lines = append(lines[:keyIdx], lines[keyIdx+1:]...)
	case value == "":
		// Nothing to remove.
		return nil
	case keyIdx >= 0:
		// Replacement, in place.
		lines[keyIdx] = newLine
	case secIdx >= 0:
		// Append at the END of the section body: after its comments and
		// keys, right before the next header (or EOF). Inserting straight
		// after the header would bury the new key above the section's own
		// explanatory comments — surprising to anyone reading the file.
		end := len(lines)
		for i := secIdx + 1; i < len(lines); i++ {
			t := strings.TrimSpace(strings.TrimRight(lines[i], "\r"))
			if t != "" && t[0] == '[' && strings.HasSuffix(t, "]") {
				end = i
				break
			}
		}
		lines = append(lines[:end], append([]string{newLine}, lines[end:]...)...)
	default:
		// New section at the end of the file, with a separating blank line.
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
			lines = append(lines, "")
		}
		lines = append(lines, "["+section+"]", newLine)
	}

	out := strings.Join(lines, "\n")
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}

	// No-op detection: compare against the original bytes so an idempotent
	// re-apply writes nothing.
	orig, rerr := os.ReadFile(path)
	if rerr == nil && string(orig) == out {
		return nil
	}

	return writeFile(path, []byte(out))
}

// readLines reads path into lines (without trailing newline handling —
// the final newline is re-added on write).
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

// writeFile replaces path atomically: temp file in the same directory with
// the ORIGINAL file's mode (0600 when the file is new), fsync, rename, and
// a one-generation .pre-doh backup of the previous content.
func writeFile(path string, data []byte) error {
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
		if b, rerr := os.ReadFile(path); rerr == nil {
			// Keep exactly one undo step (the .pre-upgrade convention).
			if err := os.WriteFile(path+".pre-doh", b, mode); err != nil {
				return fmt.Errorf("confedit: backup %s.pre-doh: %w", path, err)
			}
		}
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".confedit-*")
	if err != nil {
		return fmt.Errorf("confedit: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("confedit: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("confedit: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("confedit: close: %w", err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return fmt.Errorf("confedit: chmod: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("confedit: rename: %w", err)
	}
	tmpName = "" // renamed away; the deferred cleanup must not delete it
	return nil
}

// splitKV splits a "key = value" (or "key : value") line at the FIRST
// separator — the same rule as resolver's parser, so values containing ':'
// (DoH URLs!) survive.
func splitKV(s string) (string, string, bool) {
	eq := strings.IndexByte(s, '=')
	co := strings.IndexByte(s, ':')
	idx := -1
	switch {
	case eq < 0 && co < 0:
		return "", "", false
	case eq < 0:
		idx = co
	case co < 0:
		idx = eq
	case eq < co:
		idx = eq
	default:
		idx = co
	}
	return s[:idx], s[idx+1:], true
}
