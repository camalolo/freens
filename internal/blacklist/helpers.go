package blacklist

import (
	"os"

	"github.com/camalolo/freens/internal/atomicfile"
)

func readFile(path string) ([]byte, error) { return os.ReadFile(path) }

// writeFile is atomic (temp + rename) and owner-only: the ledger names
// accused peers, which is exactly the kind of file that must not be
// world-readable.
func writeFile(path string, data []byte) error {
	return atomicfile.Write(path, data, 0o600)
}
