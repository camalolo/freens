// genmanifest — the release.yml helper that turns one release tarball into
// its chunk manifest (internal/blobman.Manifest, JSON): the trust anchor of
// chunked peer transfer. CI runs it per platform inside the build matrix;
// the verb fetches the manifest FROM GITHUB ORIGIN and verifies every
// peer-served chunk against it.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/camalolo/freens/internal/blobman"
)

func main() {
	var (
		asset     = flag.String("asset", "", "tarball filename as it appears on the release (manifest.Asset)")
		tag       = flag.String("tag", "", "release tag (manifest.Tag)")
		chunkSize = flag.Int("chunk-size", 0, "override the chunk size (default: blobman.DefaultChunkSize)")
		out       = flag.String("out", "", "output manifest path (default: stdout)")
	)
	flag.Parse()
	if flag.NArg() != 1 || *asset == "" {
		fmt.Fprintln(os.Stderr, "usage: genmanifest -asset <release-name> [-tag v…] [-chunk-size n] [-out file.json] <tarball>")
		os.Exit(2)
	}
	m, err := blobman.Compute(flag.Arg(0), *tag, *asset)
	if err != nil {
		fmt.Fprintln(os.Stderr, "genmanifest:", err)
		os.Exit(1)
	}
	if *chunkSize > 0 {
		m.ChunkSize = *chunkSize
		if err := m.Validate(); err != nil {
			fmt.Fprintln(os.Stderr, "genmanifest:", err)
			os.Exit(1)
		}
	}
	b, err := jsonMarshal(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "genmanifest:", err)
		os.Exit(1)
	}
	if *out == "" {
		os.Stdout.Write(b)
		fmt.Println()
		return
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "genmanifest:", err)
		os.Exit(1)
	}
}

// jsonMarshal indents through the encoding/json import of this file (kept
// here so the tool body above stays focused on flags).
func jsonMarshal(m *blobman.Manifest) ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}
