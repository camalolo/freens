// blobseed — operator utility: fetch a release archive for an ARBITRARY
// platform into this box's blob cache, so platforms nobody runs locally
// (windows, the other arch) can peer-download from this box.
//
//	freens-cli is not enough: the cache lives in the DAEMON's home and is
//	served by the daemon's blob.get — this tool writes the same directory
//	the daemon reads (best-effort merge-on-read: hBlobGet opens by id, so
//	files landed here are served immediately).
//
// Usage: blobseed -release v0.19.13 -platform windows-amd64
//
// RUN AS THE DAEMON'S USER (not sudo): the cache file must be readable by
// the daemon — a root-owned 0600 file in blobs/ is silently unservable
// (hBlobGet's Open fails with EACCES and the peer answers 404-absent;
// found live 2026-09-19 when the first blobseed run went through sudo).
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/camalolo/freens/internal/dht"
	"github.com/camalolo/freens/internal/home"
)

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name            string `json:"name"`
	BrowserDownload string `json:"browser_download_url"`
}

func main() {
	rel := flag.String("release", "", "release tag (v-prefixed)")
	platform := flag.String("platform", "", "platform: windows-amd64, linux-arm64, ...")
	flag.Parse()
	if *rel == "" || *platform == "" {
		fmt.Fprintln(os.Stderr, "usage: blobseed -release v0.19.13 -platform windows-amd64")
		os.Exit(1)
	}
	tag := *rel
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}
	url := fmt.Sprintf("https://api.github.com/repos/camalolo/freens/releases/tags/%s", tag)
	client := &http.Client{Timeout: 60 * time.Second}
	rresp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "release:", err)
		os.Exit(1)
	}
	defer rresp.Body.Close()
	var data ghRelease
	if err := json.NewDecoder(rresp.Body).Decode(&data); err != nil {
		fmt.Fprintln(os.Stderr, "release decode:", err)
		os.Exit(1)
	}
	manifestName := "freens-manifest-" + *platform + ".json"
	tarName := "freens-" + *platform + ".tar.gz"
	var manifestURL, tarURL string
	for _, a := range data.Assets {
		switch a.Name {
		case manifestName:
			manifestURL = a.BrowserDownload
		case tarName:
			tarURL = a.BrowserDownload
		}
	}
	if manifestURL == "" || tarURL == "" {
		fmt.Fprintln(os.Stderr, "assets not found for", *platform)
		os.Exit(1)
	}
	mresp, err := client.Get(manifestURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "manifest:", err)
		os.Exit(1)
	}
	defer mresp.Body.Close()
	// Reuse the verb's manifest parser via the dht blob id: the manifest's
	// SHA256 field IS the blob id. Parse the small JSON directly.
	var man struct {
		SHA256    string `json:"sha256"`
		Size      uint64 `json:"size"`
		ChunkSize uint64 `json:"chunk_size"`
	}
	if err := json.NewDecoder(mresp.Body).Decode(&man); err != nil {
		fmt.Fprintln(os.Stderr, "manifest decode:", err)
		os.Exit(1)
	}
	id, err := hex.DecodeString(man.SHA256)
	if err != nil || len(id) != 32 {
		fmt.Fprintln(os.Stderr, "bad manifest digest")
		os.Exit(1)
	}
	bc, err := dht.NewBlobCache(filepath.Join(home.Dir(), "blobs"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "cache:", err)
		os.Exit(1)
	}
	if _, _, err := bc.Open(id); err == nil {
		fmt.Println("already cached:", *platform, man.SHA256[:16]+"…")
		return
	}
	fmt.Printf("downloading %s (%d bytes) ...\n", tarName, man.Size)
	dl := &http.Client{Timeout: 15 * time.Minute}
	tresp, err := dl.Get(tarURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "download:", err)
		os.Exit(1)
	}
	defer tresp.Body.Close()
	tmp, err := os.CreateTemp("", "blobseed-*.tar.gz")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), tresp.Body)
	tmp.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "download:", err)
		os.Exit(1)
	}
	if hex.EncodeToString(h.Sum(nil)) != man.SHA256 {
		fmt.Fprintln(os.Stderr, "INTEGRITY: downloaded bytes do not match the manifest digest — not caching")
		os.Exit(1)
	}
	_ = n
	if err := bc.Store(id, tmp.Name()); err != nil {
		fmt.Fprintln(os.Stderr, "store:", err)
		os.Exit(1)
	}
	_ = context.Background()
	fmt.Printf("cached %s for peer transfer (id %s…)\n", *platform, man.SHA256[:16])
}
