// assets.go — everything static the UI serves, embedded at build time (no
// external files, no CDN: the UI works on an air-gapped LAN). htmx is
// vendored under static/ with its license file.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var assetsFS embed.FS

// staticHandler serves /static from the embedded FS.
func staticHandler() http.Handler {
	sub, err := fs.Sub(assetsFS, "static")
	if err != nil {
		panic(err)
	}
	return cacheHeaders(http.FileServer(http.FS(sub)))
}

// cacheHeaders pins static asset caching (content-stable per binary).
func cacheHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		next.ServeHTTP(w, r)
	})
}
