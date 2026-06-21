package server

import (
	"embed"
	"io/fs"
	"net/http"
)

// webFS holds the compiled React dashboard.
// Built by: cd web && npm run build
// Copied to this package by: go generate ./internal/server/
//
// The build tag `noweb` skips the embed for faster dev builds.
// To build without the dashboard: go build -tags noweb ./...

//go:embed all:web_dist
var webFS embed.FS

// webHandler serves the React SPA.
// Any path not matched by the API routes falls through to here.
// React Router handles client-side routing, so we always return index.html
// for any unknown path (SPA pattern).
func webHandler() http.Handler {
	// Strip the "web_dist" prefix so index.html is at "/"
	sub, err := fs.Sub(webFS, "web_dist")
	if err != nil {
		// This only fails if web_dist doesn't exist at build time
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Dashboard not built. Run: cd web && npm run build", http.StatusServiceUnavailable)
		})
	}

	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if the exact file exists
		f, err := sub.Open(r.URL.Path[1:]) // strip leading /
		if err == nil {
			f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		// Fall back to index.html for SPA client-side routing
		r2 := *r
		r2.URL.Path = "/"
		fileServer.ServeHTTP(w, &r2)
	})
}
