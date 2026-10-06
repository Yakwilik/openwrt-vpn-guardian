package api

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
)

// dashboardFiles contains the production bundle generated from webui/.
//
//go:embed web/dist
var dashboardFiles embed.FS

type dashboardHandler struct {
	index []byte
	files http.Handler
}

func newDashboardHandler() (http.Handler, error) {
	dist, err := fs.Sub(dashboardFiles, "web/dist")
	if err != nil {
		return nil, fmt.Errorf("open embedded dashboard: %w", err)
	}

	index, err := fs.ReadFile(dist, "index.html")
	if err != nil {
		return nil, fmt.Errorf("read embedded dashboard index: %w", err)
	}

	return &dashboardHandler{
		index: index,
		files: http.FileServer(http.FS(dist)),
	}, nil
}

func (h *dashboardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	setDashboardSecurityHeaders(w)

	switch {
	case r.URL.Path == "/" || r.URL.Path == "/index.html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(h.index)
		}
	case strings.HasPrefix(r.URL.Path, "/assets/"):
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		h.files.ServeHTTP(w, r)
	default:
		http.NotFound(w, r)
	}
}

func setDashboardSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set(
		"Content-Security-Policy",
		"default-src 'self'; connect-src 'self'; img-src 'self' data:; "+
			"style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
	)
}
