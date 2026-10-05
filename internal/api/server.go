package api

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
)

const defaultAPIListen = "0.0.0.0:20175"

//go:embed web/index.html
var dashboardHTML []byte

// Serve runs the standalone dashboard and API server. It can be reached
// directly on the router LAN or placed behind an existing reverse proxy.
func Serve(args []string) error {
	fs := flag.NewFlagSet("vpn-guardian api-server", flag.ContinueOnError)
	listen := fs.String("listen", defaultAPIListen, "HTTP listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if _, _, err := config.Load(); err != nil {
		return fmt.Errorf("configuration incomplete; run vpn-guardian init: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/api/status", handleHTTPStatus)
	mux.HandleFunc("/api/history", handleHTTPHistory)
	mux.HandleFunc("/api/control", HandleControlHTTP)
	mux.HandleFunc("/", handleDashboard)

	server := &http.Server{
		Addr:              *listen,
		Handler:           dashboardAccessGuard(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      135 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return server.ListenAndServe()
}

func dashboardAccessGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !dashboardPeerAllowed(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(dashboardHTML)
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeHTTPJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func handleHTTPStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeHTTPError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	b, err := os.ReadFile(cachePath)
	if err != nil {
		writeHTTPError(w, http.StatusServiceUnavailable, "status cache unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func handleHTTPHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeHTTPError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	samples, _ := readSamples(historyPath, 1440)
	events, _ := readEvents(eventPath, 500)
	events = append(events, reconstructEvents(samples)...)
	events = normalizeEvents(events, 500)

	_, offset := time.Now().Zone()
	writeHTTPJSON(w, http.StatusOK, HistoryResponse{
		RouterTZOffset: offset,
		Samples:        samples,
		Events:         events,
	})
}

func writeHTTPJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeHTTPError(w http.ResponseWriter, status int, message string) {
	writeHTTPJSON(w, status, map[string]any{"ok": false, "error": message})
}
