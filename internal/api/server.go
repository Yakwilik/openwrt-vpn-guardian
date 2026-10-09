package api

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
)

const defaultAPIListen = "0.0.0.0:20175"

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

	dashboard, err := newDashboardHandler()
	if err != nil {
		return fmt.Errorf("initialize dashboard: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/api/status", handleHTTPStatus)
	mux.HandleFunc("/api/history", handleHTTPHistory)
	mux.HandleFunc("/api/control", HandleControlHTTP)
	mux.Handle("/", dashboard)

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

	offset := routerTZOffset()
	writeHTTPJSON(w, http.StatusOK, HistoryResponse{
		RouterTZOffset: offset,
		Samples:        samples,
		Events:         events,
	})
}

// Go may see UTC on OpenWrt even when BusyBox uses /etc/TZ (e.g. MSK-3).
// Ask the router's date implementation for its actual local UTC offset.
func routerTZOffset() int {
	_, fallback := time.Now().Zone()
	raw, err := exec.Command("/bin/date", "+%z").Output()
	if err != nil {
		return fallback
	}
	offset, ok := parseTZOffset(strings.TrimSpace(string(raw)))
	if !ok {
		return fallback
	}
	return offset
}

func parseTZOffset(raw string) (int, bool) {
	if len(raw) != 5 || (raw[0] != '+' && raw[0] != '-') {
		return 0, false
	}
	hours, errH := strconv.Atoi(raw[1:3])
	minutes, errM := strconv.Atoi(raw[3:5])
	if errH != nil || errM != nil || hours > 23 || minutes > 59 {
		return 0, false
	}
	offset := (hours*60 + minutes) * 60
	if raw[0] == '-' {
		offset = -offset
	}
	return offset, true
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
