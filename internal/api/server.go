package api

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const defaultAPIListen = "127.0.0.1:20175"

// Serve runs the dashboard API as a loopback HTTP service. nginx exposes it
// to the LAN while the listener itself stays unreachable from the network.
func Serve(args []string) error {
	fs := flag.NewFlagSet("vpn-guardian api-server", flag.ContinueOnError)
	listen := fs.String("listen", defaultAPIListen, "HTTP listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/api/status", handleHTTPStatus)
	mux.HandleFunc("/api/history", handleHTTPHistory)
	mux.HandleFunc("/api/control", handleHTTPControl)

	server := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return server.ListenAndServe()
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, "{\"ok\":true}\n")
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

// Control remains implemented by the existing CGI-compatible code so legacy
// PIN/session migration has exactly one behavior. Control requests are rare
// (initial page load, once per minute and explicit actions), so invoking the
// same binary for this endpoint keeps the migration path simple while status
// polling remains entirely in-process.
func handleHTTPControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeHTTPError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeHTTPError(w, http.StatusBadRequest, "cannot read request")
		return
	}

	exe, err := os.Executable()
	if err != nil {
		writeHTTPError(w, http.StatusInternalServerError, "cannot resolve executable")
		return
	}
	cmd := exec.Command(exe, "api", "control")
	cmd.Stdin = bytes.NewReader(body)
	cmd.Env = cgiEnvironment(r, len(body))
	out, runErr := cmd.CombinedOutput()
	if runErr != nil && !bytes.Contains(out, []byte("Content-Type:")) {
		writeHTTPError(w, http.StatusInternalServerError, strings.TrimSpace(string(out)))
		return
	}

	status, headers, responseBody, err := parseCGIResponse(out)
	if err != nil {
		writeHTTPError(w, http.StatusBadGateway, err.Error())
		return
	}
	for key, values := range headers {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(status)
	_, _ = w.Write(responseBody)
}

func cgiEnvironment(r *http.Request, bodyLen int) []string {
	env := make([]string, 0, len(os.Environ())+16)
	for _, item := range os.Environ() {
		switch {
		case strings.HasPrefix(item, "REQUEST_METHOD="),
			strings.HasPrefix(item, "REMOTE_ADDR="),
			strings.HasPrefix(item, "CONTENT_LENGTH="),
			strings.HasPrefix(item, "CONTENT_TYPE="),
			strings.HasPrefix(item, "HTTP_COOKIE="),
			strings.HasPrefix(item, "HTTP_X_VPN_CSRF="),
			strings.HasPrefix(item, "HTTP_X_VPN_UNLOCK="),
			strings.HasPrefix(item, "HTTP_ORIGIN="),
			strings.HasPrefix(item, "HTTP_REFERER="),
			strings.HasPrefix(item, "HTTP_HOST="):
			continue
		}
		env = append(env, item)
	}

	remote := strings.TrimSpace(r.Header.Get("X-Real-IP"))
	if remote == "" {
		remote = r.RemoteAddr
		if host, _, err := net.SplitHostPort(remote); err == nil {
			remote = host
		}
	}

	env = append(env,
		"REQUEST_METHOD="+r.Method,
		"REMOTE_ADDR="+remote,
		"CONTENT_LENGTH="+strconv.Itoa(bodyLen),
		"CONTENT_TYPE="+r.Header.Get("Content-Type"),
		"HTTP_COOKIE="+r.Header.Get("Cookie"),
		"HTTP_X_VPN_CSRF="+r.Header.Get("X-VPN-CSRF"),
		"HTTP_X_VPN_UNLOCK="+r.Header.Get("X-VPN-Unlock"),
		"HTTP_ORIGIN="+r.Header.Get("Origin"),
		"HTTP_REFERER="+r.Header.Get("Referer"),
		"HTTP_HOST="+r.Host,
	)
	return env
}

func parseCGIResponse(out []byte) (int, http.Header, []byte, error) {
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(out, sep)
	sepLen := len(sep)
	if idx < 0 {
		sep = []byte("\n\n")
		idx = bytes.Index(out, sep)
		sepLen = len(sep)
	}
	if idx < 0 {
		return 0, nil, nil, fmt.Errorf("control CGI returned no headers")
	}

	status := http.StatusOK
	headers := make(http.Header)
	for _, line := range strings.Split(strings.ReplaceAll(string(out[:idx]), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if strings.EqualFold(key, "Status") {
			fields := strings.Fields(value)
			if len(fields) > 0 {
				if parsed, err := strconv.Atoi(fields[0]); err == nil {
					status = parsed
				}
			}
			continue
		}
		headers.Add(key, value)
	}
	return status, headers, out[idx+sepLen:], nil
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
