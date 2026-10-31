package api

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
)

const quicLogTailSize int64 = 128 << 10

type quicEvent struct {
	TS      int64  `json:"ts"`
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

type quicResponse struct {
	Mode              string      `json:"mode"`
	Effective         bool        `json:"effective"`
	FirewallAvailable bool        `json:"firewallAvailable"`
	RejectedUDP443    uint64      `json:"rejectedUDP443"`
	LogsAvailable     bool        `json:"logsAvailable"`
	Events            []quicEvent `json:"events"`
	UpdatedAt         int64       `json:"updatedAt"`
}

// Persistent logs may reveal local topology. Never expose them without
// a valid management session or an authorized service API key.
func handleQUICHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeHTTPError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, _, sessionOK := currentSession(r); !sessionOK && !serviceAPIAuthenticated(r) {
		writeHTTPError(w, http.StatusUnauthorized, "management session required")
		return
	}
	stack, err := config.LoadStack()
	if err != nil {
		writeHTTPError(w, http.StatusServiceUnavailable, "QUIC configuration unavailable")
		return
	}
	mode := stack.Front.QUICMode
	if mode == "" {
		mode = "allow"
	}
	out := quicResponse{Mode: mode, Events: []quicEvent{}, UpdatedAt: time.Now().Unix()}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	firewall, err := exec.CommandContext(ctx, "nft", "list", "table", "inet", "vpn_front").CombinedOutput()
	if err == nil {
		count, enabled := parseQUICFirewall(string(firewall))
		out.FirewallAvailable = true
		out.RejectedUDP443 = count
		out.Effective = (mode == "tcp-fallback") == enabled
	}
	out.Events, out.LogsAvailable = loadQUICEvents(paths.DiagnosticsDir, 25)
	writeHTTPJSON(w, http.StatusOK, out)
}

// Rejected UDP/443 packets are intentional fallbacks, NOT Xray QUIC errors.
// nft output contains four counters (input/forward, IPv4/IPv6).
func parseQUICFirewall(body string) (rejected uint64, fallback bool) {
	chain := ""
	seenInput, seenForward := false, false
	for _, line := range strings.Split(body, "\n") {
		s := strings.TrimSpace(line)
		if strings.HasPrefix(s, "chain ") {
			fields := strings.Fields(s)
			chain = ""
			if len(fields) > 1 {
				chain = fields[1]
			}
			if chain == "quic_tcp_fallback_input" {
				seenInput = true
			}
			if chain == "quic_tcp_fallback_forward" {
				seenForward = true
			}
			continue
		}
		if s == "}" {
			chain = ""
			continue
		}
		if chain != "quic_tcp_fallback_input" && chain != "quic_tcp_fallback_forward" {
			continue
		}
		if !strings.Contains(s, "udp dport 443") || !strings.Contains(s, "reject") {
			continue
		}
		fields := strings.Fields(s)
		for i := 0; i+2 < len(fields); i++ {
			if fields[i] == "counter" && fields[i+1] == "packets" {
				n, err := strconv.ParseUint(fields[i+2], 10, 64)
				if err == nil {
					rejected += n
				}
				break
			}
		}
	}
	return rejected, seenInput && seenForward
}

func quicEventFromLine(line string) (quicEvent, bool) {
	at := strings.IndexByte(line, ' ')
	if at <= 0 {
		return quicEvent{}, false
	}
	ts, err := time.Parse(time.RFC3339Nano, line[:at])
	if err != nil {
		return quicEvent{}, false
	}
	rest := line[at+1:]
	if !strings.Contains(rest, "source=syslog") {
		return quicEvent{}, false
	}
	lower := strings.ToLower(rest)
	kind := ""
	if strings.Contains(lower, "vpn-guardian-control:") && strings.Contains(lower, "quic mode changed to ") {
		kind = "mode-change"
	} else {
		isQUIC := strings.Contains(lower, "quic") || strings.Contains(lower, "http/3") ||
			strings.Contains(lower, "http3") || strings.Contains(lower, "crypto_error")
		isUDP := strings.Contains(lower, "udp:") && strings.Contains(lower, ":443")
		bad := strings.Contains(lower, "error") || strings.Contains(lower, "fail") ||
			strings.Contains(lower, "timeout") || strings.Contains(lower, "warn") ||
			strings.Contains(lower, "reset by peer") || strings.Contains(lower, "broken pipe") ||
			strings.Contains(lower, "handshake") || strings.Contains(lower, "refused")
		if (isQUIC || isUDP) && bad {
			kind = "error"
		}
	}
	if kind == "" {
		return quicEvent{}, false
	}
	if i := strings.Index(rest, ": "); i >= 0 {
		rest = rest[i+2:]
	}
	// The persistent logger already redacts secrets and URL query strings.
	// Prevent accidental newlines or oversized text from reaching the UI.
	rest = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, rest)
	if len(rest) > 400 {
		rest = rest[:400] + "…"
	}
	return quicEvent{TS: ts.Unix(), Kind: kind, Message: strings.TrimSpace(rest)}, true
}

func loadQUICEvents(dir string, limit int) ([]quicEvent, bool) {
	found := []quicEvent{}
	if limit < 1 {
		return found, false
	}
	available := false
	for i := 3; i >= 0; i-- {
		name := "events.log"
		if i > 0 {
			name = fmt.Sprintf("events.log.%d", i)
		}
		data, err := readQUICLogTail(filepath.Join(dir, name), quicLogTailSize)
		if err != nil {
			continue
		}
		available = true
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 2048), 64*1024)
		for scanner.Scan() {
			if event, ok := quicEventFromLine(scanner.Text()); ok {
				found = append(found, event)
			}
		}
	}
	sort.SliceStable(found, func(i, j int) bool { return found[i].TS > found[j].TS })
	if len(found) > limit {
		found = found[:limit]
	}
	return found, available
}

func readQUICLogTail(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular log file")
	}
	start := int64(0)
	if info.Size() > maxBytes {
		start = info.Size() - maxBytes
	}
	data, err := io.ReadAll(io.NewSectionReader(f, start, info.Size()-start))
	if err != nil {
		return nil, err
	}
	if start > 0 {
		idx := bytes.IndexByte(data, '\n')
		if idx < 0 {
			return nil, nil
		}
		data = data[idx+1:]
	}
	return data, nil
}
