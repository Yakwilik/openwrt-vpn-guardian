package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const quicNFTFixture = `table inet vpn_front {
 chain quic_tcp_fallback_input {
  type filter hook input priority -30; policy accept;
  iifname "br-lan" ip saddr 192.168.8.0/24 udp dport 443 counter packets 3 bytes 400 reject
  iifname "br-lan" meta nfproto ipv6 udp dport 443 counter packets 2 bytes 200 reject
 }
 chain quic_tcp_fallback_forward {
  type filter hook forward priority -30; policy accept;
  iifname "br-lan" ip saddr 192.168.8.0/24 udp dport 443 counter packets 5610 bytes 7839240 reject
  iifname "br-lan" meta nfproto ipv6 udp dport 443 counter packets 7 bytes 600 reject
 }
 chain prerouting {
  iifname "br-lan" udp dport 443 counter packets 999999 bytes 999999 tproxy ip to 127.0.0.1:52346
 }
}`

func TestQUICFirewallCounterAndMode(t *testing.T) {
	count, active := parseQUICFirewall(quicNFTFixture)
	if !active || count != 5622 {
		t.Fatalf("incorrect QUIC fallback state: active=%v count=%d", active, count)
	}
	count, active = parseQUICFirewall(`table inet vpn_front { chain prerouting { ip protocol udp counter packets 666 bytes 333 accept } }`)
	if active || count != 0 {
		t.Fatalf("allow mode counted unrelated counters: active=%v count=%d", active, count)
	}
	partial := strings.Replace(quicNFTFixture, "chain quic_tcp_fallback_input", "chain disabled_quic_filter", 1)
	if _, active = parseQUICFirewall(partial); active {
		t.Fatal("incomplete fallback rules reported active")
	}
}

func TestQUICEventsAreFilteredAndReadAcrossRotations(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)
	stamp := func(offset int) string { return t0.Add(time.Duration(offset) * time.Minute).Format(time.RFC3339Nano) }
	old := strings.Join([]string{
		stamp(-30) + " source=syslog daemon.err xray[12]: [Error] transport/internet/quic: handshake failed",
		stamp(-29) + " source=syslog daemon.info xray[12]: accepted tcp:private.example:443",
		stamp(-28) + " source=diagnostics type=state-change {\"Status\":{\"quic_mode\":\"tcp-fallback\"}}",
		stamp(-27) + " source=syslog daemon.warn xray[12]: HTTP/3 handshake timeout",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "events.log.1"), []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	newer := strings.Join([]string{
		stamp(0) + " source=syslog user.notice vpn-guardian-control: QUIC mode changed to allow",
		stamp(1) + " source=syslog daemon.err xray[42]: [Error] udp:1.2.3.4:443 failed to process outbound",
		stamp(2) + " source=syslog daemon.info xray[42]: crypto_error 0x128: tls: handshake failure",
		stamp(3) + " source=syslog daemon.info xray[42]: [Error] dns failed to read response length > EOF",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "events.log"), []byte(newer), 0600); err != nil {
		t.Fatal(err)
	}
	events, ready := loadQUICEvents(dir, 20)
	if !ready || len(events) != 5 {
		t.Fatalf("got %d events ready=%v: %+v", len(events), ready, events)
	}
	if events[0].Kind != "error" || events[0].TS != t0.Add(2*time.Minute).Unix() {
		t.Fatalf("latest QUIC error not first: %+v", events[0])
	}
	if events[2].Kind != "mode-change" {
		t.Fatalf("mode changes not distinguished from errors: %+v", events[2])
	}
	limited, _ := loadQUICEvents(dir, 2)
	if len(limited) != 2 {
		t.Fatalf("unbounded events: %+v", limited)
	}
	_, available := loadQUICEvents(filepath.Join(dir, "missing"), 25)
	if available {
		t.Fatal("missing logs reported available")
	}
}

func TestQUICLogTailOmitsPartialFirstLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.log")
	content := strings.Repeat("a", 200) + "\n" + "valid last line\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	tail, err := readQUICLogTail(path, 40)
	if err != nil || string(tail) != "valid last line\n" {
		t.Fatalf("partial first line leaked: %q, %v", tail, err)
	}
}

func TestQUICManagementReadRequiresAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/quic", nil)
	rec := httptest.NewRecorder()
	handleQUICHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated QUIC diagnostics status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "events") || strings.Contains(rec.Body.String(), "nft") {
		t.Fatalf("unauthenticated response revealed sensitive diagnostics: %q", rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodPost, "/api/quic", nil)
	rec = httptest.NewRecorder()
	handleQUICHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/quic status = %d", rec.Code)
	}
}

func TestQUICControlRejectsInvalidMode(t *testing.T) {
	for _, mode := range []string{"", "invalid", "drop", "off", "ALLOW"} {
		_, err := executeControlAction(controlRequest{Action: "quic_mode", QUICMode: mode})
		if err == nil {
			t.Fatalf("invalid mode %q accepted", mode)
		}
	}
	event, ok := quicEventFromLine(fmt.Sprintf("%s source=syslog daemon.info xray[1]: successful connection to http/3", time.Now().UTC().Format(time.RFC3339Nano)))
	if ok || event.Kind != "" {
		t.Fatalf("successful HTTP/3 event incorrectly labeled error: %#v", event)
	}
}
