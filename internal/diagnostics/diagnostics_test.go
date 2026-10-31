package diagnostics

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRotatingLogBoundsDiskAndPreservesLastEvents(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "persistent")
	log, err := newRotatedLog(dir, "events.log", 1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "LAST EVENT SURVIVES"
	for i := 0; i < 100; i++ {
		payload := strings.Repeat("x", 90) + " marker"
		if i == 99 {
			payload = expected
		}
		if err := log.WriteLine(payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("want active and 3 rotations, got %d files", len(entries))
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > 1024 || info.Mode().Perm() != 0600 {
			t.Errorf("%s size=%d mode=%v", entry.Name(), info.Size(), info.Mode())
		}
	}
	if dirStat, err := os.Stat(dir); err != nil || dirStat.Mode().Perm() != 0700 {
		t.Fatalf("directory must be private: %v %v", dirStat, err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "events.log"))
	if err != nil || !bytes.Contains(b, []byte(expected)) {
		t.Fatalf("most recent event lost: %s %v", b, err)
	}
	// Reopen must append, preserving incidents across daemon restarts.
	reopened, err := newRotatedLog(dir, "events.log", 1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.WriteLine("after restart"); err != nil {
		t.Fatal(err)
	}
	_ = reopened.Close()
	b, _ = os.ReadFile(filepath.Join(dir, "events.log"))
	if !bytes.Contains(b, []byte(expected)) || !bytes.Contains(b, []byte("after restart")) {
		t.Fatalf("restart discarded logs: %s", b)
	}
}

func TestRotatingLogRejectsSymlinks(t *testing.T) {
	dir := t.TempDir()
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := newRotatedLog(alias, "events.log", 1024, 2); err == nil {
		t.Fatal("symlinked log directory accepted")
	}
	dest := filepath.Join(dir, "private.txt")
	if err := os.WriteFile(dest, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dest, filepath.Join(dir, "events.log")); err != nil {
		t.Fatal(err)
	}
	if _, err := newRotatedLog(dir, "events.log", 1024, 2); err == nil {
		t.Fatal("symlinked log file accepted")
	}
}

func TestConcurrentLogWritesRemainWhole(t *testing.T) {
	log, err := newRotatedLog(t.TempDir(), "events.log", 1<<20, 3)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for id := 0; id < 8; id++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				if err := log.WriteLine("line from worker"); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	_ = log.Close()
	data, err := os.ReadFile(log.path)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(strings.Split(strings.TrimSpace(string(data)), "\n")); got != 800 {
		t.Fatalf("concurrent writes lost or split lines: %d", got)
	}
}

func TestLogreadFilterRetainsErrorsWithoutVerboseTraffic(t *testing.T) {
	fixtures := []struct {
		text string
		want bool
	}{
		{"daemon.info xray[111]: accepted tcp:example.com:443", false},
		{"daemon.info xray[111]: [dns-query -> vpn-backend]", false},
		{"daemon.err xray[111]: failed to process packet: EOF", true},
		{"daemon.info dnsmasq[7]: reply 0.0.0.0", false},
		{"daemon.err dnsmasq[7]: upstream server unavailable", true},
		{"daemon.info vpn-guardian-watchdog: switched successfully id=17", true},
		{"daemon.info vpn-guardian-control: policy runtime -> killswitch-blocked", true},
		{"daemon.info vpn-guardian-diagnostics: daemon started", false},
		{"kern.err kernel: nf_conntrack: table full", true},
		{"daemon.info xray[13]: accepted udp:secret.example:443", false},
	}
	var data strings.Builder
	for _, tc := range fixtures {
		if got := relevantSyslog(tc.text); got != tc.want {
			t.Errorf("filter(%q) = %v, want %v", tc.text, got, tc.want)
		}
		data.WriteString(tc.text + "\n")
	}
	log, err := newRotatedLog(t.TempDir(), "events.log", 64*1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := scanSyslog(strings.NewReader(data.String()), log); err != nil {
		t.Fatal(err)
	}
	_ = log.Close()
	stored, _ := os.ReadFile(log.path)
	if !bytes.Contains(stored, []byte("nf_conntrack")) ||
		bytes.Contains(stored, []byte("accepted tcp:")) {
		t.Fatalf("unexpected persisted log content: %q", stored)
	}
	redacted := cleanSyslog("xray error https://example.com/path?auth=secret123 token=abc123 password=qwe")
	if strings.Contains(redacted, "secret123") || strings.Contains(redacted, "abc123") || strings.Contains(redacted, "qwe") {
		t.Fatalf("sensitive query and values survived: %q", redacted)
	}
}

func TestStateWatcherIgnoresTimestampAndResourceCounters(t *testing.T) {
	w := newStateWatcher(60 * time.Second)
	now := time.Unix(10000, 0)
	s := snapshot{Status: healthStatus{Now: 10000, Overall: "ok", Node: "node-A"},
		Processes: map[string][]int{"vpn-front": {123}}}
	if event, _ := w.observe(s, now); event == "" {
		t.Fatal("initial state not persisted")
	}
	s.Status.Now = 10010
	s.Conntrack = 1050
	s.MemAvailableKB = 600000
	if event, heartbeat := w.observe(s, now.Add(10*time.Second)); event != "" || heartbeat {
		t.Fatalf("normal resource fluctuations caused flash writes: event=%s heartbeat=%v", event, heartbeat)
	}
	s.Processes["vpn-front"] = []int{222}
	if event, _ := w.observe(s, now.Add(15*time.Second)); event == "" {
		t.Fatal("process replacement not logged")
	}
	s.Status.Overall = "down"
	if event, _ := w.observe(s, now.Add(20*time.Second)); event == "" {
		t.Fatal("health outage not logged")
	}
	if event, heartbeat := w.observe(s, now.Add(82*time.Second)); event != "" || !heartbeat {
		t.Fatal("periodic heartbeat did not record ongoing state")
	}
}

func TestSnapshotTracksProcessAndStaleStatus(t *testing.T) {
	dir := t.TempDir()
	proc := filepath.Join(dir, "proc")
	if err := os.MkdirAll(filepath.Join(proc, "123"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "123", "cmdline"),
		[]byte("/usr/bin/xray\x00run\x00-config\x00/etc/vpn-guardian/generated/front.json\x00"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(proc, "sys", "net", "netfilter"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "sys", "net", "netfilter", "nf_conntrack_count"), []byte("42\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(proc, "meminfo"), []byte("MemAvailable:       98765 kB\n"), 0600)
	cache := filepath.Join(dir, "status.json")
	b, _ := json.Marshal(healthStatus{Now: 10000, Overall: "ok", Node: "N", Services: map[string]string{"front": "running"}})
	if err := os.WriteFile(cache, b, 0600); err != nil {
		t.Fatal(err)
	}
	s := collectSnapshot(cache, proc, time.Unix(10029, 0))
	if s.Status.Overall != "ok" || s.StatusAgeSeconds != 29 ||
		s.MemAvailableKB != 98765 || s.Conntrack != 42 ||
		len(s.Processes["vpn-front"]) != 1 || s.Processes["vpn-front"][0] != 123 {
		t.Fatalf("snapshot fields lost: %+v", s)
	}
	if err := os.WriteFile(cache, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := collectSnapshot(cache, proc, time.Now()); got.StatusError == "" {
		t.Fatal("malformed status cache not detected")
	}
}

func TestDiagnosticsRejectsBadModeAndInterval(t *testing.T) {
	if err := Run([]string{"-mode", "unknown"}); err == nil {
		t.Fatal("unsupported diagnostics mode accepted")
	}
	if err := Run([]string{"-mode", "daemon", "-interval", "1s"}); err == nil {
		t.Fatal("unbounded fast diagnostic writes accepted")
	}
	if err := Run([]string{"unexpected"}); err == nil {
		t.Fatal("positional args accepted")
	}
}

func TestCancelledHTTPProbeIsBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := probeHTTP(ctx, "probe", "direct", "https://example.com")
	if p.Error == "" {
		t.Fatal("canceled probe must report an error")
	}
}
