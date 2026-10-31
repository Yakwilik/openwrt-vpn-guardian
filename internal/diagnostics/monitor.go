package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
)

const (
	defaultInterval = 10 * time.Second
	heartbeatEvery  = 60 * time.Second
	probeEvery      = 2 * time.Minute
)

type healthStatus struct {
	Now           int64             `json:"now"`
	Overall       string            `json:"overall"`
	Node          string            `json:"node"`
	VPNIP         string            `json:"vpn_ip"`
	HomeIP        string            `json:"home_ip"`
	HealthCount   int               `json:"health_count"`
	HealthTotal   int               `json:"health_total"`
	HealthStatus  string            `json:"health_status"`
	DNSHealthy    bool              `json:"dns_healthy"`
	TProxyActive  bool              `json:"tproxy_active"`
	PolicyRuntime string            `json:"policy_runtime"`
	ControlMode   string            `json:"control_mode"`
	Services      map[string]string `json:"services"`
}

type snapshot struct {
	Time             string           `json:"time"`
	BootID           string           `json:"boot_id,omitempty"`
	UptimeSeconds    int64            `json:"uptime_seconds,omitempty"`
	StatusAgeSeconds int64            `json:"status_age_seconds,omitempty"`
	StatusError      string           `json:"status_error,omitempty"`
	Status           healthStatus     `json:"status"`
	Processes        map[string][]int `json:"processes"`
	Conntrack        int64            `json:"conntrack"`
	ConntrackMax     int64            `json:"conntrack_max"`
	MemAvailableKB   int64            `json:"mem_available_kb"`
}

func Run(args []string) error {
	fs := flag.NewFlagSet("vpn-guardian diagnostics", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	mode := fs.String("mode", "daemon", "daemon|once")
	interval := fs.Duration("interval", defaultInterval, "process and status sampling interval")
	dir := fs.String("dir", paths.DiagnosticsDir, "persistent log directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("diagnostics accepts no positional arguments")
	}
	switch *mode {
	case "once":
		return json.NewEncoder(os.Stdout).Encode(collectSnapshot(paths.StatusCache, "/proc", time.Now()))
	case "daemon":
		if *interval < 5*time.Second || *interval > 5*time.Minute {
			return fmt.Errorf("diagnostics interval must be between 5s and 5m")
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return runDaemon(ctx, *dir, *interval, paths.StatusCache, "/proc")
	default:
		return fmt.Errorf("unknown diagnostics mode %q", *mode)
	}
}

func runDaemon(ctx context.Context, dir string, interval time.Duration, cache, proc string) error {
	events, err := newRotatedLog(dir, "events.log", maxLogBytes, logBackups)
	if err != nil {
		return err
	}
	defer events.Close()
	health, err := newRotatedLog(dir, "health.jsonl", maxLogBytes, logBackups)
	if err != nil {
		return err
	}
	defer health.Close()
	probes, err := newRotatedLog(dir, "probes.jsonl", maxLogBytes, logBackups)
	if err != nil {
		return err
	}
	defer probes.Close()
	started := time.Now()
	_ = events.WriteLine(started.UTC().Format(time.RFC3339Nano) + " source=diagnostics type=start version=1 persistent=true")
	_ = health.WriteLine(mustJSON(collectSnapshot(cache, proc, started)))
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		followSyslog(ctx, events)
	}()
	defer workers.Wait() // drain writers before closing rotated files.

	watcher := newStateWatcher(heartbeatEvery)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	nextProbe := started
	for {
		now := time.Now()
		snap := collectSnapshot(cache, proc, now)
		if event, heartbeat := watcher.observe(snap, now); event != "" || heartbeat {
			if event != "" {
				if err := events.WriteLine(now.UTC().Format(time.RFC3339Nano) + " source=diagnostics type=state-change " + event); err != nil {
					fmt.Fprintln(os.Stderr, "diagnostics event:", err)
				}
			}
			if err := health.WriteLine(mustJSON(snap)); err != nil {
				fmt.Fprintln(os.Stderr, "diagnostics health:", err)
			}
		}
		if !now.Before(nextProbe) {
			// Probes have bounded timeouts, do not mutate routes or select VPN
			// nodes, and record only response codes/errors (no page bodies).
			nextProbe = now.Add(probeEvery)
			workers.Add(1)
			go func() {
				defer workers.Done()
				out := collectProbes(ctx, time.Now())
				if err := probes.WriteLine(mustJSON(out)); err != nil {
					fmt.Fprintln(os.Stderr, "diagnostics probes:", err)
				}
			}()
		}

		select {
		case <-ctx.Done():
			_ = events.WriteLine(time.Now().UTC().Format(time.RFC3339Nano) + " source=diagnostics type=shutdown")
			_ = events.Sync()
			_ = health.Sync()
			_ = probes.Sync()
			return nil
		case <-ticker.C:
		}
	}
}

func mustJSON(value any) string {
	b, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("{\"error\":%q}", err)
	}
	return string(b)
}

type stateWatcher struct {
	lastFingerprint string
	lastHeartbeat   time.Time
	heartbeat       time.Duration
}

func newStateWatcher(heartbeat time.Duration) *stateWatcher {
	return &stateWatcher{heartbeat: heartbeat}
}

func (w *stateWatcher) observe(s snapshot, now time.Time) (event string, heartbeat bool) {
	// Ignore timestamp and resource counters when tracking state transitions.
	// A process PID or a stale collector update is significant; normal
	// conntrack fluctuation and memory cache churn are not.
	state := s.Status
	state.Now = 0 // collector refresh timestamps are not state changes.
	fingerprint := struct {
		Status healthStatus
		Error  string
		Stale  bool
		PIDs   map[string][]int
	}{state, s.StatusError, s.StatusAgeSeconds > 20, s.Processes}
	encoded := mustJSON(fingerprint)
	changed := encoded != w.lastFingerprint
	if changed {
		event = encoded
		w.lastFingerprint = encoded
	}
	if changed || w.lastHeartbeat.IsZero() || now.Sub(w.lastHeartbeat) >= w.heartbeat {
		w.lastHeartbeat = now
		return event, true
	}
	return "", false
}

func collectSnapshot(cache, proc string, now time.Time) snapshot {
	s := snapshot{
		Time:           now.UTC().Format(time.RFC3339Nano),
		BootID:         readTrimmed(filepath.Join(proc, "sys/kernel/random/boot_id")),
		Processes:      processPIDs(proc),
		Conntrack:      readNumber(filepath.Join(proc, "sys/net/netfilter/nf_conntrack_count")),
		ConntrackMax:   readNumber(filepath.Join(proc, "sys/net/netfilter/nf_conntrack_max")),
		MemAvailableKB: availableMemory(filepath.Join(proc, "meminfo")),
	}
	if uptime, err := os.ReadFile(filepath.Join(proc, "uptime")); err == nil {
		fields := strings.Fields(string(uptime))
		if len(fields) != 0 {
			if sec, err := strconv.ParseFloat(fields[0], 64); err == nil {
				s.UptimeSeconds = int64(sec)
			}
		}
	}
	content, err := os.ReadFile(cache)
	if err != nil {
		s.StatusError = err.Error()
		return s
	}
	if err := json.Unmarshal(content, &s.Status); err != nil {
		s.StatusError = "status cache contains malformed JSON"
		return s
	}
	if s.Status.Now == 0 {
		s.StatusError = "status cache has no timestamp"
		return s
	}
	s.StatusAgeSeconds = int64(now.Sub(time.Unix(s.Status.Now, 0)).Seconds())
	if s.StatusAgeSeconds < 0 {
		s.StatusAgeSeconds = 0
	}
	return s
}

func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readNumber(path string) int64 {
	n, _ := strconv.ParseInt(readTrimmed(path), 10, 64)
	return n
}

func availableMemory(path string) int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == "MemAvailable:" {
			value, _ := strconv.ParseInt(fields[1], 10, 64)
			return value
		}
	}
	return 0
}

func processPIDs(proc string) map[string][]int {
	entries, err := os.ReadDir(proc)
	if err != nil {
		return map[string][]int{}
	}
	out := make(map[string][]int)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(proc, entry.Name(), "cmdline"))
		if err != nil {
			continue
		}
		service := classifyProcess(strings.Split(string(raw), "\x00"))
		if service != "" {
			out[service] = append(out[service], pid)
		}
	}
	for name := range out {
		sort.Ints(out[name])
	}
	return out
}

func classifyProcess(args []string) string {
	if len(args) == 0 {
		return ""
	}
	bin := filepath.Base(args[0])
	command := strings.Join(args[1:], " ")
	switch bin {
	case "xray":
		switch {
		case strings.Contains(command, "/generated/front.json"):
			return "vpn-front"
		case strings.Contains(command, "/generated/policy.json"):
			return "vpn-policy"
		case strings.Contains(command, "/generated/dns-xray.json"):
			return "vpn-dns-xray"
		case strings.Contains(command, "/etc/xray/"):
			return "xray"
		}
	case "vpn-guardian":
		if len(args) >= 2 {
			switch args[1] {
			case "watchdog", "collector", "api-server", "dns-proxy":
				return "vpn-guardian-" + args[1]
			}
		}
	case "v2raya_core":
		return "v2raya-core"
	case "v2raya":
		return "v2raya"
	case "dnsmasq":
		return "dnsmasq"
	}
	return ""
}
