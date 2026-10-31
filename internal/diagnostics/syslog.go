package diagnostics

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var (
	queryString = regexp.MustCompile("(?i)(https?://[^?\\s\"']+)\\?[^\\s\"']+")
	secretValue = regexp.MustCompile("(?i)(password|token|secret|authorization|cookie|api[_-]?key)([=:]\\s*)[^\\s,;]+")
)

// Persist exceptional messages, never verbose Xray connection-accept logs or
// DNS query streams. These can reveal browser history and fill flash rapidly.
func relevantSyslog(line string) bool {
	s := strings.ToLower(line)
	if strings.Contains(s, "vpn-guardian-diagnostics") {
		return false
	}
	if strings.Contains(s, "oom-killer") || strings.Contains(s, "out of memory") ||
		strings.Contains(s, "nf_conntrack: table full") || strings.Contains(s, "i/o error") ||
		strings.Contains(s, "overlayfs:") {
		return true
	}
	guardian := strings.Contains(s, "vpn-guardian-watchdog") ||
		strings.Contains(s, "vpn-guardian-control") ||
		strings.Contains(s, "vpn-guardian-dns") ||
		strings.Contains(s, "vpn-backend-watchdog") ||
		strings.Contains(s, "vpn-front") ||
		strings.Contains(s, "vpn-policy") ||
		strings.Contains(s, "vpn-dashboard-collector")
	if guardian && (strings.Contains(s, "vpn-guardian-watchdog") || strings.Contains(s, "vpn-guardian-control")) {
		return true
	}
	services := guardian || strings.Contains(s, "xray[") || strings.Contains(s, "v2raya") ||
		strings.Contains(s, "dnsmasq[") || strings.Contains(s, "procd:") ||
		strings.Contains(s, "netifd:")
	if !services {
		return false
	}
	if strings.Contains(s, "accepted tcp:") || strings.Contains(s, "accepted udp:") ||
		strings.Contains(s, "dns-query ->") {
		return false
	}
	if strings.Contains(s, "daemon.err ") || strings.Contains(s, "daemon.warn ") ||
		strings.Contains(s, "kern.err ") || strings.Contains(s, "kern.warn ") {
		return true
	}
	// Do not persist verbose debug/info messages that reveal visited hosts.
	for _, problem := range []string{
		"error", "warn", "failed", "failure", "timeout", "unreachable",
		"panic", "fatal", "crash", "exited", "respawn", "restarting",
		"stopped", "killed", "refused", "disconnected", "link down",
		"interface down", "network down", "backend unavailable",
	} {
		if strings.Contains(s, problem) {
			return true
		}
	}
	return false
}

func cleanSyslog(line string) string {
	line = queryString.ReplaceAllString(line, "${1}?[redacted]")
	return secretValue.ReplaceAllString(line, "${1}${2}[redacted]")
}

// Follow logd's in-memory ring and persist selected events as they happen.
// A logread crash is not allowed to terminate the snapshot monitor. The
// restart marker lets an operator distinguish missing syslog from quiet logs.
func followSyslog(ctx context.Context, events *rotatedLog) {
	for ctx.Err() == nil {
		err := streamSyslog(ctx, events)
		if ctx.Err() != nil {
			return
		}
		detail := "logread stream exited"
		if err != nil {
			detail = fmt.Sprintf("logread stream exited: %s", err)
		}
		if writeErr := events.WriteLine(time.Now().UTC().Format(time.RFC3339Nano) + " source=diagnostics type=logread-error " + cleanSyslog(detail)); writeErr != nil {
			fmt.Fprintln(os.Stderr, "diagnostics log write:", writeErr)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func streamSyslog(ctx context.Context, events *rotatedLog) error {
	// -l 0 requests only new messages so a procd restart does not duplicate
	// historical ring contents.
	cmd := exec.CommandContext(ctx, "logread", "-f", "-l", "0")
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	scanner := bufio.NewScanner(pipe)
	scanner.Buffer(make([]byte, 4096), 256*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !relevantSyslog(line) {
			continue
		}
		if err := events.WriteLine(time.Now().UTC().Format(time.RFC3339Nano) + " source=syslog " + cleanSyslog(line)); err != nil {
			fmt.Fprintln(os.Stderr, "diagnostics syslog storage:", err)
		}
	}
	scanErr := scanner.Err()
	waitErr := cmd.Wait()
	if scanErr != nil {
		return scanErr
	}
	return waitErr
}

// scanSyslog is separated to permit deterministic filter tests without procd.
func scanSyslog(r io.Reader, out *rotatedLog) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 256*1024)
	for scanner.Scan() {
		if relevantSyslog(scanner.Text()) {
			if err := out.WriteLine(cleanSyslog(scanner.Text())); err != nil {
				return err
			}
		}
	}
	return scanner.Err()
}
