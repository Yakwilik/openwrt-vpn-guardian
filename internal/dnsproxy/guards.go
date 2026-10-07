package dnsproxy

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// EnsureLocalGuards adds only no-forward zones, never changes the resolver
// list, DHCP ranges or networking. dnsmasq must own negative answers for local
// zones too; sending a local question to dnsmasq alone does not prevent leaks.
func dnsmasqConfigDir() (string, string, error) {
	configs, err := filepath.Glob("/var/etc/dnsmasq.conf.*")
	if err != nil {
		return "", "", err
	}
	for _, main := range configs {
		b, err := os.ReadFile(main)
		if err != nil {
			return "", "", err
		}
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(line, "conf-dir=") {
				continue
			}
			directory := strings.Split(strings.TrimPrefix(line, "conf-dir="), ",")[0]
			if filepath.IsAbs(directory) {
				return main, directory, nil
			}
		}
	}
	return "", "", fmt.Errorf("dnsmasq requires a configured conf-dir for local no-forward zones")
}

func EnsureLocalGuards() error {
	main, directory, err := dnsmasqConfigDir()
	if err != nil {
		return err
	}
	local, err := LocalNames("/")
	if err != nil {
		return err
	}
	data := renderLocalGuards(local)
	path := filepath.Join(directory, "vpn-guardian-local.conf")
	old, readErr := os.ReadFile(path)
	if readErr == nil && bytes.Equal(old, data) {
		return nil
	}
	if readErr != nil && !os.IsNotExist(readErr) {
		return readErr
	}
	if err := os.MkdirAll(directory, 0755); err != nil {
		return err
	}
	if err := os.WriteFile(path+".new", data, 0644); err != nil {
		return err
	}
	// dnsmasq ignores *.new only when configured with a pattern, so remove the
	// staging name before asking dnsmasq to parse the complete actual config.
	if err := os.Rename(path+".new", path); err != nil {
		return err
	}
	restore := func() {
		if readErr == nil {
			_ = os.WriteFile(path, old, 0644)
		} else {
			_ = os.Remove(path)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "dnsmasq", "--test", "--conf-file="+main).CombinedOutput(); err != nil {
		restore()
		return fmt.Errorf("local DNS guard validation: %w: %s", err, out)
	}
	if out, err := exec.CommandContext(ctx, "/etc/init.d/dnsmasq", "restart").CombinedOutput(); err != nil {
		restore()
		return fmt.Errorf("restart local resolver: %w: %s", err, out)
	}
	return nil
}

func RemoveLocalGuards() error {
	_, directory, err := dnsmasqConfigDir()
	if err != nil {
		return err
	}
	path := filepath.Join(directory, "vpn-guardian-local.conf")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "/etc/init.d/dnsmasq", "restart").CombinedOutput(); err != nil {
		return fmt.Errorf("restart local resolver after guard cleanup: %w: %s", err, out)
	}
	return nil
}

func renderLocalGuards(local *DomainMatcher) []byte {
	zones := map[string]bool{}
	add := func(zone string) {
		if !strings.Contains(zone, ".") {
			if _, isSuffix := local.suffix[zone]; !isSuffix {
				return
			}
		}
		if zone == "" || strings.ContainsAny(zone, "/\n\r\t #=,*") || local.internalForward[zone] {
			return
		}
		// Explicit internal split-DNS forwarding remains authoritative for its zone.
		for forward := range local.internalForward {
			if zone == forward || strings.HasSuffix(zone, "."+forward) {
				return
			}
		}
		zones[zone] = true
	}
	for zone := range local.suffix {
		add(zone)
	}
	for name := range local.full {
		add(name)
	}
	names := make([]string, 0, len(zones))
	for zone := range zones {
		names = append(names, zone)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("# Managed by vpn-guardian: local negative answers must not leave dnsmasq.\ndomain-needed\n")
	for _, zone := range names {
		redundant := false
		for _, parent := range names {
			if zone != parent && strings.HasSuffix(zone, "."+parent) {
				redundant = true
				break
			}
		}
		if !redundant {
			fmt.Fprintf(&b, "local=/%s/\n", zone)
		}
	}
	return []byte(b.String())
}
