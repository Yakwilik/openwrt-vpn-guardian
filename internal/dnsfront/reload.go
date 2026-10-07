package dnsfront

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"time"
)

// Use the object selected by the running instance's generated configuration;
// OpenWrt may name it dnsmasq or dnsmasq.<section>.
func nativeUBusObject(configuration []byte) (string, error) {
	var object string
	for _, raw := range strings.Split(string(configuration), "\n") {
		line := strings.TrimPrefix(strings.TrimSpace(raw), "--")
		var candidate string
		if line == "enable-ubus" {
			candidate = "dnsmasq"
		} else if value, ok := strings.CutPrefix(line, "enable-ubus="); ok {
			candidate = strings.TrimSpace(value)
		} else {
			continue
		}
		if candidate == "" || strings.ContainsAny(candidate, " \t\r\x00/\\\"'") {
			return "", errors.New("invalid native dnsmasq UBus object")
		}
		if object != "" && candidate != object {
			return "", errors.New("ambiguous native dnsmasq UBus object")
		}
		object = candidate
	}
	if object == "" {
		return "", errors.New("native selector acknowledgement requires enable-ubus in dnsmasq configuration")
	}
	return object, nil
}

// Resolve the acknowledgement mechanism before publishing any bytes. A binary
// advertising the capability must acknowledge the real apply; delivery of a
// signal or an unrelated service response is never an acceptable substitute.
func selectorReloadAction(s State, port int) (func() error, error) {
	version, err := command("dnsmasq", "--version")
	if err != nil {
		return nil, err
	}
	if slices.Contains(strings.Fields(string(version)), "regex-server-ack") {
		configuration, err := os.ReadFile(s.MainConfig)
		if err != nil {
			return nil, err
		}
		object, err := nativeUBusObject(configuration)
		if err != nil {
			return nil, err
		}
		return func() error {
			_, err := command("ubus", "-t", "10", "call", object, "reload_servers")
			if err != nil {
				return fmt.Errorf("acknowledge native DNS selectors: %w", err)
			}
			return nil
		}, nil
	}
	// Stock dnsmasq cannot acknowledge a servers-file reload. Restart it and
	// check the replacement instance instead of pretending that HUP is an ack.
	return func() error {
		if _, err := command("/etc/init.d/dnsmasq", "restart"); err != nil {
			return err
		}
		if err := LinkBootstrap(); err != nil {
			return err
		}
		return waitNativeDNSReady(port)
	}, nil
}

func waitNativeDNSReady(port int) error {
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:53", 150*time.Millisecond)
		if err == nil {
			conn.Close()
			return Check(port)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("native dnsmasq did not become ready")
}

func publishSelectors(path string, selectors []byte, reload func() error) error {
	previous, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	changed := !bytes.Equal(previous, selectors)
	if changed {
		if err := atomicWrite(path, selectors, 0644); err != nil {
			return err
		}
	}
	// Identical selectors may accompany a stricter resolver/cache policy.
	if err := reload(); err != nil {
		if !changed {
			return err
		}
		if restoreErr := atomicWrite(path, previous, 0644); restoreErr != nil {
			return errors.Join(err, fmt.Errorf("restore native DNS selectors: %w", restoreErr))
		}
		return errors.Join(err, reload())
	}
	return nil
}
