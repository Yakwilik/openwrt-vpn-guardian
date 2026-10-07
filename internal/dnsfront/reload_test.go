package dnsfront

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeUBusObjectUsesGeneratedInstance(t *testing.T) {
	for _, tt := range []struct{ config, want string }{
		{"enable-ubus\n", "dnsmasq"},
		{"# ignored\nenable-ubus=dnsmasq.cfg123\n", "dnsmasq.cfg123"},
		{"--enable-ubus=dnsmasq.lan\n", "dnsmasq.lan"},
		{"# enable-ubus=wrong\n", ""},
		{"enable-ubus=\n", ""},
		{"enable-ubus=dnsmasq.one\nenable-ubus=dnsmasq.two\n", ""},
	} {
		got, err := nativeUBusObject([]byte(tt.config))
		if got != tt.want || (err != nil) != (tt.want == "") {
			t.Fatalf("object for %q = %q, %v; want %q", tt.config, got, err, tt.want)
		}
	}
}

func TestSelectorReloadActionRequiresActualDaemonAcknowledgement(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	for name, script := range map[string]string{
		"dnsmasq": "#!/bin/sh\nprintf '%s\\n' 'Compile time options: UBus regex-server regex-server-ack'\n",
		"ubus":    "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$GUARDIAN_ACK_TEST_LOG\"\n[ \"${GUARDIAN_ACK_TEST_FAIL:-0}\" = 0 ]\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GUARDIAN_ACK_TEST_LOG", log)
	config := filepath.Join(dir, "main.conf")
	if err := os.WriteFile(config, []byte("enable-ubus=dnsmasq.lan7\n"), 0600); err != nil {
		t.Fatal(err)
	}
	reload, err := selectorReloadAction(State{MainConfig: config}, 20176)
	if err != nil {
		t.Fatal(err)
	}
	if err := reload(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDIAN_ACK_TEST_FAIL", "1")
	if err := reload(); err == nil {
		t.Fatal("failed daemon acknowledgement was accepted")
	}
	calls, err := os.ReadFile(log)
	if err != nil || string(calls) != strings.Repeat("-t 10 call dnsmasq.lan7 reload_servers\n", 2) {
		t.Fatalf("called an unrelated service or async signal: %s, %v", calls, err)
	}
}

func TestPublishSelectorsWaitsForAcknowledgement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.servers")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- publishSelectors(path, []byte("new"), func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("publication did not request acknowledgement")
	}
	select {
	case err := <-done:
		close(release)
		t.Fatalf("publication returned before daemon acknowledgement: %v", err)
	default:
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPublishSelectorsAcknowledgesRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.servers")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	rejected := errors.New("daemon rejected candidate")
	var seen []string
	err := publishSelectors(path, []byte("new"), func() error {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		seen = append(seen, string(data))
		if len(seen) == 1 {
			return rejected
		}
		return nil
	})
	if !errors.Is(err, rejected) || strings.Join(seen, ",") != "new,old" {
		t.Fatalf("rollback was not applied and acknowledged: %v, %v", seen, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "old" {
		t.Fatalf("rejected selectors remain active on disk: %q, %v", data, err)
	}
}
