package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultStackValidates(t *testing.T) {
	cfg := DefaultStack("br-lan", "192.168.8.0/24", "eth1", "/usr/share/xray")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default stack must validate: %v", err)
	}
}

func TestStackValidation(t *testing.T) {
	base := DefaultStack("br-lan", "192.168.8.0/24", "eth1", "/usr/share/xray")

	tests := []struct {
		name   string
		mutate func(*Stack)
	}{
		{
			name: "missing lan interface",
			mutate: func(s *Stack) {
				s.LANInterface = ""
			},
		},
		{
			name: "missing wan interface",
			mutate: func(s *Stack) {
				s.WANInterface = ""
			},
		},
		{
			name: "invalid backend port",
			mutate: func(s *Stack) {
				s.Backend.SocksPort = 0
			},
		},
		{
			name: "invalid front port",
			mutate: func(s *Stack) {
				s.Front.TProxyPort = 70000
			},
		},
		{
			name: "invalid route table",
			mutate: func(s *Stack) {
				s.Front.RouteTable = 0
			},
		},
		{
			name: "invalid policy",
			mutate: func(s *Stack) {
				s.Policy.Default = "unknown"
			},
		},
		{
			name: "zero watchdog interval",
			mutate: func(s *Stack) {
				s.Backend.WatchdogInterval = "0s"
			},
		},
		{
			name: "invalid collector interval",
			mutate: func(s *Stack) {
				s.Dashboard.CollectorInterval = "never"
			},
		},
		{
			name: "empty bypass list",
			mutate: func(s *Stack) {
				s.Bypass4 = nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			cfg.Bypass4 = append([]string(nil), base.Bypass4...)
			tt.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected validation failure")
			}
		})
	}
}

func TestRoutingValidation(t *testing.T) {
	routing := DefaultRouting()
	if err := routing.Validate(); err != nil {
		t.Fatalf("default routing must validate: %v", err)
	}

	routing.Version++
	if err := routing.Validate(); err == nil {
		t.Fatal("expected unsupported routing version to fail")
	}
}

func TestExampleManifestsValidate(t *testing.T) {
	if _, _, err := LoadFiles("../../configs/stack.example.json", "../../configs/routing.example.json"); err != nil {
		t.Fatalf("packaged example manifests must validate: %v", err)
	}
}

func TestSaveStackFileIsAtomicAndValidated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stack.json")
	cfg := DefaultStack("br-lan", "192.168.8.0/24", "eth1", "/usr/share/xray")
	cfg.Selection.AllowedTransports = []Transport{TransportVLESSXHTTPReality}

	if err := saveStackFile(path, cfg); err != nil {
		t.Fatalf("save valid stack: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved stack: %v", err)
	}

	invalid := cfg
	invalid.Selection.AllowedTransports = nil
	if err := saveStackFile(path, invalid); err == nil {
		t.Fatal("invalid stack must not be saved")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read stack after rejected save: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("rejected save changed existing stack file")
	}

	var loaded Stack
	if err := readJSON(path, &loaded); err != nil {
		t.Fatalf("decode saved stack: %v", err)
	}
	if len(loaded.Selection.AllowedTransports) != 1 ||
		loaded.Selection.AllowedTransports[0] != TransportVLESSXHTTPReality {
		t.Fatalf("saved selection = %v", loaded.Selection.AllowedTransports)
	}
}
