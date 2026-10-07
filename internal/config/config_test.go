package config

import (
	"bytes"
	"encoding/json"
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

func TestDNSDefaultsAndValidation(t *testing.T) {
	cfg := DefaultStack("br-lan", "192.168.8.0/24", "eth1", "/usr/share/xray")
	if cfg.DNS.Mode != DNSModeCustom || cfg.DNS.ListenPort != 20176 || cfg.DNS.XrayPort != 20178 {
		t.Fatalf("default DNS = %#v", cfg.DNS)
	}
	if len(cfg.DNS.Resolvers) != 2 {
		t.Fatalf("default resolvers = %v", cfg.DNS.Resolvers)
	}

	tests := []struct {
		name      string
		resolvers []string
	}{
		{name: "hostname", resolvers: []string{"dns.example.com"}},
		{name: "ipv6", resolvers: []string{"2606:4700:4700::1111"}},
		{name: "bad port", resolvers: []string{"1.1.1.1:0"}},
		{name: "duplicate canonical endpoint", resolvers: []string{"1.1.1.1", "1.1.1.1:53"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := cfg
			candidate.DNS.Resolvers = tt.resolvers
			if err := candidate.Validate(); err == nil {
				t.Fatal("expected DNS validation failure")
			}
		})
	}
}

func TestLoadFilesNormalizesLegacyV1DNS(t *testing.T) {
	dir := t.TempDir()
	stackPath := filepath.Join(dir, "stack.json")
	routingPath := filepath.Join(dir, "routing.json")

	stack := DefaultStack("br-lan", "192.168.8.0/24", "eth1", "/usr/share/xray")
	data, err := json.Marshal(stack)
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatal(err)
	}
	delete(legacy, "dns")
	data, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stackPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	routingData, err := json.Marshal(DefaultRouting())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(routingPath, routingData, 0600); err != nil {
		t.Fatal(err)
	}

	loaded, _, err := LoadFiles(stackPath, routingPath)
	if err != nil {
		t.Fatalf("legacy v1 manifest failed to load: %v", err)
	}
	want := DefaultClientDNS()
	if loaded.DNS.Mode != want.Mode || loaded.DNS.ListenPort != want.ListenPort ||
		len(loaded.DNS.Resolvers) != len(want.Resolvers) {
		t.Fatalf("normalized DNS = %#v, want %#v", loaded.DNS, want)
	}
}

func TestNormalizeLegacyVPNModeToCustom(t *testing.T) {
	cfg := DefaultStack("br-lan", "192.168.8.0/24", "eth1", "/usr/share/xray")
	cfg.DNS.Mode = "vpn"
	cfg.DNS.XrayPort = 0
	normalized := NormalizeStack(cfg)
	if normalized.DNS.Mode != DNSModeCustom || normalized.DNS.XrayPort != 20178 {
		t.Fatalf("legacy DNS normalized to %#v", normalized.DNS)
	}
}
