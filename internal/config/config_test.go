package config

import "testing"

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
