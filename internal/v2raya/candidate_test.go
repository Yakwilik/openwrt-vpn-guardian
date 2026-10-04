package v2raya

import "testing"

func TestCandidateEligibility(t *testing.T) {
	tests := []struct {
		name                   string
		protocol, network, sec string
		base                   int
		ok                     bool
	}{
		{"hysteria2", "hysteria2", "", "", 20, true},
		{"xhttp reality", "vless", "xhttp", "reality", 40, true},
		{"shadowsocks", "shadowsocks", "", "", 60, true},
		{"ws tls", "vless", "ws", "tls", 80, true},
		{"tcp reality", "vless", "tcp", "reality", 100, true},
		{"unsupported grpc", "vless", "grpc", "tls", 0, false},
		{"wrong security", "vless", "xhttp", "tls", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := CandidatePriorityBase(tt.protocol, tt.network, tt.sec)
			if ok != tt.ok || got != tt.base {
				t.Fatalf("CandidatePriorityBase() = (%d,%v), want (%d,%v)", got, ok, tt.base, tt.ok)
			}
			if CandidateEligible(tt.protocol, tt.network, tt.sec) != tt.ok {
				t.Fatalf("CandidateEligible() mismatch")
			}
		})
	}
}

func TestCandidatePriorityIncludesSort(t *testing.T) {
	got, ok := CandidatePriority("VLESS", "XHTTP", "Reality", 7)
	if !ok {
		t.Fatal("candidate unexpectedly rejected")
	}
	if got != 47 {
		t.Fatalf("priority = %d, want 47", got)
	}
}
