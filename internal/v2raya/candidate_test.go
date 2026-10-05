package v2raya

import (
	"testing"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
)

func TestCandidatePolicyTransportFilter(t *testing.T) {
	nodes := []struct {
		transport              config.Transport
		protocol, network, sec string
		base                   int
	}{
		{config.TransportHysteria2, "hysteria2", "", "", 20},
		{config.TransportVLESSXHTTPReality, "vless", "xhttp", "reality", 40},
		{config.TransportShadowsocks, "shadowsocks", "", "", 60},
		{config.TransportVLESSWSTLS, "vless", "ws", "tls", 80},
		{config.TransportVLESSTCPReality, "vless", "tcp", "reality", 100},
	}
	for _, allowed := range nodes {
		t.Run(string(allowed.transport), func(t *testing.T) {
			policy, err := NewCandidatePolicy(config.Selection{AllowedTransports: []config.Transport{allowed.transport}})
			if err != nil {
				t.Fatal(err)
			}
			for _, node := range nodes {
				want := node.transport == allowed.transport
				priority, eligible := policy.Priority(node.protocol, node.network, node.sec, 7)
				if eligible != want || policy.Eligible(node.protocol, node.network, node.sec) != want {
					t.Errorf("allow=%s node=%s eligibility=%v, want %v", allowed.transport, node.transport, eligible, want)
				}
				if want && priority != node.base+7 {
					t.Errorf("priority=%d, want %d", priority, node.base+7)
				}
				if !want && priority != 0 {
					t.Errorf("denied candidate has priority %d", priority)
				}
			}
		})
	}
}

func TestCandidatePolicyNormalization(t *testing.T) {
	policy, err := NewCandidatePolicy(config.Selection{AllowedTransports: []config.Transport{config.TransportVLESSXHTTPReality}})
	if err != nil {
		t.Fatal(err)
	}
	got, eligible := policy.Priority(" VLESS ", " XHTTP ", " Reality ", 7)
	if !eligible || got != 47 {
		t.Fatalf("normalized priority=(%d,%v), want (47,true)", got, eligible)
	}
}

func TestCandidatePolicyRejectsUnsupportedCombinations(t *testing.T) {
	policy, err := NewCandidatePolicy(config.Selection{AllowedTransports: config.SupportedTransports()})
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range [][3]string{
		{"vless", "grpc", "tls"},
		{"vless", "xhttp", "tls"},
		{"vless", "ws", "reality"},
		{"vless", "tcp", ""},
		{"vmess", "tcp", "tls"},
		{"", "", ""},
	} {
		if policy.Eligible(node[0], node[1], node[2]) {
			t.Errorf("unsupported combination accepted: %v", node)
		}
	}
}

func TestCandidatePolicyRejectsInvalidSelection(t *testing.T) {
	for _, transports := range [][]config.Transport{
		nil,
		{},
		{"unknown"},
		{config.TransportHysteria2, config.TransportHysteria2},
	} {
		policy, err := NewCandidatePolicy(config.Selection{AllowedTransports: transports})
		if err == nil {
			t.Errorf("invalid allowlist accepted: %v", transports)
		}
		if policy.Eligible("hysteria2", "", "") {
			t.Error("failed policy construction must reject all candidates")
		}
	}
}

func TestCandidatePolicyZeroValueDeniesAll(t *testing.T) {
	var policy CandidatePolicy
	if priority, eligible := policy.Priority("vless", "tcp", "reality", 0); eligible || priority != 0 {
		t.Fatalf("zero policy=(%d,%v), want (0,false)", priority, eligible)
	}
}

func TestCandidatePolicySnapshotsSelection(t *testing.T) {
	selection := config.Selection{AllowedTransports: []config.Transport{config.TransportVLESSXHTTPReality}}
	policy, err := NewCandidatePolicy(selection)
	if err != nil {
		t.Fatal(err)
	}
	selection.AllowedTransports[0] = config.TransportVLESSTCPReality
	if !policy.Eligible("vless", "xhttp", "reality") || policy.Eligible("vless", "tcp", "reality") {
		t.Fatal("caller mutation changed an existing policy")
	}
}
