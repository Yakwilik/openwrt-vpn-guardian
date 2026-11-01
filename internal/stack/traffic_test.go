package stack

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
)

func TestTrafficModeLegacyAndFrontIsolation(t *testing.T) {
	s := defaultStack("br-lan", "192.168.8.0/24", "eth1", "/usr/share/xray")
	r := defaultRouting()
	if s.TrafficMode() != config.TrafficSelective {
		t.Fatal("legacy default changed")
	}
	before := makeFront(s, r)
	if !reflect.DeepEqual(before, makeSelectiveFront(s, r)) {
		t.Fatal("legacy front changed")
	}
	original, _ := json.Marshal(r)
	s.Front.TrafficMode = config.TrafficFullVPN
	full := makeFront(s, r)
	raw, _ := json.Marshal(full)
	if bytes.Contains(raw, []byte("policy-gateway")) || bytes.Contains(raw, []byte("sniffing")) {
		t.Fatal("full VPN must not depend on classification or fail-open policy")
	}
	rules := full["routing"].(map[string]any)["rules"].([]any)
	last := rules[len(rules)-1].(map[string]any)
	if last["network"] != "tcp,udp" || last["outboundTag"] != "full-vpn" {
		t.Fatalf("catch-all absent: %#v", last)
	}
	out := full["outbounds"].([]any)[1].(map[string]any)
	server := out["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	if server["port"] != s.Backend.SocksPort {
		t.Fatal("full VPN sent to potentially direct policy gateway")
	}
	after, _ := json.Marshal(r)
	if !bytes.Equal(original, after) {
		t.Fatal("saved rules changed")
	}
	s.Front.TrafficMode = config.TrafficSelective
	if !reflect.DeepEqual(before, makeFront(s, r)) {
		t.Fatal("selective rollback does not restore front")
	}
}

func TestTrafficModeDNSAllNamesAndReversiblePreferences(t *testing.T) {
	for _, dnsMode := range []string{config.DNSModeSystem, config.DNSModeCustom, config.DNSModeXray} {
		t.Run(dnsMode, func(t *testing.T) {
			s := defaultStack("br-lan", "192.168.8.0/24", "eth1", "/usr/share/xray")
			s.DNS.Mode = dnsMode
			r := Routing{Version: 1, ProxyDomains: []string{"full:one.example"}}
			saved, _ := json.Marshal(s.DNS)
			selective, err := dnsSelectors(s, r)
			if err != nil {
				t.Fatal(err)
			}
			full := s
			full.Front.TrafficMode = config.TrafficFullVPN
			all, err := dnsSelectors(full, r)
			if err != nil || !bytes.Contains(all, []byte("server=/regex:^.*$/127.0.0.1#20176")) {
				t.Fatalf("all DNS not protected: %s %v", all, err)
			}
			if full.EffectiveClientDNS().ProxyOnly() || full.EffectiveClientDNS().Mode == config.DNSModeSystem {
				t.Fatal("effective DNS leaked to system")
			}
			stored, _ := json.Marshal(full.DNS)
			if !bytes.Equal(saved, stored) {
				t.Fatal("stored DNS preferences overwritten")
			}
			for _, pair := range [][2]Stack{{s, full}, {full, s}} {
				transitional, err := transitionDNSSelectors(pair[0], r, pair[1], r)
				if err != nil || !bytes.Contains(transitional, []byte("server=/regex:^.*$/")) {
					t.Fatalf("transition lost protection: %s %v", transitional, err)
				}
			}
			full.Front.TrafficMode = config.TrafficSelective
			restored, err := dnsSelectors(full, r)
			if err != nil || !bytes.Equal(selective, restored) {
				t.Fatal("selective DNS not restored")
			}
		})
	}
}

func TestFullVPNGuardRejectsUnhandledPublicForwarding(t *testing.T) {
	s := defaultStack("br-lan", "192.168.8.0/24", "eth1", "/usr/share/xray")
	if strings.Contains(makeNFT(s), "full_vpn_forward_guard") {
		t.Fatal("legacy traffic unexpectedly blocked")
	}
	s.Front.TrafficMode = config.TrafficFullVPN
	s.Front.QUICMode = "tcp-fallback"
	nft := makeNFT(s)
	start := strings.Index(nft, "chain full_vpn_forward_guard")
	if start < 0 {
		t.Fatal("IPv6/ICMP leak guard missing")
	}
	end := strings.Index(nft[start:], "\n  }")
	guard := nft[start : start+end]
	for _, wanted := range []string{"hook forward priority filter - 25", `iifname "br-lan" ip daddr @bypass4 return`, `ip6 daddr { ::1/128, fc00::/7, fe80::/10, ff00::/8 } return`, `iifname "br-lan" counter reject with icmpx type admin-prohibited`} {
		if !strings.Contains(guard, wanted) {
			t.Fatalf("missing %q: %s", wanted, guard)
		}
	}
	if strings.Contains(guard, "eth1") || strings.Contains(guard, "hook output") {
		t.Fatal("backend or router traffic affected")
	}
	if !strings.Contains(nft, "quic_tcp_fallback_forward") {
		t.Fatal("QUIC policy lost")
	}
}

func TestTrafficModeRejectsInvalidInputBeforeMutation(t *testing.T) {
	for _, mode := range []string{"", "all", "direct", "full-vpn; reboot"} {
		if ConfigureTrafficMode(mode) == nil {
			t.Fatalf("invalid mode %q accepted", mode)
		}
	}
	s := defaultStack("br-lan", "192.168.8.0/24", "eth1", "/usr/share/xray")
	s.Front.TrafficMode = "bad"
	if s.Validate() == nil {
		t.Fatal("invalid manifest accepted")
	}
}
