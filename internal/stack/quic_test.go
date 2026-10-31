package stack

import (
	"reflect"
	"strings"
	"testing"
)

func TestQUICModeDefaultDoesNotModifyExistingRouting(t *testing.T) {
	s := defaultStack("br-test", "192.0.2.0/24", "eth-test", "/opt/xray")
	a := makeNFT(s)
	s.Front.QUICMode = "allow"
	b := makeNFT(s)
	if a != b {
		t.Fatal("allow must preserve legacy dataplane")
	}
	if strings.Contains(a, "quic_tcp_fallback") {
		t.Fatal("legacy manifests must not opt into port rejection")
	}
}
func TestQUICFallbackRejectsOnlyLANUDP443(t *testing.T) {
	s := defaultStack("br-test", "192.0.2.0/24", "eth-test", "/opt/xray")
	s.Front.QUICMode = "tcp-fallback"
	n := makeNFT(s)
	for _, h := range []string{"input", "forward"} {
		start := strings.Index(n, "chain quic_tcp_fallback_"+h)
		if start < 0 {
			t.Fatalf("missing %s reject hook", h)
		}
		end := strings.Index(n[start:], "\n  }")
		if end < 0 {
			t.Fatal("unterminated chain")
		}
		chain := n[start : start+end]
		for _, wanted := range []string{`iifname "br-test" ct status dnat return`, `iifname "br-test" ip daddr @bypass4 return`, `iifname "br-test" ip saddr 192.0.2.0/24 udp dport 443 counter reject with icmpx type port-unreachable`, `iifname "br-test" meta nfproto ipv6 udp dport 443 counter reject with icmpx type port-unreachable`} {
			if !strings.Contains(chain, wanted) {
				t.Errorf("missing scoped guard %s", wanted)
			}
		}
		if strings.Contains(chain, "drop") || strings.Contains(chain, "tcp dport") || strings.Contains(chain, "eth-test") {
			t.Fatal("fallback must reject immediately, not affect TCP or WAN/backend")
		}
	}
	start := strings.Index(n, "chain prerouting {")
	end := strings.Index(n[start:], "chain forward_guard")
	chain := n[start : start+end]
	fallback := strings.Index(chain, "udp dport 443 meta mark set")
	tproxy := strings.Index(chain, "tproxy ip to")
	if fallback < 0 || tproxy < fallback {
		t.Fatal("UDP443 must exit before TPROXY")
	}
	if !strings.Contains(chain, "meta mark & 0xffffff3f ct mark set ct mark & 0xffffff3f return") {
		t.Fatal("only Guardian-owned mark bits may be cleared")
	}
	if strings.Index(chain, "ip daddr @bypass4 return") > fallback {
		t.Fatal("local destinations must remain exempt")
	}
}
func TestQUICModeDoesNotChangeXrayOrDNSServers(t *testing.T) {
	s := defaultStack("br-test", "192.0.2.0/24", "eth-test", "/opt/xray")
	beforeFront := makeFront(s, defaultRouting())
	beforeDNS := makeDNSXray(s)
	beforePolicy := makePolicy(s, "killswitch")
	s.Front.QUICMode = "tcp-fallback"
	if !reflect.DeepEqual(beforeFront, makeFront(s, defaultRouting())) || !reflect.DeepEqual(beforeDNS, makeDNSXray(s)) || !reflect.DeepEqual(beforePolicy, makePolicy(s, "killswitch")) {
		t.Fatal("compatibility guard must not change VPN/DNS configuration")
	}
}
func TestQUICModeValidatesOptions(t *testing.T) {
	s := defaultStack("br-test", "192.0.2.0/24", "eth-test", "/opt/xray")
	for _, v := range []string{"", "allow", "tcp-fallback"} {
		s.Front.QUICMode = v
		if err := s.Validate(); err != nil {
			t.Fatalf("valid mode %q rejected: %v", v, err)
		}
	}
	s.Front.QUICMode = "unknown"
	if err := s.Validate(); err == nil {
		t.Fatal("unknown mode accepted")
	}
	for _, args := range [][]string{nil, {}, {"drop"}, {"tcp-fallback", "extra"}} {
		if err := configureQUIC(args); err == nil {
			t.Fatal("invalid arguments accepted")
		}
	}
}
