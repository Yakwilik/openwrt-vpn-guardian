package stack

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
)

func TestDefaultStackUsesVPNOnlyFailurePolicy(t *testing.T) {
	cfg := defaultStack("br-test", "192.0.2.0/24", "eth-test", "/opt/xray")

	if cfg.Policy.Default != "killswitch" {
		t.Fatalf("default policy = %q, want killswitch", cfg.Policy.Default)
	}
	if cfg.Front.SocksPort <= 0 || cfg.Front.TProxyPort <= 0 || cfg.Front.PolicyPort <= 0 {
		t.Fatalf("front ports must be positive: %+v", cfg.Front)
	}
	if cfg.Backend.SocksPort <= 0 {
		t.Fatalf("backend SOCKS port must be positive: %d", cfg.Backend.SocksPort)
	}
}

func TestGenerateUsesOwnedRuntimePaths(t *testing.T) {
	cfg := defaultStack("br-test", "192.0.2.0/24", "eth-test", "/opt/xray-assets")
	dir := t.TempDir()

	if err := generate(dir, cfg, defaultRouting()); err != nil {
		t.Fatal(err)
	}

	mustContainFile(t, filepath.Join(dir, "vpn-front.init"), paths.FrontConfig)
	mustContainFile(t, filepath.Join(dir, "vpn-front.init"), `ASSETS="/opt/xray-assets"`)
	mustContainFile(t, filepath.Join(dir, "vpn-policy.init"), paths.PolicyConfig)
	mustContainFile(t, filepath.Join(dir, "vpn-front-routing.init"), paths.FrontEnabled)
	mustContainFile(t, filepath.Join(dir, "vpn-front-routing.init"), paths.FrontNFT)
	mustContainFile(t, filepath.Join(dir, filepath.Base(paths.FrontConfig)), "\"domainStrategy\": \"UseIPv4\"")

	for _, name := range []string{
		filepath.Base(paths.FrontConfig),
		filepath.Base(paths.PolicyFailOpen),
		filepath.Base(paths.PolicyVPNOnly),
		filepath.Base(paths.PolicyBlocked),
		filepath.Base(paths.PolicyDirect),
		filepath.Base(paths.FrontNFT),
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("generated file %s: %v", name, err)
		}
	}
}

func TestGeneratedRoutingIsScopedToLAN(t *testing.T) {
	cfg := defaultStack("br-test", "192.0.2.0/24", "eth-test", "/opt/xray")
	nft := makeNFT(cfg)

	if !strings.Contains(nft, `iifname "br-test" ip saddr 192.0.2.0/24`) {
		t.Fatalf("nft config is not scoped to configured LAN:\n%s", nft)
	}
	if strings.Contains(nft, "blackhole") {
		t.Fatalf("front nft must not install a global blackhole:\n%s", nft)
	}
}

func mustContainFile(t *testing.T, path, needle string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), needle) {
		t.Fatalf("%s does not contain %q:\n%s", path, needle, string(b))
	}
}

func TestNftReloadIsAtomicAndFailsClosed(t *testing.T) {
	cfg := defaultStack("br-test", "192.0.2.0/24", "eth-test", "/opt/xray")
	rules := makeNFT(cfg)
	for _, fragment := range []string{"add table inet vpn_front\ndelete table inet vpn_front\n", "chain forward_guard", "counter drop"} {
		if !strings.Contains(rules, fragment) {
			t.Errorf("missing guard %q", fragment)
		}
	}
	init := makeRoutingInit(cfg)
	if strings.Contains(strings.Split(init, "stop() {")[0], "nft delete") {
		t.Fatal("reload must not delete the active table in a separate transaction")
	}
	if strings.Contains(strings.Split(init, "stop() {")[0], "route flush") {
		t.Fatal("reload must not flush active policy routes")
	}
}

func TestGeneratedFrontBypassesDNATReplies(t *testing.T) {
	cfg := defaultStack("br-test", "192.0.2.0/24", "eth-test", "/opt/xray")
	nft := makeNFT(cfg)

	const rule = `iifname "br-test" ip saddr 192.0.2.0/24 ct status dnat return`
	if got := strings.Count(nft, rule); got != 2 {
		t.Fatalf("DNAT reply bypass count = %d, want 2:\n%s", got, nft)
	}

	tproxy := `iifname "br-test" ip saddr 192.0.2.0/24 meta nfproto ipv4 meta l4proto { tcp, udp }`
	if strings.Index(nft, rule) > strings.Index(nft, tproxy) {
		t.Fatalf("DNAT bypass must run before TPROXY marking:\n%s", nft)
	}
}

func TestGeneratedClientDNSInterception(t *testing.T) {
	cfg := defaultStack("br-test", "192.0.2.0/24", "eth-test", "/opt/xray")
	nft := makeNFT(cfg)
	for _, fragment := range []string{
		"chain dns_redirect",
		"type nat hook prerouting priority -170",
		`iifname "br-test" ip saddr 192.0.2.0/24 udp dport 53 redirect to :53`,
		`iifname "br-test" ip saddr 192.0.2.0/24 tcp dport 53 redirect to :53`,
	} {
		if !strings.Contains(nft, fragment) {
			t.Fatalf("generated nft missing %q:\n%s", fragment, nft)
		}
	}
	init := makeDNSInit(cfg)
	if !strings.Contains(init, `dns-proxy`) {
		t.Fatalf("generated DNS service is incomplete:\n%s", init)
	}
}

func TestSystemDNSStillInterceptsClientsForLocalDispatch(t *testing.T) {
	cfg := defaultStack("br-test", "192.0.2.0/24", "eth-test", "/opt/xray")
	cfg.DNS.Mode = "system"
	nft := makeNFT(cfg)
	if !strings.Contains(nft, "chain dns_redirect") || !strings.Contains(nft, "dport 53 redirect") {
		t.Fatalf("system DNS mode must still pass LAN DNS through Guardian dispatcher:\n%s", nft)
	}
}

func TestDNSXrayIsIsolatedFromApplicationPolicy(t *testing.T) {
	cfg := defaultStack("br-test", "192.0.2.0/24", "eth-test", "/opt/xray")
	for _, mode := range []string{"killswitch", "failopen", "direct", "killswitch-blocked"} {
		p := makePolicy(cfg, mode)
		if _, ok := p["dns"]; ok {
			t.Fatalf("%s application policy must not inherit VPN DNS", mode)
		}
		if len(p["inbounds"].([]any)) != 1 {
			t.Fatal("application policy acquired an extra listener")
		}
	}
	raw, _ := json.Marshal(makeDNSXray(cfg))
	text := string(raw)
	for _, part := range []string{`"tag":"dns-in"`, `"tag":"dns-query"`, `"outboundTag":"vpn-backend"`, `"protocol":"dns"`} {
		if !strings.Contains(text, part) {
			t.Fatalf("DNS core missing %s", part)
		}
	}
}

func TestDNSNativeFrontendLoopbackCompatibility(t *testing.T) {
	cfg := defaultStack("br-lan", "192.168.8.0/24", "eth1", "/usr/share/xray")
	rules := makeNFT(cfg)
	for _, fragment := range []string{`oifname "lo" ip daddr 127.0.0.1 tcp dport 20176 meta mark set meta mark | 0x8000`, `oifname "lo" ip saddr 127.0.0.1 tcp sport 53 meta mark set meta mark | 0x8000`, `udp dport 53 redirect to :53`} {
		if !strings.Contains(rules, fragment) {
			t.Fatalf("missing %s", fragment)
		}
	}
	if strings.Contains(rules, "redirect to :20176") {
		t.Fatal("LAN bypasses native dnsmasq")
	}
}

func TestFailOpenObservatoryConvergesQuickly(t *testing.T) {
	cfg := defaultStack("br-test", "192.0.2.0/24", "eth-test", "/opt/xray")
	raw, err := json.Marshal(makePolicy(cfg, "failopen"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"probeInterval":"1s"`) {
		t.Fatalf("fail-open observatory is too slow: %s", text)
	}
}

func TestFailOpenDirectPolicyIsDeterministicDirect(t *testing.T) {
	cfg := defaultStack("br-test", "192.0.2.0/24", "eth-test", "/opt/xray")
	raw, err := json.Marshal(makePolicy(cfg, "failopen-direct"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"outboundTag":"direct"`) {
		t.Fatalf("failopen-direct is not direct: %s", text)
	}
	if strings.Contains(text, `"balancerTag"`) {
		t.Fatalf("failopen-direct must not depend on observatory: %s", text)
	}
}

func TestGeneratedDNSRejectsWANClients(t *testing.T) {
	cfg := defaultStack("br-lan", "192.168.8.0/24", "eth1", "/usr/share/xray")
	rules := makeNFT(cfg)
	for _, fragment := range []string{
		`chain dns_wan_guard`,
		`iifname "eth1" tcp dport 53 counter drop`,
		`iifname "eth1" udp dport 53 counter drop`,
	} {
		if !strings.Contains(rules, fragment) {
			t.Fatalf("WAN DNS guard missing %q:\n%s", fragment, rules)
		}
	}
	if strings.Contains(rules, `iifname "eth1" tcp dport 20175 counter drop`) {
		t.Fatal("WAN DNS guard must not block management API")
	}
}
