package dnsproxy

import (
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	"testing"
)

func TestFullVPNDNSProtectsUnlistedNamesAndCannotFallback(t *testing.T) {
	for _, mode := range []string{config.DNSModeSystem, config.DNSModeCustom, config.DNSModeXray} {
		s := config.DefaultStack("br-lan", "192.168.8.0/24", "eth1", "/tmp/unused-assets")
		s.DNS.Mode = mode
		s.Front.TrafficMode = config.TrafficFullVPN
		rt, err := BuildRuntime(s, config.Routing{Version: 1, ProxyDomains: []string{"full:listed.example"}}, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		for _, host := range []string{"listed.example.", "unlisted.example.", "ya.ru.", "notebook.google.com."} {
			if rt.route(host) != "proxy" {
				t.Fatalf("full VPN uses system resolver for %s", host)
			}
		}
		if rt.policy() != "killswitch" {
			t.Fatal("full VPN DNS inherited direct/failopen")
		}
		if rt.Mode == config.DNSModeSystem || len(rt.Resolvers) == 0 {
			t.Fatal("full VPN lacks protected DNS")
		}
		if s.DNS.Mode != mode || !s.DNS.ProxyOnly() {
			t.Fatal("saved DNS modified")
		}
	}
}
