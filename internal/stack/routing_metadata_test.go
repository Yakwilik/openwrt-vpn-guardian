package stack

import (
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	"testing"
)

func TestRoutingGroupAndNoteChangesDoNotRequireDataplaneRestart(t *testing.T) {
	before := config.Routing{Version: config.Version,
		ProxyDomains: []string{"domain:auth.kimi.ai", "geosite:telegram"},
		ProxyIPs:     []string{"91.108.8.0/22"},
	}
	grouped := before
	grouped.Groups = []config.RoutingGroup{{ID: "telegram", Name: "Telegram", Description: "Все адреса Telegram"}}
	grouped.RuleGroups = map[string]string{
		"geosite:telegram": "telegram",
		"91.108.8.0/22":    "telegram",
	}
	grouped.Notes = map[string]string{"domain:auth.kimi.ai": "Kimi auth"}
	if !sameRoutingDataplane(before, grouped) {
		t.Fatal("group-only update would unnecessarily restart vpn-front")
	}
	withRule := grouped
	withRule.ProxyDomains = append([]string(nil), grouped.ProxyDomains...)
	withRule.ProxyDomains = append(withRule.ProxyDomains, "domain:example.com")
	if sameRoutingDataplane(before, withRule) {
		t.Fatal("adding a domain requires an actual routing update")
	}
	withIP := grouped
	withIP.ProxyIPs = []string{"91.108.56.0/22"}
	if sameRoutingDataplane(before, withIP) {
		t.Fatal("changing IP networks requires an actual routing update")
	}
}
