package stack

import (
	"fmt"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/dnsproxy"
)

// dnsSelectors is the complete native dnsmasq forwarding policy. The default
// upstream is deliberately absent: direct questions belong to dnsmasq itself.
func dnsSelectors(s config.Stack, r config.Routing) ([]byte, error) {
	if s.DNS.Mode == config.DNSModeSystem {
		return []byte("# Native system DNS; no Guardian selectors.\n"), nil
	}
	if !s.DNS.ProxyOnly() {
		// This is the operator's explicit all-domains DNS mode, never an implicit
		// fallback for a domain rule which the native compiler cannot represent.
		return []byte(fmt.Sprintf("# Explicit all-domains protected DNS.\nserver=/#/127.0.0.1#%d\n", s.DNS.ListenPort)), nil
	}
	matcher, err := dnsproxy.LoadDomainMatcher(r.ProxyDomains, s.AssetsDir)
	if err != nil {
		return nil, err
	}
	return matcher.DNSMasqServersWithRegex(s.DNS.ListenPort)
}

// During a routing or DNS transition, protect the union of both policies.
// A newly protected name may briefly receive REFUSED from the old Guardian
// runtime, but must never fall through to a public direct resolver.
func transitionDNSSelectors(before config.Stack, oldRules config.Routing, after config.Stack, newRules config.Routing) ([]byte, error) {
	oldProtected := before.DNS.Mode != config.DNSModeSystem
	newProtected := after.DNS.Mode != config.DNSModeSystem
	if !oldProtected {
		return dnsSelectors(after, newRules)
	}
	if !newProtected {
		return dnsSelectors(before, oldRules)
	}
	if !before.DNS.ProxyOnly() {
		return dnsSelectors(before, oldRules)
	}
	if !after.DNS.ProxyOnly() {
		return dnsSelectors(after, newRules)
	}
	combined := newRules
	combined.ProxyDomains = append(append([]string{}, oldRules.ProxyDomains...), newRules.ProxyDomains...)
	return dnsSelectors(after, combined)
}
