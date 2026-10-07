package stack

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/dnsproxy"
)

func selectorStack(mode string, only *bool) config.Stack {
	return config.Stack{DNS: config.ClientDNS{Mode: mode, OnlyProxyDomains: only, ListenPort: 20176}}
}

func TestDNSSelectorsSystemAndExplicitAllDomains(t *testing.T) {
	// These policies do not need to expand a proxy geosite list. A missing
	// geosite asset must not turn explicit system mode into a protected path.
	rules := config.Routing{ProxyDomains: []string{"geosite:unavailable"}}
	for _, only := range []bool{false, true} {
		selectors, err := dnsSelectors(selectorStack(config.DNSModeSystem, &only), rules)
		if err != nil || strings.Contains(string(selectors), "server=") {
			t.Fatalf("system mode generated forwarding selectors: %q %v", selectors, err)
		}
	}
	all := false
	for _, mode := range []string{config.DNSModeCustom, config.DNSModeXray} {
		selectors, err := dnsSelectors(selectorStack(mode, &all), rules)
		if err != nil || !strings.Contains(string(selectors), "server=/#/127.0.0.1#20176\n") {
			t.Fatalf("explicit all-domain policy lost: %q %v", selectors, err)
		}
	}
}

func TestDNSSelectorsDefaultIsOnlyProxyAndUnsupportedDoesNotBroaden(t *testing.T) {
	s := selectorStack(config.DNSModeCustom, nil)
	selectors, err := dnsSelectors(s, config.Routing{ProxyDomains: []string{"full:only.test", "domain:tree.test"}})
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{"only.test": true, "sub.only.test": false, "tree.test": true, "sub.tree.test": true, "ordinary.test": false} {
		if got := selectedByStackConfig(t, selectors, name); got != want {
			t.Errorf("name %s selected=%t want %t", name, got, want)
		}
	}
	selectors, err = dnsSelectors(s, config.Routing{ProxyDomains: []string{"domain:good.test", `regexp:\bunsupported\b`}})
	var report *dnsproxy.DNSMasqCompileError
	if selectors != nil || !errors.As(err, &report) || len(report.Unsupported) != 1 {
		t.Fatalf("unsupported selector was skipped or widened: %q %v", selectors, err)
	}
}

func TestTransitionDNSSelectorsProtectsUnionAcrossPolicyModes(t *testing.T) {
	oldRules := config.Routing{ProxyDomains: []string{"full:old.test", "domain:old-tree.test", `regexp:^old[0-9]+\.regex\.test$`}}
	newRules := config.Routing{ProxyDomains: []string{"full:child.old.test", "domain:new-tree.test", `regexp:^new[0-9]+\.regex\.test$`}}
	oldMatcher, err := dnsproxy.LoadDomainMatcher(oldRules.ProxyDomains, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	newMatcher, err := dnsproxy.LoadDomainMatcher(newRules.ProxyDomains, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	queries := []string{"old.test", "child.old.test", "deep.child.old.test", "old-tree.test", "sub.old-tree.test", "new-tree.test", "sub.new-tree.test", "old1.regex.test", "new2.regex.test", "ordinary.test"}
	for _, beforeMode := range []string{config.DNSModeSystem, config.DNSModeCustom, config.DNSModeXray} {
		for _, afterMode := range []string{config.DNSModeSystem, config.DNSModeCustom, config.DNSModeXray} {
			for _, beforeOnly := range []bool{false, true} {
				for _, afterOnly := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s-only=%t_to_%s-only=%t", beforeMode, beforeOnly, afterMode, afterOnly), func(t *testing.T) {
						before, after := selectorStack(beforeMode, &beforeOnly), selectorStack(afterMode, &afterOnly)
						selectors, err := transitionDNSSelectors(before, oldRules, after, newRules)
						if err != nil {
							t.Fatal(err)
						}
						for _, name := range queries {
							oldProtected := beforeMode != config.DNSModeSystem && (!beforeOnly || oldMatcher.Match(name))
							newProtected := afterMode != config.DNSModeSystem && (!afterOnly || newMatcher.Match(name))
							if got := selectedByStackConfig(t, selectors, name); got != (oldProtected || newProtected) {
								t.Errorf("%s selected=%t; before=%t after=%t:\n%s", name, got, oldProtected, newProtected, selectors)
							}
						}
					})
				}
			}
		}
	}
}

func TestTransitionDNSSelectorsFullDoesNotPunchHoleInNewDomain(t *testing.T) {
	s := selectorStack(config.DNSModeCustom, nil)
	before := config.Routing{ProxyDomains: []string{"full:api.example.test"}}
	after := config.Routing{ProxyDomains: []string{"domain:example.test"}}
	selectors, err := transitionDNSSelectors(s, before, s, after)
	if err != nil {
		t.Fatal(err)
	}
	if !selectedByStackConfig(t, selectors, "sub.api.example.test") || strings.Contains(string(selectors), "/*.api.example.test/#") {
		t.Fatalf("old Full exclusion weakens new Domain protection: %s", selectors)
	}
	if len(before.ProxyDomains) != 1 || before.ProxyDomains[0] != "full:api.example.test" ||
		len(after.ProxyDomains) != 1 || after.ProxyDomains[0] != "domain:example.test" {
		t.Fatal("transition compilation modified the source routing policies")
	}
}

// Use the documented native suffix precedence, followed by extension regexes
// before the default direct upstream. This exercises the policy compiler's
// public output independently of its normalization implementation.
func selectedByStackConfig(t *testing.T, selectors []byte, name string) bool {
	t.Helper()
	best, selected := -1, false
	var expressions []*regexp.Regexp
	for _, line := range strings.Split(string(selectors), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "/")
		if len(parts) != 3 || parts[0] != "server=" {
			t.Fatalf("unexpected selector syntax %q", line)
		}
		pattern := parts[1]
		if strings.HasPrefix(pattern, "regex:") {
			re, err := regexp.CompilePOSIX(strings.TrimPrefix(pattern, "regex:"))
			if err != nil {
				t.Fatal(err)
			}
			expressions = append(expressions, re)
			continue
		}
		matches := name == pattern || strings.HasSuffix(name, "."+pattern)
		if pattern == "#" {
			pattern, matches = "", true
		} else if strings.HasPrefix(pattern, "*") {
			pattern = strings.TrimPrefix(pattern, "*")
			matches = strings.HasSuffix(name, pattern)
		}
		if matches && len(pattern) > best {
			best, selected = len(pattern), parts[2] != "#"
		}
	}
	if best >= 0 {
		return selected
	}
	for _, expression := range expressions {
		if expression.MatchString(name) {
			return true
		}
	}
	return false
}
