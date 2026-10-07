package dnsproxy

import (
	"fmt"
	"regexp/syntax"
	"sort"
	"strings"
)

// DNSMasqUnsupportedRule identifies a routing rule that cannot be represented
// without changing its matching semantics. Source is the configured rule,
// including the geosite group and attribute filters for an expanded entry.
type DNSMasqUnsupportedRule struct {
	Source string
	Kind   string
	Value  string
	Reason string
}

// DNSMasqCompileError reports every unsupported selector, in a stable order.
// Callers can inspect Unsupported with errors.As; a compilation error never
// accompanies a partial configuration that might silently omit proxy domains.
type DNSMasqCompileError struct {
	Unsupported []DNSMasqUnsupportedRule
}

func (e *DNSMasqCompileError) Error() string {
	var out strings.Builder
	fmt.Fprintf(&out, "cannot compile %d DNS routing rule(s) for dnsmasq", len(e.Unsupported))
	for _, rule := range e.Unsupported {
		fmt.Fprintf(&out, "; %s (%s:%q): %s", rule.Source, rule.Kind, rule.Value, rule.Reason)
	}
	return out.String()
}

type dnsMasqRuleKey struct {
	kind  uint64
	value string
}

func selectorKindName(kind uint64) string {
	switch kind {
	case 0:
		return "plain"
	case 1:
		return "regexp"
	case 2:
		return "domain"
	case 3:
		return "full"
	default:
		return fmt.Sprintf("type-%d", kind)
	}
}

func selectorRuleValue(kind uint64, value string) string {
	switch kind {
	case 0:
		return strings.ToLower(value)
	case 2, 3:
		return canonicalName(value)
	default:
		return value
	}
}

// DNSMasqServers compiles this matcher's OR of proxy domain rules into a
// dnsmasq servers-file. The caller must configure the default dnsmasq upstreams
// as direct DNS resolvers and must not install a default Guardian upstream.
// Only matching names will then reach Guardian at 127.0.0.1:port.
//
// dnsmasq's /name/ syntax includes descendants. An exact Full rule therefore
// also needs /*.name/#, which sends descendants to the standard upstreams.
// More specific proxy rules override that exclusion. Covered Full rules are
// removed first so their exclusions cannot punch holes in a Domain rule.
//
// Regex support is deliberately conservative: finite anchored names can be
// compiled within a bounded expansion budget. A presentation regexp dot is
// not equivalent to a native DNS label boundary and is never rewritten as one.
// Other regexes must be provably covered by a compiled Domain rule or produce
// an explicit error. Plain substring rules have no native dnsmasq equivalent.
func (m *DomainMatcher) DNSMasqServers(port int) ([]byte, error) {
	return m.dnsMasqServers(port, false)
}

// DNSMasqServersWithRegex first attempts standard dnsmasq selectors. If that
// cannot preserve all rules, it can emit regex: selectors for a dnsmasq build
// advertising the regex-server capability. That extension must match the same
// escaped, ASCII-lowercased DNS question presentation used by miekg/dns and
// DomainMatcher, and use POSIX ERE without REG_ICASE or REG_NEWLINE.
//
// When regex selectors are needed, Full rules also become anchored regexes.
// This avoids synthetic subdomain exclusions taking priority over a matching
// regex. The caller must check the binary capability before activating any
// configuration containing regex: selectors.
func (m *DomainMatcher) DNSMasqServersWithRegex(port int) ([]byte, error) {
	config, err := m.DNSMasqServers(port)
	if err == nil || port < 1 || port > 65535 {
		return config, err
	}
	return m.dnsMasqServers(port, true)
}

func (m *DomainMatcher) dnsMasqServers(port int, allowRegex bool) ([]byte, error) {
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid Guardian DNS port %d", port)
	}
	if m == nil {
		return []byte{}, nil
	}

	// Index provenance once, rather than scanning all geosite entries for each
	// unsupported rule. Use the same normalization as the runtime matcher.
	provenance := make(map[dnsMasqRuleKey][]matcherRule)
	for _, rule := range m.rules {
		key := dnsMasqRuleKey{rule.kind, selectorRuleValue(rule.kind, rule.value)}
		provenance[key] = append(provenance[key], rule)
	}
	unsupported := make(map[DNSMasqUnsupportedRule]struct{})
	reject := func(kind uint64, value string, reason error) {
		rules := provenance[dnsMasqRuleKey{kind, value}]
		if len(rules) == 0 {
			rules = []matcherRule{{kind: kind, value: value}}
		}
		for _, rule := range rules {
			sources := rule.sources
			if len(sources) == 0 {
				sources = []string{selectorKindName(kind) + ":" + rule.value}
			}
			for _, source := range sources {
				unsupported[DNSMasqUnsupportedRule{
					Source: source, Kind: selectorKindName(kind), Value: rule.value, Reason: reason.Error(),
				}] = struct{}{}
			}
		}
	}

	full, suffix := make(map[string]struct{}), make(map[string]struct{})
	nativeRegex := make(map[string]struct{})
	for name := range m.full {
		if err := validSelectorName(name); err != nil {
			reject(3, name, err)
		} else {
			full[name] = struct{}{}
		}
	}
	for name := range m.suffix {
		if err := validSelectorName(name); err != nil {
			reject(2, name, err)
		} else {
			suffix[name] = struct{}{}
		}
	}

	type pendingRegex struct {
		value string
		re    *syntax.Regexp
		err   error
	}
	var pending []pendingRegex
	seen := make(map[string]bool)
	for _, r := range m.regex {
		value := r.String()
		if seen[value] {
			continue
		}
		seen[value] = true
		re, err := syntax.Parse(value, syntax.Perl)
		if err != nil {
			reject(1, value, err)
			continue
		}
		rules, err := regexpDNSMasqRules(re)
		if err != nil {
			pending = append(pending, pendingRegex{value, re, err})
			continue
		}
		for _, rule := range rules {
			if rule.kind == 2 {
				suffix[rule.value] = struct{}{}
			} else {
				full[rule.value] = struct{}{}
			}
		}
	}
	// Only a proven DNS label boundary permits a native Domain rule to cover
	// a presentation regexp. Otherwise preserve it in the extended output.
	for _, rule := range pending {
		if regexpCoveredByDomains(rule.re, suffix) {
			continue
		}
		if !allowRegex {
			reject(1, rule.value, rule.err)
			continue
		}
		ere, err := regexpPOSIXSelector(rule.re)
		if err != nil {
			reject(1, rule.value, err)
		} else {
			nativeRegex[ere] = struct{}{}
		}
	}
	for _, value := range m.plain {
		if !allowRegex {
			reject(0, value, fmt.Errorf("dnsmasq cannot match a substring at arbitrary positions in a domain name"))
			continue
		}
		ere, err := quotePOSIXSelector(value)
		if err != nil {
			reject(0, value, err)
		} else {
			nativeRegex[ere] = struct{}{}
		}
	}
	if len(unsupported) > 0 {
		report := &DNSMasqCompileError{Unsupported: make([]DNSMasqUnsupportedRule, 0, len(unsupported))}
		for rule := range unsupported {
			report.Unsupported = append(report.Unsupported, rule)
		}
		sort.Slice(report.Unsupported, func(i, j int) bool {
			a, b := report.Unsupported[i], report.Unsupported[j]
			if a.Source != b.Source {
				return a.Source < b.Source
			}
			if a.Kind != b.Kind {
				return a.Kind < b.Kind
			}
			if a.Value != b.Value {
				return a.Value < b.Value
			}
			return a.Reason < b.Reason
		})
		return nil, report
	}

	// Every longer suffix is redundant when an ancestor is already selected.
	// Check against the complete map before replacing it with the reduced map.
	reduced := make(map[string]struct{}, len(suffix))
	for name := range suffix {
		_, parent, hasParent := strings.Cut(name, ".")
		if !hasParent || !coveredByDomain(parent, suffix) {
			reduced[name] = struct{}{}
		}
	}
	for name := range full {
		if coveredByDomain(name, reduced) {
			delete(full, name)
		}
	}

	var out strings.Builder
	for _, name := range sortedSelectorNames(reduced) {
		fmt.Fprintf(&out, "server=/%s/127.0.0.1#%d\n", name, port)
	}
	for _, name := range sortedSelectorNames(full) {
		if len(nativeRegex) == 0 {
			fmt.Fprintf(&out, "server=/%s/127.0.0.1#%d\nserver=/*.%s/#\n", name, port, name)
		} else {
			// validSelectorName above guarantees this literal is representable.
			literal, _ := quotePOSIXSelector(name)
			nativeRegex["^"+literal+"$"] = struct{}{}
		}
	}
	for _, expr := range sortedSelectorNames(nativeRegex) {
		fmt.Fprintf(&out, "server=/regex:%s/127.0.0.1#%d\n", expr, port)
	}
	return []byte(out.String()), nil
}

func coveredByDomain(name string, suffixes map[string]struct{}) bool {
	for name != "" {
		if _, ok := suffixes[name]; ok {
			return true
		}
		_, parent, ok := strings.Cut(name, ".")
		if !ok {
			break
		}
		name = parent
	}
	return false
}

func sortedSelectorNames(names map[string]struct{}) []string {
	result := make([]string, 0, len(names))
	for name := range names {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

// Keep configuration metacharacters, escaped wire names and implicit IDNA
// conversions out of selectors. Rejecting an unsupported spelling leaves the
// runtime matcher unchanged and prevents a broader or injected dnsmasq rule.
func validSelectorName(name string) error {
	if name == "" || len(name) > 253 {
		return fmt.Errorf("dnsmasq selector must be a nonempty DNS name of at most 253 bytes")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("dnsmasq selector has an empty label or a label longer than 63 bytes")
		}
		for _, c := range label {
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
				continue
			}
			return fmt.Errorf("dnsmasq selector contains unsupported character %q; automatic rewriting would change matching semantics", c)
		}
	}
	return nil
}
