package dnsproxy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"google.golang.org/protobuf/encoding/protowire"
)

func loadSelectorMatcher(t *testing.T, rules ...string) *DomainMatcher {
	t.Helper()
	m, err := LoadDomainMatcher(rules, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDNSMasqServersNormalizeAndPreserveExactFull(t *testing.T) {
	m := loadSelectorMatcher(t,
		"domain:EXAMPLE.com.", "domain:child.example.com", "domain:example.com",
		"full:example.com", "full:api.example.com",
		"full:ONLY.test.", "full:child.only.test", "domain:proxy.only.test",
		"full:covered.proxy.only.test",
	)
	config, err := m.DNSMasqServers(5354)
	if err != nil {
		t.Fatal(err)
	}
	want := "server=/example.com/127.0.0.1#5354\n" +
		"server=/proxy.only.test/127.0.0.1#5354\n" +
		"server=/child.only.test/127.0.0.1#5354\nserver=/*.child.only.test/#\n" +
		"server=/only.test/127.0.0.1#5354\nserver=/*.only.test/#\n"
	if string(config) != want {
		t.Fatalf("configuration:\n%s\nwant:\n%s", config, want)
	}
	checks := map[string]bool{
		"EXAMPLE.COM.": true, "www.example.com": true, "deep.api.example.com": true,
		"notexample.com": false, "example.com.evil": false,
		"only.test": true, "child.only.test": true, "deep.child.only.test": false,
		"other.only.test": false, "otheronly.test": false,
		"proxy.only.test": true, "deep.proxy.only.test": true, "deep.covered.proxy.only.test": true,
		"ordinary.test": false,
	}
	checkSelectorMembership(t, m, config, checks)
	second, err := m.DNSMasqServers(5354)
	if err != nil || string(second) != want {
		t.Fatalf("compilation is not stable: %s, %v", second, err)
	}
}

func TestDNSMasqServersEmptyAndPortValidation(t *testing.T) {
	for _, m := range []*DomainMatcher{nil, newMatcher()} {
		for _, compile := range []func(int) ([]byte, error){m.DNSMasqServers, m.DNSMasqServersWithRegex} {
			config, err := compile(65535)
			if err != nil || len(config) != 0 {
				t.Fatalf("empty matcher: %s %v", config, err)
			}
			for _, port := range []int{-1, 0, 65536} {
				config, err := compile(port)
				if err == nil || config != nil {
					t.Fatalf("invalid port %d produced %q, %v", port, config, err)
				}
			}
		}
	}
}

func TestDNSMasqServersFiniteRegexpEquivalence(t *testing.T) {
	tests := []struct {
		pattern string
		queries map[string]bool
	}{
		{`^api\.example\.com$`, map[string]bool{"api.example.com": true, "a.api.example.com": false, "api.example.com.evil": false}},
		{`^v[12]\.example$`, map[string]bool{"v1.example": true, "v2.example": true, "v3.example": false, "a.v1.example": false}},
		{`^(one|two)\.example$`, map[string]bool{"one.example": true, "two.example": true, "a.one.example": false, "three.example": false}},
		{`^a\.example$|^b\.example$`, map[string]bool{"a.example": true, "b.example": true, "x.b.example": false}},
		{`^(ab){1,2}\.example$`, map[string]bool{"ab.example": true, "abab.example": true, "ababab.example": false}},
		{`^foo[-_]bar\.example$`, map[string]bool{"foo-bar.example": true, "foo_bar.example": true, "foo.bar.example": false}},
	}
	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			m := loadSelectorMatcher(t, "regexp:"+tt.pattern)
			config, err := m.DNSMasqServers(5354)
			if err != nil {
				t.Fatal(err)
			}
			checkSelectorMembership(t, m, config, tt.queries)
			extended, err := m.DNSMasqServersWithRegex(5354)
			if err != nil || string(extended) != string(config) {
				t.Fatalf("representable regexp unnecessarily requires extension: %s %v", extended, err)
			}
		})
	}
}

func TestDomainMatcherUsesDNSLabelBoundaries(t *testing.T) {
	m := loadSelectorMatcher(t, "domain:example.com")
	config, err := m.DNSMasqServers(5354)
	if err != nil {
		t.Fatal(err)
	}
	checkSelectorMembership(t, m, config, map[string]bool{
		"example.com.": true, "WWW.EXAMPLE.COM.": true, "deep.www.example.com": true,
		"notexample.com": false, "example.com.evil": false,
		`x\.example.com.`: false, `x\\\.example.com.`: false,
		`x\\.example.com.`: true, `x\.y.example.com.`: true,
		`x.y\.example.com.`: false, `example\.com.`: false,
	})
}

func TestDNSMasqServersRegexpPreservesPresentationBoundaries(t *testing.T) {
	patterns := []string{`(^|\.)example\.com$`, `(?:\A|\.)example\.com\z`, `^x.*\.example\.com$`}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			// A literal dot in a presentation regexp can match an embedded
			// escaped dot. The Domain rule cannot cover those names.
			m := loadSelectorMatcher(t, "domain:example.com", "regexp:"+pattern)
			if config, err := m.DNSMasqServers(5354); err == nil || config != nil {
				t.Fatalf("presentation regexp silently became a native suffix: %s, %v", config, err)
			}
			config, err := m.DNSMasqServersWithRegex(5354)
			if err != nil || !strings.Contains(string(config), "server=/regex:") {
				t.Fatalf("extended selector omitted the presentation regexp: %s, %v", config, err)
			}
			checkSelectorMembership(t, m, config, map[string]bool{
				"example.com.": true, "www.example.com.": true,
				`x\.example.com.`: true, `x\\\.example.com.`: true,
				"notexample.com": false, "example.com.evil": false,
			})
		})
	}
}

const (
	githubReleaseRegexp   = `^github-production-release-asset-[0-9a-zA-Z]{6}\.s3\.amazonaws\.com$`
	openAIWebPubSubRegexp = `^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$`
)

func TestDNSMasqServersUnsupportedIsAggregateAndAtomic(t *testing.T) {
	m := loadSelectorMatcher(t, "domain:good.example", "regexp:"+githubReleaseRegexp,
		"regexp:"+openAIWebPubSubRegexp, `regexp:^UPPER\.example$`,
		"domain:bad.example/server=/#/203.0.113.1", "full:bad\n.example")
	config, err := m.DNSMasqServers(5354)
	var report *DNSMasqCompileError
	if !errors.As(err, &report) || len(report.Unsupported) != 5 || config != nil {
		t.Fatalf("partial output or lost errors: %q, %#v, %v", config, report, err)
	}
	for _, rule := range report.Unsupported {
		if rule.Source == "" || rule.Kind == "" || rule.Value == "" || rule.Reason == "" {
			t.Fatalf("missing diagnostic provenance: %#v", rule)
		}
		if !strings.Contains(err.Error(), rule.Source) {
			t.Fatalf("aggregate message lost source %q: %v", rule.Source, err)
		}
	}
	if !m.Match("github-production-release-asset-a1b2c3.s3.amazonaws.com") ||
		!m.Match("chatgpt-async-webps-prod-eu-1.webpubsub.azure.com") ||
		!m.Match("GOOD.EXAMPLE.") || m.Match("UPPER.example") {
		t.Fatal("selector compilation changed runtime matching semantics")
	}
}

func TestDNSMasqServersRejectsAmbiguousRegexpAndUnsafeNames(t *testing.T) {
	rules := []string{
		`regexp:example\.com$`, `regexp:^[^.]+\.example$`, `regexp:(?i)^example$`,
		`regexp:^example\.com\.$`, `regexp:(?m)^example$`,
		"domain:.", "domain:.example.com", "domain:*.example.com", "domain:example..com",
		"full:example.com..", "domain:é.example", "domain:" + strings.Repeat("a", 64) + ".example",
	}
	for _, rule := range rules {
		t.Run(rule, func(t *testing.T) {
			m := loadSelectorMatcher(t, rule)
			config, err := m.DNSMasqServers(5354)
			if err == nil || config != nil {
				t.Fatalf("unsupported rule silently rewritten: %s, %v", config, err)
			}
		})
	}
}

func TestDNSMasqServersRegexpCoverageRequiresProof(t *testing.T) {
	tests := []struct {
		rules []string
		ok    bool
	}{
		{[]string{"domain:s3.amazonaws.com", "regexp:" + githubReleaseRegexp}, false},
		{[]string{`regexp:(^|\.)s3\.amazonaws\.com$`, "regexp:" + githubReleaseRegexp}, false},
		{[]string{"domain:amazonaws.com", "regexp:" + githubReleaseRegexp}, true},
		{[]string{"domain:amazonaws.com", `regexp:^prefix-\S+amazonaws\.com$`}, false},
		{[]string{"domain:s3.amazonaws.com", `regexp:^prefix\S+\.s3\.amazonaws\.com`}, false},
		{[]string{"domain:foo.test", "domain:bar.test", `regexp:^x.+\.foo\.test$|^y.+\.bar\.test$`}, false},
		{[]string{"domain:foo.test", `regexp:^x.+\.foo\.test$|^y.+\.bar\.test$`}, false},
		{[]string{"domain:foo.test", "domain:bar.test", `regexp:^x.+marker\.foo\.test$|^y.+marker\.bar\.test$`}, true},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.rules, "+"), func(t *testing.T) {
			m := loadSelectorMatcher(t, tt.rules...)
			config, err := m.DNSMasqServers(5354)
			if (err == nil) != tt.ok || (!tt.ok && config != nil) {
				t.Fatalf("coverage proof got %q, %v", config, err)
			}
		})
	}
}

func writeSelectorGeosite(t *testing.T, groups map[string][]geoDomain) string {
	t.Helper()
	var data []byte
	var names []string
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry := pbText(1, name)
		for _, rule := range groups[name] {
			domain := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), rule.kind)
			domain = append(domain, pbText(2, rule.value)...)
			var attrs []string
			for attr := range rule.attrs {
				attrs = append(attrs, attr)
			}
			sort.Strings(attrs)
			for _, attr := range attrs {
				value := uint64(0)
				if rule.attrs[attr] {
					value = 1
				}
				field := protowire.AppendVarint(protowire.AppendTag(pbText(1, attr), 2, protowire.VarintType), value)
				domain = protowire.AppendBytes(protowire.AppendTag(domain, 3, protowire.BytesType), field)
			}
			entry = protowire.AppendBytes(protowire.AppendTag(entry, 2, protowire.BytesType), domain)
		}
		data = protowire.AppendBytes(protowire.AppendTag(data, 1, protowire.BytesType), entry)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "geosite.dat"), data, 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDNSMasqGeositeTypeAttributesAndSourcePreservation(t *testing.T) {
	dir := writeSelectorGeosite(t, map[string][]geoDomain{"TEST": {
		{kind: 2, value: "DOMAIN.example", attrs: map[string]bool{"selected": true}},
		{kind: 3, value: "only.example", attrs: map[string]bool{"selected": true}},
		{kind: 0, value: "Needle", attrs: map[string]bool{"unsupported": true, "also": true}},
		{kind: 1, value: `^proxy\d+\.example$`, attrs: map[string]bool{"unsupported": true}},
	}})
	m, err := LoadDomainMatcher([]string{"geosite:TeSt@selected"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	config, err := m.DNSMasqServers(5354)
	if err != nil {
		t.Fatal(err)
	}
	checkSelectorMembership(t, m, config, map[string]bool{
		"domain.example": true, "sub.domain.example": true, "only.example": true,
		"sub.only.example": false, "hasneedle.example": false, "proxy1.example": false,
	})

	m, err = LoadDomainMatcher([]string{"geosite:TeSt@unsupported", "geosite:test@also", "geosite:test@unsupported"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	config, err = m.DNSMasqServers(5354)
	var report *DNSMasqCompileError
	if !errors.As(err, &report) || len(report.Unsupported) != 5 || config != nil {
		t.Fatalf("wrong expanded-source errors: %q, %#v, %v", config, report, err)
	}
	if !m.Match("hasNEEDLE.example") || !m.Match("proxy123.example") || m.Match("domain.example") {
		t.Fatal("Plain, Regex or attribute semantics changed")
	}

	m, err = LoadDomainMatcher([]string{"geosite:test@!unsupported"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Match("domain.example") || m.Match("proxy123.example") || m.Match("needle.example") {
		t.Fatal("inverted attribute semantics changed")
	}
}

func TestDNSMasqServersWithRegexLivePatternsAndFullUnion(t *testing.T) {
	m := loadSelectorMatcher(t, "domain:proxy.example", "full:s3.amazonaws.com", "full:only.test",
		"regexp:"+githubReleaseRegexp, "regexp:"+openAIWebPubSubRegexp, `regexp:^x\d+\.only\.test$`)
	config, err := m.DNSMasqServersWithRegex(5354)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(config), "/#") || strings.Contains(string(config), "server=/only.test/") ||
		!strings.Contains(string(config), "server=/regex:^only\\.test$/127.0.0.1#5354") ||
		!strings.Contains(string(config), "[^ ]") {
		t.Fatalf("extended configuration changes the OR of Full and Regex rules:\n%s", config)
	}
	checkSelectorMembership(t, m, config, map[string]bool{
		"proxy.example": true, "deep.proxy.example": true,
		"only.test": true, "x12.only.test": true, "unprotected.only.test": false,
		"s3.amazonaws.com": true, "unrelated.s3.amazonaws.com": false,
		"github-production-release-asset-a1b2C3.s3.amazonaws.com":      true,
		"github-production-release-asset-a1b2c.s3.amazonaws.com":       false,
		"github-production-release-asset-a1b2c34.s3.amazonaws.com":     false,
		"github-production-release-asset-a1b2c3.s3.amazonaws.com.evil": false,
		"chatgpt-async-webps-prod-eu-123.webpubsub.azure.com":          true,
		"chatgpt-async-webps-prod-eu.foo-123.webpubsub.azure.com":      true,
		"chatgpt-async-webps-prod--123.webpubsub.azure.com":            false,
		"chatgpt-async-webps-prod-eu-a.webpubsub.azure.com":            false,
		"chatgpt-async-webps-prod-eu 1-123.webpubsub.azure.com":        false,
		`chatgpt-async-webps-prod-eu\0091-123.webpubsub.azure.com`:     true,
		"unrelated.webpubsub.azure.com":                                false,
	})
}

func TestDNSMasqServersWithRegexPlainPreservesSubstring(t *testing.T) {
	m := newMatcher()
	if err := m.add(0, "Need.Le", "geosite:fixture"); err != nil {
		t.Fatal(err)
	}
	if err := m.add(3, "only.test"); err != nil {
		t.Fatal(err)
	}
	config, err := m.DNSMasqServersWithRegex(5354)
	if err != nil {
		t.Fatal(err)
	}
	checkSelectorMembership(t, m, config, map[string]bool{
		"need.le": true, "prefixneed.lepostfix.test": true, "needle.test": false,
		"only.test": true, "x.only.test": false,
	})
}

func TestPOSIXSelectorCharacterClassesMatchEveryPrintableASCIIByte(t *testing.T) {
	patterns := []string{`\S`, `\s`, `\d`, `\D`, `\w`, `\W`, `.`, `(?s:.)`, `[^.]`, `[a-z-]`, `[\]\\^\[-]`}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			re, err := syntax.Parse(pattern, syntax.Perl)
			if err != nil {
				t.Fatal(err)
			}
			ere, err := regexpPOSIXSelector(re)
			if err != nil {
				t.Fatal(err)
			}
			posix, err := regexp.CompilePOSIX(ere)
			if err != nil {
				t.Fatalf("invalid POSIX expression %q: %v", ere, err)
			}
			original := regexp.MustCompile(pattern)
			for c := rune(32); c <= 126; c++ {
				value := string(c)
				if posix.MatchString(value) != original.MatchString(value) {
					t.Fatalf("%q -> %q disagrees at character %q", pattern, ere, c)
				}
			}
		})
	}
}

func TestDNSMasqServersWithRegexRejectsUnprovenConversions(t *testing.T) {
	patterns := []string{`\bword\b`, `(?i)case`, `\p{Han}+`, `literal/slash`, `hash#tag`, `literal"quote`, `\n`, `(?m)^line$`, `x{256}`}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			m := loadSelectorMatcher(t, "domain:good.example", "regexp:"+pattern)
			config, err := m.DNSMasqServersWithRegex(5354)
			var report *DNSMasqCompileError
			if config != nil || !errors.As(err, &report) || len(report.Unsupported) != 1 {
				t.Fatalf("unsupported conversion not atomic: %q, %v", config, err)
			}
		})
	}
}

// This independent interpreter models dnsmasq's documented longest matching
// suffix selection and the regex extension's final check before default DNS.
// Native integration tests additionally exercise the real dnsmasq binary.
func selectorConfigMatches(t *testing.T, config []byte, query string) bool {
	t.Helper()
	name := canonicalName(query)
	longest, selected := -1, false
	var expressions []*regexp.Regexp
	for _, line := range strings.Split(strings.TrimSpace(string(config)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "/")
		if len(parts) != 3 || parts[0] != "server=" {
			t.Fatalf("invalid generated selector %q", line)
		}
		pattern, target := parts[1], parts[2]
		if strings.HasPrefix(pattern, "regex:") {
			re, err := regexp.CompilePOSIX(strings.TrimPrefix(pattern, "regex:"))
			if err != nil {
				t.Fatalf("invalid generated POSIX regex %q: %v", line, err)
			}
			expressions = append(expressions, re)
			continue
		}
		var matches bool
		if strings.HasPrefix(pattern, "*") {
			pattern = strings.TrimPrefix(pattern, "*")
			base := strings.TrimPrefix(pattern, ".")
			matches = name != base && dns.IsSubDomain(base, name)
		} else {
			matches = dns.IsSubDomain(pattern, name)
		}
		if matches && len(pattern) > longest {
			longest, selected = len(pattern), target != "#"
		}
	}
	if longest >= 0 {
		return selected
	}
	for _, re := range expressions {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

func checkSelectorMembership(t *testing.T, m *DomainMatcher, config []byte, checks map[string]bool) {
	t.Helper()
	for name, want := range checks {
		t.Run(fmt.Sprintf("query=%s", name), func(t *testing.T) {
			if got := m.Match(name); got != want {
				t.Fatalf("runtime Match(%q) = %t, want %t", name, got, want)
			}
			if got := selectorConfigMatches(t, config, name); got != want {
				t.Fatalf("generated selector(%q) = %t, want %t:\n%s", name, got, want, config)
			}
		})
	}
}
