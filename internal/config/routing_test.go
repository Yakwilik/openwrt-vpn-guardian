package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestRoutingRuleRoundTrip(t *testing.T) {
	rules := []RoutingRule{
		{Type: RoutingRuleGeosite, Value: "openai", Note: "OpenAI / ChatGPT"},
		{Type: RoutingRuleDomain, Value: "jetbrains.com", Note: "JetBrains updates"},
		{Type: RoutingRuleFull, Value: "download.jetbrains.com", Note: "Exact download host"},
		{Type: RoutingRuleRegexp, Value: "^cdn\\d+\\.example\\.com$"},
		{Type: RoutingRuleIP, Value: "203.0.113.0/24"},
		{Type: RoutingRuleGeoIP, Value: "us"},
	}

	routing, err := RoutingFromRules(rules)
	if err != nil {
		t.Fatalf("RoutingFromRules: %v", err)
	}
	got, err := routing.Rules()
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	if !slices.Equal(got, rules) {
		t.Fatalf("round trip = %#v, want %#v", got, rules)
	}
}

func TestRoutingFromRulesRejectsInvalidValues(t *testing.T) {
	tests := []RoutingRule{
		{Type: RoutingRuleIP, Value: "not-an-ip"},
		{Type: RoutingRuleRegexp, Value: "["},
		{Type: RoutingRuleDomain, Value: "has whitespace.example com"},
		{Type: "unknown", Value: "value"},
	}

	for _, rule := range tests {
		t.Run(string(rule.Type)+"/"+rule.Value, func(t *testing.T) {
			if _, err := RoutingFromRules([]RoutingRule{rule}); err == nil {
				t.Fatalf("expected validation failure for %#v", rule)
			}
		})
	}
}

func TestRoutingFromRulesRejectsDuplicates(t *testing.T) {
	_, err := RoutingFromRules([]RoutingRule{
		{Type: RoutingRuleDomain, Value: "jetbrains.com"},
		{Type: RoutingRuleDomain, Value: "jetbrains.com"},
	})
	if err == nil {
		t.Fatal("duplicate routing rules must be rejected")
	}
}

func TestRoutingNotesAreValidated(t *testing.T) {
	tooLong := strings.Repeat("x", 201)
	tests := []RoutingRule{
		{Type: RoutingRuleDomain, Value: "example.com", Note: "line one\nline two"},
		{Type: RoutingRuleDomain, Value: "example.com", Note: tooLong},
	}
	for _, rule := range tests {
		if _, err := RoutingFromRules([]RoutingRule{rule}); err == nil {
			t.Fatalf("expected invalid note to fail: %#v", rule)
		}
	}
}

func TestRoutingRejectsOrphanNote(t *testing.T) {
	routing := Routing{
		Version:      Version,
		ProxyDomains: []string{"domain:example.com"},
		Notes:        map[string]string{"domain:missing.example": "orphan"},
	}
	if err := routing.Validate(); err == nil {
		t.Fatal("orphan routing note must fail validation")
	}
}

func TestRoutingGroupsRoundTripPreservesRulesAndEmptyGroups(t *testing.T) {
	groups := []RoutingGroup{
		{ID: "telegram", Name: "Telegram", Description: "Домены и адреса Telegram"},
		{ID: "empty", Name: "Новая группа"},
	}
	rules := []RoutingRule{
		{Type: RoutingRuleGeosite, Value: "telegram", Group: "telegram"},
		{Type: RoutingRuleIP, Value: "91.108.8.0/22", Note: "IPv4", Group: "telegram"},
		{Type: RoutingRuleDomain, Value: "example.com", Note: "No group"},
	}
	routing, err := RoutingFromRulesWithGroups(rules, groups)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(routing.Groups, groups) {
		t.Fatalf("groups were not persisted: %#v", routing.Groups)
	}
	want, err := routing.Rules()
	if err != nil {
		t.Fatal(err)
	}
	gotGroups := map[string]string{}
	for _, entry := range want {
		gotGroups[string(entry.Type)+":"+entry.Value] = entry.Group
	}
	if gotGroups["geosite:telegram"] != "telegram" ||
		gotGroups["ip:91.108.8.0/22"] != "telegram" ||
		gotGroups["domain:example.com"] != "" {
		t.Fatalf("group membership was lost: %#v", want)
	}
	if len(routing.ProxyDomains) != 2 || len(routing.ProxyIPs) != 1 {
		t.Fatalf("grouping changed network routes: %#v", routing)
	}
}

func TestRoutingGroupsRejectInvalidOrOrphanMetadata(t *testing.T) {
	rule := []RoutingRule{{Type: RoutingRuleDomain, Value: "example.com"}}
	tests := []struct {
		name   string
		groups []RoutingGroup
		group  string
	}{
		{"orphan", nil, "missing"},
		{"duplicate", []RoutingGroup{{ID: "a", Name: "One"}, {ID: "a", Name: "Two"}}, ""},
		{"bad id", []RoutingGroup{{ID: "bad id", Name: "Broken"}}, ""},
		{"empty name", []RoutingGroup{{ID: "a", Name: ""}}, ""},
		{"description too long", []RoutingGroup{{ID: "a", Name: "A", Description: strings.Repeat("x", 301)}}, ""},
		{"name too long", []RoutingGroup{{ID: "a", Name: strings.Repeat("x", 81)}}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provided := append([]RoutingRule(nil), rule...)
			provided[0].Group = tc.group
			if _, err := RoutingFromRulesWithGroups(provided, tc.groups); err == nil {
				t.Fatalf("accepted invalid group metadata: %#v, %q", tc.groups, tc.group)
			}
		})
	}
	if err := (Routing{
		Version:      Version,
		ProxyDomains: []string{"domain:example.com"},
		Groups:       []RoutingGroup{{ID: "a", Name: "A"}},
		RuleGroups:   map[string]string{"domain:missing.example": "a"},
	}).Validate(); err == nil {
		t.Fatal("orphan group mapping was accepted")
	}
}

func TestLegacyRoutingFilesWithoutGroupsStayValid(t *testing.T) {
	legacy := Routing{
		Version:      Version,
		ProxyDomains: []string{"geosite:telegram"},
		ProxyIPs:     []string{"91.108.8.0/22"},
		Notes:        map[string]string{"91.108.8.0/22": "Telegram"},
	}
	if err := legacy.Validate(); err != nil {
		t.Fatal(err)
	}
	rules, err := legacy.Rules()
	if err != nil || len(rules) != 2 || rules[0].Group != "" || rules[1].Group != "" {
		t.Fatalf("legacy routing changed: %#v, %v", rules, err)
	}
}

func TestGroupedRoutingPersistsAcrossFileSaveAndReload(t *testing.T) {
	groups := []RoutingGroup{{ID: "telegram", Name: "Telegram", Description: "Домены и IP"}}
	rules := []RoutingRule{
		{Type: RoutingRuleGeosite, Value: "telegram", Group: "telegram"},
		{Type: RoutingRuleIP, Value: "91.108.8.0/22", Group: "telegram"},
		{Type: RoutingRuleDomain, Value: "auth.kimi.ai", Note: "Kimi auth"},
	}
	want, err := RoutingFromRulesWithGroups(rules, groups)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "routing.json")
	if err := saveRoutingFile(path, want); err != nil {
		t.Fatal(err)
	}
	var got Routing
	if err := readJSON(path, &got); err != nil {
		t.Fatal(err)
	}
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Groups, want.Groups) {
		t.Fatalf("groups not persisted: %#v", got.Groups)
	}
	if got.RuleGroups["91.108.8.0/22"] != "telegram" {
		t.Fatalf("membership lost: %#v", got.RuleGroups)
	}
	if got.Notes["domain:auth.kimi.ai"] != "Kimi auth" {
		t.Fatalf("notes lost: %#v", got.Notes)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("routing manifest permissions: %v %v", info, err)
	}
}
