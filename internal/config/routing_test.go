package config

import (
	"slices"
	"testing"
)

func TestRoutingRuleRoundTrip(t *testing.T) {
	rules := []RoutingRule{
		{Type: RoutingRuleGeosite, Value: "openai"},
		{Type: RoutingRuleDomain, Value: "jetbrains.com"},
		{Type: RoutingRuleFull, Value: "download.jetbrains.com"},
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
