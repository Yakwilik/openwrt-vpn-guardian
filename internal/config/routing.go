package config

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode/utf8"
)

type RoutingRuleType string

const (
	RoutingRuleGeosite RoutingRuleType = "geosite"
	RoutingRuleDomain  RoutingRuleType = "domain"
	RoutingRuleFull    RoutingRuleType = "full"
	RoutingRuleRegexp  RoutingRuleType = "regexp"
	RoutingRuleIP      RoutingRuleType = "ip"
	RoutingRuleGeoIP   RoutingRuleType = "geoip"
)

type RoutingRule struct {
	Type  RoutingRuleType `json:"type"`
	Value string          `json:"value"`
	Note  string          `json:"note,omitempty"`
	Group string          `json:"group,omitempty"`
}

// RoutingGroup is display metadata and never changes the network dataplane.
type RoutingGroup struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

var routingGroupIDPattern = regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")

func validateRoutingGroup(g RoutingGroup) error {
	if !routingGroupIDPattern.MatchString(g.ID) {
		return fmt.Errorf("invalid group id %q", g.ID)
	}
	if strings.TrimSpace(g.Name) != g.Name || g.Name == "" ||
		utf8.RuneCountInString(g.Name) > 80 || strings.ContainsAny(g.Name, "\r\n\x00") {
		return fmt.Errorf("group name must have 1–80 characters without surrounding whitespace or control characters")
	}
	if strings.TrimSpace(g.Description) != g.Description ||
		utf8.RuneCountInString(g.Description) > 300 ||
		strings.ContainsAny(g.Description, "\r\n\x00") {
		return fmt.Errorf("group description must have at most 300 characters without newlines")
	}
	return nil
}

type RoutingRuleOption struct {
	Value RoutingRuleType
	Label string
}

func RoutingRuleOptions() []RoutingRuleOption {
	return []RoutingRuleOption{
		{Value: RoutingRuleGeosite, Label: "Geosite"},
		{Value: RoutingRuleDomain, Label: "Domain"},
		{Value: RoutingRuleFull, Label: "Full domain"},
		{Value: RoutingRuleRegexp, Label: "Regexp"},
		{Value: RoutingRuleIP, Label: "IP / CIDR"},
		{Value: RoutingRuleGeoIP, Label: "GeoIP"},
	}
}

func (r Routing) Rules() ([]RoutingRule, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r.RulesUnchecked()
}

// RoutingFromRules preserves the original ungrouped caller contract.
func RoutingFromRules(rules []RoutingRule) (Routing, error) {
	return RoutingFromRulesWithGroups(rules, nil)
}

func RoutingFromRulesWithGroups(rules []RoutingRule, groups []RoutingGroup) (Routing, error) {
	out := Routing{Version: Version, Notes: make(map[string]string),
		RuleGroups: make(map[string]string), Groups: append([]RoutingGroup(nil), groups...)}
	seen := make(map[string]struct{}, len(rules))

	for i, rule := range rules {
		stored, domainRule, err := rule.storedValue()
		if err != nil {
			return Routing{}, fmt.Errorf("routing rule %d: %w", i, err)
		}
		key := fmt.Sprintf("%t:%s", domainRule, stored)
		if _, exists := seen[key]; exists {
			return Routing{}, fmt.Errorf("routing rule %d duplicates %q", i, stored)
		}
		seen[key] = struct{}{}

		note, err := normalizeRoutingNote(rule.Note)
		if err != nil {
			return Routing{}, fmt.Errorf("routing rule %d: %w", i, err)
		}
		if note != "" {
			out.Notes[stored] = note
		}
		if rule.Group != "" {
			out.RuleGroups[stored] = rule.Group
		}
		if domainRule {
			out.ProxyDomains = append(out.ProxyDomains, stored)
		} else {
			out.ProxyIPs = append(out.ProxyIPs, stored)
		}
	}
	if len(out.Notes) == 0 {
		out.Notes = nil
	}
	if len(out.RuleGroups) == 0 {
		out.RuleGroups = nil
	}
	if err := out.Validate(); err != nil {
		return Routing{}, err
	}
	return out, nil
}

func normalizeRoutingNote(note string) (string, error) {
	note = strings.TrimSpace(note)
	if note == "" {
		return "", nil
	}
	if strings.ContainsAny(note, "\r\n") {
		return "", fmt.Errorf("note must be a single line")
	}
	if len([]rune(note)) > 200 {
		return "", fmt.Errorf("note must be at most 200 characters")
	}
	return note, nil
}

func (r RoutingRule) storedValue() (string, bool, error) {
	value := strings.TrimSpace(r.Value)
	if value == "" {
		return "", false, fmt.Errorf("%s value must not be empty", r.Type)
	}

	switch r.Type {
	case RoutingRuleGeosite, RoutingRuleDomain, RoutingRuleFull:
		if strings.ContainsAny(value, " \t\r\n") {
			return "", false, fmt.Errorf("%s value must not contain whitespace", r.Type)
		}
		return string(r.Type) + ":" + value, true, nil
	case RoutingRuleRegexp:
		if _, err := regexp.Compile(value); err != nil {
			return "", false, fmt.Errorf("invalid regexp: %w", err)
		}
		return "regexp:" + value, true, nil
	case RoutingRuleIP:
		if net.ParseIP(value) == nil {
			if _, _, err := net.ParseCIDR(value); err != nil {
				return "", false, fmt.Errorf("invalid IP or CIDR %q", value)
			}
		}
		return value, false, nil
	case RoutingRuleGeoIP:
		if strings.ContainsAny(value, " \t\r\n") {
			return "", false, fmt.Errorf("geoip value must not contain whitespace")
		}
		return "geoip:" + value, false, nil
	default:
		return "", false, fmt.Errorf("unsupported routing rule type %q", r.Type)
	}
}

func parseStoredRoutingRule(raw string, domainRule bool) (RoutingRule, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return RoutingRule{}, fmt.Errorf("routing entry must not be empty")
	}

	if domainRule {
		for _, typ := range []RoutingRuleType{
			RoutingRuleGeosite,
			RoutingRuleDomain,
			RoutingRuleFull,
			RoutingRuleRegexp,
		} {
			prefix := string(typ) + ":"
			if strings.HasPrefix(raw, prefix) {
				rule := RoutingRule{Type: typ, Value: strings.TrimPrefix(raw, prefix)}
				if _, _, err := rule.storedValue(); err != nil {
					return RoutingRule{}, err
				}
				return rule, nil
			}
		}
		return RoutingRule{}, fmt.Errorf("unsupported domain routing entry %q", raw)
	}

	if strings.HasPrefix(raw, "geoip:") {
		rule := RoutingRule{Type: RoutingRuleGeoIP, Value: strings.TrimPrefix(raw, "geoip:")}
		if _, _, err := rule.storedValue(); err != nil {
			return RoutingRule{}, err
		}
		return rule, nil
	}
	rule := RoutingRule{Type: RoutingRuleIP, Value: raw}
	if _, _, err := rule.storedValue(); err != nil {
		return RoutingRule{}, err
	}
	return rule, nil
}
