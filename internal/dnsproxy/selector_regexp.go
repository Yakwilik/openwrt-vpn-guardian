package dnsproxy

import (
	"fmt"
	"regexp/syntax"
)

// A finite regexp can still encode billions of names. Keep generation bounded
// and report the original rule rather than emitting a truncated expansion.
const maxSelectorRegexpNames = 256

func withoutRegexpCapture(re *syntax.Regexp) *syntax.Regexp {
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	return re
}

func regexpConcatParts(re *syntax.Regexp) []*syntax.Regexp {
	re = withoutRegexpCapture(re)
	if re.Op != syntax.OpConcat {
		return []*syntax.Regexp{re}
	}
	var parts []*syntax.Regexp
	for _, child := range re.Sub {
		parts = append(parts, regexpConcatParts(child)...)
	}
	return parts
}

// Recognize only the start assertion (^|\.), not an optional dot or an
// arbitrary-prefix wildcard, which have different domain-boundary semantics.
func regexpDomainBoundary(re *syntax.Regexp) bool {
	re = withoutRegexpCapture(re)
	if re.Op != syntax.OpAlternate || len(re.Sub) != 2 {
		return false
	}
	a, b := withoutRegexpCapture(re.Sub[0]), withoutRegexpCapture(re.Sub[1])
	if b.Op == syntax.OpBeginText {
		a, b = b, a
	}
	return a.Op == syntax.OpBeginText && b.Op == syntax.OpLiteral && len(b.Rune) == 1 && b.Rune[0] == '.'
}

func regexpDNSMasqRules(re *syntax.Regexp) ([]dnsMasqRuleKey, error) {
	re = withoutRegexpCapture(re)
	if re.Op == syntax.OpAlternate {
		var rules []dnsMasqRuleKey
		for _, branch := range re.Sub {
			expanded, err := regexpDNSMasqRules(branch)
			if err != nil {
				return nil, err
			}
			rules = append(rules, expanded...)
			if len(rules) > maxSelectorRegexpNames {
				return nil, fmt.Errorf("finite regular expression expansion exceeds %d selectors", maxSelectorRegexpNames)
			}
		}
		return rules, nil
	}

	parts := regexpConcatParts(re)
	if len(parts) < 3 || parts[len(parts)-1].Op != syntax.OpEndText {
		return nil, fmt.Errorf("dnsmasq requires an anchored finite name regular expression")
	}
	var kind uint64
	switch {
	case parts[0].Op == syntax.OpBeginText:
		kind = 3
	case regexpDomainBoundary(parts[0]):
		return nil, fmt.Errorf("a presentation regexp dot can match inside an escaped DNS label; a native domain selector cannot preserve that boundary")
	default:
		return nil, fmt.Errorf("regular expression start cannot be represented as an exact name or a domain-boundary selector")
	}
	names, err := finiteRegexpNames(&syntax.Regexp{Op: syntax.OpConcat, Sub: parts[1 : len(parts)-1]})
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("empty regular expression language is not a DNS selector")
	}
	rules := make([]dnsMasqRuleKey, 0, len(names))
	for _, name := range names {
		// Regex is case-sensitive and Match canonicalizes the question first.
		// Do not lowercase or trim regex literals as if they were Domain rules.
		if name != canonicalName(name) {
			return nil, fmt.Errorf("regular expression contains a noncanonical literal; normalizing it would change its matching semantics")
		}
		if err := validSelectorName(name); err != nil {
			return nil, err
		}
		rules = append(rules, dnsMasqRuleKey{kind, name})
	}
	return rules, nil
}

func finiteRegexpNames(re *syntax.Regexp) ([]string, error) {
	re = withoutRegexpCapture(re)
	switch re.Op {
	case syntax.OpEmptyMatch:
		return []string{""}, nil
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 {
			return nil, fmt.Errorf("case-folded regular expression literals require matching beyond native DNS suffix semantics")
		}
		value := string(re.Rune)
		if len(value) > 253 {
			return nil, fmt.Errorf("regular expression expansion contains a name longer than 253 bytes")
		}
		return []string{value}, nil
	case syntax.OpCharClass:
		var values []string
		for i := 0; i < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			if lo < 32 || hi > 126 {
				return nil, fmt.Errorf("regular expression character class cannot be expanded into native ASCII DNS names")
			}
			for r := lo; r <= hi; r++ {
				values = append(values, string(r))
				if len(values) > maxSelectorRegexpNames {
					return nil, fmt.Errorf("finite regular expression expansion exceeds %d names", maxSelectorRegexpNames)
				}
			}
		}
		return values, nil
	case syntax.OpConcat:
		values := []string{""}
		for _, child := range re.Sub {
			next, err := finiteRegexpNames(child)
			if err != nil {
				return nil, err
			}
			values, err = regexpNameProduct(values, next)
			if err != nil {
				return nil, err
			}
		}
		return values, nil
	case syntax.OpAlternate:
		var values []string
		for _, child := range re.Sub {
			next, err := finiteRegexpNames(child)
			if err != nil {
				return nil, err
			}
			values, err = regexpNameUnion(values, next)
			if err != nil {
				return nil, err
			}
		}
		return values, nil
	case syntax.OpQuest:
		values, err := finiteRegexpNames(re.Sub[0])
		if err != nil {
			return nil, err
		}
		return regexpNameUnion([]string{""}, values)
	case syntax.OpRepeat:
		if re.Max < 0 {
			return nil, fmt.Errorf("unbounded regular expression repetition has no native dnsmasq domain selector")
		}
		unit, err := finiteRegexpNames(re.Sub[0])
		if err != nil {
			return nil, err
		}
		current := []string{""}
		var values []string
		for n := 0; n <= re.Max; n++ {
			if n >= re.Min {
				values, err = regexpNameUnion(values, current)
				if err != nil {
					return nil, err
				}
			}
			if n < re.Max {
				current, err = regexpNameProduct(current, unit)
				if err != nil {
					return nil, err
				}
			}
		}
		return values, nil
	default:
		return nil, fmt.Errorf("regular expression operation %s has no finite native dnsmasq selector", re.Op)
	}
}

func regexpNameUnion(a, b []string) ([]string, error) {
	values := make(map[string]struct{}, len(a)+len(b))
	for _, set := range [][]string{a, b} {
		for _, name := range set {
			values[name] = struct{}{}
			if len(values) > maxSelectorRegexpNames {
				return nil, fmt.Errorf("finite regular expression expansion exceeds %d names", maxSelectorRegexpNames)
			}
		}
	}
	return sortedSelectorNames(values), nil
}

func regexpNameProduct(a, b []string) ([]string, error) {
	values := make(map[string]struct{})
	for _, prefix := range a {
		for _, suffix := range b {
			name := prefix + suffix
			if len(name) > 253 {
				return nil, fmt.Errorf("regular expression expansion contains a name longer than 253 bytes")
			}
			values[name] = struct{}{}
			if len(values) > maxSelectorRegexpNames {
				return nil, fmt.Errorf("finite regular expression expansion exceeds %d names", maxSelectorRegexpNames)
			}
		}
	}
	return sortedSelectorNames(values), nil
}

// A regexp need not be expanded when it can only match names already covered
// by a Domain rule. Prove coverage using an end-of-text anchor and a mandatory
// case-sensitive literal suffix with a provably unescaped dot boundary. A dot
// at the start of the mandatory suffix may follow a backslash matched by an
// earlier expression and is not sufficient. Do not infer coverage merely from
// a substring appearing somewhere in the regexp source.
func regexpCoveredByDomains(re *syntax.Regexp, suffixes map[string]struct{}) bool {
	re = withoutRegexpCapture(re)
	if re.Op == syntax.OpAlternate {
		for _, branch := range re.Sub {
			if !regexpCoveredByDomains(branch, suffixes) {
				return false
			}
		}
		return len(re.Sub) > 0
	}
	parts := regexpConcatParts(re)
	if len(parts) < 2 || parts[len(parts)-1].Op != syntax.OpEndText {
		return false
	}
	var literal string
	for i := len(parts) - 2; i >= 0; i-- {
		part := parts[i]
		if part.Op != syntax.OpLiteral || part.Flags&syntax.FoldCase != 0 {
			break
		}
		literal = string(part.Rune) + literal
	}
	for i := 1; i < len(literal); i++ {
		if literal[i] != '.' || literal[i-1] == '\\' {
			continue
		}
		if _, ok := suffixes[literal[i+1:]]; ok {
			return true
		}
	}
	return false
}
