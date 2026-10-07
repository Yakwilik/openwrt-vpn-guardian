package dnsproxy

import (
	"fmt"
	"regexp/syntax"
	"strings"
	"unicode"
)

// dnsmasq reads a configuration line into its 1025-byte name buffer. Leave
// room for the selector prefix, upstream address, port and newline. POSIX
// implementations are only required to support repetition bounds up to 255.
const (
	maxPOSIXSelectorBytes = 900
	maxPOSIXRepeat        = 255
)

func regexpPOSIXSelector(re *syntax.Regexp) (string, error) {
	value, err := renderPOSIXSelector(re)
	if err != nil {
		return "", err
	}
	if len(value) > maxPOSIXSelectorBytes {
		return "", fmt.Errorf("POSIX regular expression exceeds %d bytes supported by the dnsmasq config reader", maxPOSIXSelectorBytes)
	}
	return value, nil
}

// The regex-server capability matches miekg/dns presentation strings: printable
// ASCII, with special bytes escaped and other bytes written as backslash plus
// three decimal digits. A literal space remains a space after its backslash.
// This makes dot and RE2's non-newline dot equivalent, and makes the printable
// ASCII projection of a character class exact. In particular, RE2 \S is [^ ]
// here, not POSIX [^[:space:]] evaluated on an unescaped wire name.
func renderPOSIXSelector(re *syntax.Regexp) (string, error) {
	re = withoutRegexpCapture(re)
	switch re.Op {
	case syntax.OpEmptyMatch:
		return "a{0}", nil
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 {
			return "", fmt.Errorf("case-folded regular expression literals are not supported by the POSIX selector adapter")
		}
		return quotePOSIXSelector(string(re.Rune))
	case syntax.OpCharClass:
		if re.Flags&syntax.FoldCase != 0 {
			return "", fmt.Errorf("case-folded character classes are not supported by the POSIX selector adapter")
		}
		return posixSelectorClass(re.Rune)
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return ".", nil
	case syntax.OpBeginText:
		// Parentheses keep assertions special even when an anchor appears in
		// the middle of a concatenation, where POSIX otherwise permits a
		// literal interpretation of caret or dollar.
		return "(^)", nil
	case syntax.OpEndText:
		return "($)", nil
	case syntax.OpConcat, syntax.OpAlternate:
		parts := make([]string, 0, len(re.Sub))
		for _, child := range re.Sub {
			part, err := renderPOSIXSelector(child)
			if err != nil {
				return "", err
			}
			parts = append(parts, part)
		}
		if re.Op == syntax.OpAlternate {
			return "(" + strings.Join(parts, "|") + ")", nil
		}
		return strings.Join(parts, ""), nil
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		child, err := renderPOSIXSelector(re.Sub[0])
		if err != nil {
			return "", err
		}
		var repeat string
		switch re.Op {
		case syntax.OpStar:
			repeat = "*"
		case syntax.OpPlus:
			repeat = "+"
		case syntax.OpQuest:
			repeat = "?"
		case syntax.OpRepeat:
			if re.Min > maxPOSIXRepeat || re.Max > maxPOSIXRepeat {
				return "", fmt.Errorf("regular expression repetition exceeds portable POSIX limit %d", maxPOSIXRepeat)
			}
			if re.Min == re.Max {
				repeat = fmt.Sprintf("{%d}", re.Min)
			} else if re.Max < 0 {
				repeat = fmt.Sprintf("{%d,}", re.Min)
			} else {
				repeat = fmt.Sprintf("{%d,%d}", re.Min, re.Max)
			}
		}
		// Greedy versus non-greedy matching does not change boolean membership.
		return "(" + child + ")" + repeat, nil
	default:
		return "", fmt.Errorf("regular expression operation %s is not supported by the POSIX selector adapter", re.Op)
	}
}

func quotePOSIXSelector(value string) (string, error) {
	var out strings.Builder
	for _, c := range value {
		if err := validPOSIXConfigChar(c); err != nil {
			return "", err
		}
		if strings.ContainsRune(`\.^$*+?()[{|`, c) {
			out.WriteByte('\\')
		}
		out.WriteRune(c)
	}
	if out.Len() > maxPOSIXSelectorBytes {
		return "", fmt.Errorf("POSIX literal exceeds %d bytes supported by the dnsmasq config reader", maxPOSIXSelectorBytes)
	}
	return out.String(), nil
}

func validPOSIXConfigChar(c rune) error {
	if c < 32 || c > 126 || c == '/' || c == '#' || c == '"' {
		return fmt.Errorf("regular expression contains unsupported dnsmasq config character %q", c)
	}
	return nil
}

func posixSelectorClass(ranges []rune) (string, error) {
	var included [127]bool
	for i := 0; i < len(ranges); i += 2 {
		lo, hi := ranges[i], ranges[i+1]
		// Complements such as [^a], \D and \S include every non-ASCII rune.
		// Project these onto the known ASCII question representation. More
		// elaborate Unicode classes remain explicitly unsupported.
		if hi > 126 && (hi != unicode.MaxRune || lo > 127) {
			return "", fmt.Errorf("Unicode character classes are not supported by the POSIX selector adapter")
		}
		for c := rune(32); c <= 126; c++ {
			if c >= lo && c <= hi {
				included[c] = true
			}
		}
	}
	var positive, negative []rune
	for c := rune(32); c <= 126; c++ {
		if included[c] {
			positive = append(positive, c)
		} else {
			negative = append(negative, c)
		}
	}
	if len(positive) == 0 {
		return "", fmt.Errorf("character class has no printable ASCII matches in the DNS question representation")
	}
	if len(negative) == 0 {
		return ".", nil
	}
	if len(positive) == 1 {
		return quotePOSIXSelector(string(positive))
	}
	canEncode := func(chars []rune) bool {
		for _, c := range chars {
			if validPOSIXConfigChar(c) != nil {
				return false
			}
		}
		return true
	}
	if canEncode(positive) && (len(positive) <= len(negative) || !canEncode(negative)) {
		return explicitPOSIXClass(positive, false), nil
	}
	if canEncode(negative) {
		return explicitPOSIXClass(negative, true), nil
	}
	return "", fmt.Errorf("character class cannot be represented without dnsmasq config delimiters")
}

// Explicit members avoid locale-dependent ranges and character classes.
// A closing bracket must come first and a hyphen last. Doubling a backslash
// works both with POSIX literal-backslash brackets and libc escape handling.
func explicitPOSIXClass(chars []rune, negative bool) string {
	var members strings.Builder
	has := func(c rune) bool {
		for _, member := range chars {
			if member == c {
				return true
			}
		}
		return false
	}
	if has(']') {
		members.WriteByte(']')
	}
	for _, c := range chars {
		if c == ']' || c == '-' || c == '^' {
			continue
		}
		if c == '\\' {
			members.WriteByte('\\')
		}
		members.WriteRune(c)
	}
	if has('^') {
		if members.Len() == 0 && !negative && has('-') {
			return "[-^]"
		}
		members.WriteByte('^')
	}
	if has('-') {
		members.WriteByte('-')
	}
	if negative {
		return "[^" + members.String() + "]"
	}
	return "[" + members.String() + "]"
}
