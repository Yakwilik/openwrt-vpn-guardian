package dnsproxy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

// DomainMatcher uses the same full/domain/regexp and geosite.dat semantics as
// the Xray front. IP-only routing rules cannot classify a DNS question before
// it is resolved and deliberately do not become DNS domain rules.
type DomainMatcher struct {
	full   map[string]struct{}
	suffix map[string]struct{}
	plain  []string
	regex  []*regexp.Regexp
}

func newMatcher() *DomainMatcher {
	return &DomainMatcher{full: map[string]struct{}{}, suffix: map[string]struct{}{}}
}
func canonicalName(s string) string { return strings.TrimSuffix(strings.ToLower(s), ".") }
func (m *DomainMatcher) Match(name string) bool {
	if m == nil {
		return false
	}
	name = canonicalName(name)
	if _, ok := m.full[name]; ok {
		return true
	}
	for suffix := name; suffix != ""; {
		if _, ok := m.suffix[suffix]; ok {
			return true
		}
		i := strings.IndexByte(suffix, '.')
		if i < 0 {
			break
		}
		suffix = suffix[i+1:]
	}
	for _, p := range m.plain {
		if strings.Contains(name, p) {
			return true
		}
	}
	for _, r := range m.regex {
		if r.MatchString(name) {
			return true
		}
	}
	return false
}
func (m *DomainMatcher) add(kind uint64, value string) error {
	if value == "" {
		return fmt.Errorf("empty domain rule")
	}
	switch kind {
	case 0:
		m.plain = append(m.plain, strings.ToLower(value))
	case 1:
		r, err := regexp.Compile(value)
		if err != nil {
			return err
		}
		m.regex = append(m.regex, r)
	case 2:
		m.suffix[canonicalName(value)] = struct{}{}
	case 3:
		m.full[canonicalName(value)] = struct{}{}
	default:
		return fmt.Errorf("unknown geosite domain type %d", kind)
	}
	return nil
}

type geoDomain struct {
	kind  uint64
	value string
	attrs map[string]bool
}

// walkProto checks wire lengths instead of trusting third-party geodata. This
// reader intentionally depends only on protobuf wire decoding, not Xray's core.
func walkProto(b []byte, visit func(protowire.Number, protowire.Type, []byte, uint64) error) error {
	for len(b) > 0 {
		number, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		var data []byte
		var value uint64
		switch typ {
		case protowire.BytesType:
			data, n = protowire.ConsumeBytes(b)
		case protowire.VarintType:
			value, n = protowire.ConsumeVarint(b)
		default:
			n = protowire.ConsumeFieldValue(number, typ, b)
		}
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		if err := visit(number, typ, data, value); err != nil {
			return err
		}
	}
	return nil
}

func parseGeoDomain(b []byte) (geoDomain, error) {
	d := geoDomain{attrs: map[string]bool{}}
	err := walkProto(b, func(n protowire.Number, t protowire.Type, b []byte, v uint64) error {
		switch {
		case n == 1 && t == protowire.VarintType:
			d.kind = v
		case n == 2 && t == protowire.BytesType:
			d.value = string(b)
		case n == 3 && t == protowire.BytesType:
			var key string
			enabled := false
			if err := walkProto(b, func(n protowire.Number, t protowire.Type, b []byte, v uint64) error {
				if n == 1 && t == protowire.BytesType {
					key = strings.ToLower(string(b))
				}
				if n == 2 && t == protowire.VarintType {
					enabled = v != 0
				}
				return nil
			}); err != nil {
				return err
			}
			if key != "" {
				d.attrs[key] = enabled
			}
		}
		return nil
	})
	return d, err
}

func LoadDomainMatcher(rules []string, assetsDir string) (*DomainMatcher, error) {
	m := newMatcher()
	groups := map[string][][]string{}
	for _, rule := range rules {
		typ, value, ok := strings.Cut(rule, ":")
		if !ok {
			return nil, fmt.Errorf("invalid domain rule %q", rule)
		}
		var kind uint64
		switch typ {
		case "full":
			kind = 3
		case "domain":
			kind = 2
		case "regexp":
			kind = 1
		case "geosite":
			parts := strings.Split(strings.ToLower(value), "@")
			groups[parts[0]] = append(groups[parts[0]], parts[1:])
			continue
		default:
			return nil, fmt.Errorf("unsupported DNS routing rule %q", typ)
		}
		if err := m.add(kind, value); err != nil {
			return nil, fmt.Errorf("%s: %w", rule, err)
		}
	}
	if len(groups) == 0 {
		return m, nil
	}
	file := filepath.Join(assetsDir, "geosite.dat")
	st, err := os.Stat(file)
	if err != nil {
		return nil, err
	}
	if st.Size() > 64<<20 {
		return nil, fmt.Errorf("geosite.dat exceeds 64 MiB")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	found := map[string]bool{}
	err = walkProto(data, func(n protowire.Number, t protowire.Type, b []byte, _ uint64) error {
		if n != 1 || t != protowire.BytesType {
			return nil
		}
		var code string
		var entries [][]byte
		if err := walkProto(b, func(n protowire.Number, t protowire.Type, b []byte, _ uint64) error {
			if n == 1 && t == protowire.BytesType {
				code = strings.ToLower(string(b))
			}
			if n == 2 && t == protowire.BytesType {
				entries = append(entries, b)
			}
			return nil
		}); err != nil {
			return err
		}
		filters, needed := groups[code]
		if !needed {
			return nil
		}
		found[code] = true
		for _, entry := range entries {
			d, err := parseGeoDomain(entry)
			if err != nil {
				return err
			}
			include := false
			for _, attrs := range filters {
				matches := true
				for _, attr := range attrs {
					invert := strings.HasPrefix(attr, "!")
					key := strings.TrimPrefix(attr, "!")
					if key == "" || d.attrs[key] == invert {
						matches = false
						break
					}
				}
				if matches {
					include = true
					break
				}
			}
			if include {
				if err := m.add(d.kind, d.value); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse geosite.dat: %w", err)
	}
	for group := range groups {
		if !found[group] {
			return nil, fmt.Errorf("geosite group %q not found", group)
		}
	}
	return m, nil
}
