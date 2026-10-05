package config

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode"
)

// ValidateInterfaceName checks Linux interface name constraints, not whether
// an interface exists. Presence is checked against the router during preflight.
func ValidateInterfaceName(name string) error {
	if name == "" || len(name) > 15 || name == "." || name == ".." {
		return errors.New("must be a Linux interface name of 1 to 15 bytes")
	}
	if strings.ContainsAny(name, "/:") || strings.ContainsFunc(name, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) {
		return errors.New("must not contain slashes, colons, whitespace or control characters")
	}
	return nil
}

// ValidateLANCIDR accepts IPv4 prefixes, including an interface address with its
// prefix length. Setup may use Prefix.Masked when persisting the network address.
func ValidateLANCIDR(value string) error {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return fmt.Errorf("must be an IPv4 CIDR: %w", err)
	}
	if !prefix.Addr().Is4() {
		return errors.New("must be an IPv4 CIDR")
	}
	return nil
}
