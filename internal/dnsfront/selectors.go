package dnsfront

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type selectorRule struct {
	domains []string
	target  string
}

// A selector plan is supplied by the routing compiler, including an explicit
// empty plan for System mode. nil means the policy was not loaded; accepting it
// during installation would silently make every protected lookup direct.
func selectorRules(port int, data []byte) ([]selectorRule, error) {
	if port < 1 || port > 65535 || port == 53 {
		return nil, fmt.Errorf("invalid Guardian DNS upstream port %d", port)
	}
	if data == nil {
		return nil, errors.New("native DNS selectors were not provided")
	}
	want := fmt.Sprintf("127.0.0.1#%d", port)
	var rules []selectorRule
	for number, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		value, ok := strings.CutPrefix(line, "server=/")
		if !ok {
			return nil, fmt.Errorf("native DNS selector line %d must be a domain-specific server directive", number+1)
		}
		parts := strings.Split(value, "/")
		if len(parts) < 2 {
			return nil, fmt.Errorf("native DNS selector line %d has no upstream", number+1)
		}
		rule := selectorRule{domains: parts[:len(parts)-1], target: parts[len(parts)-1]}
		if rule.target != want && rule.target != "#" && rule.target != "" {
			return nil, fmt.Errorf("native DNS selector line %d has an unexpected upstream", number+1)
		}
		for _, domain := range rule.domains {
			if expression, regex := strings.CutPrefix(domain, "regex:"); regex {
				if expression == "" || strings.ContainsAny(expression, "\r\n\t\x00/#\"") || rule.target != want {
					return nil, fmt.Errorf("native DNS selector line %d has an invalid regex rule", number+1)
				}
				continue
			}
			if domain == "#" {
				continue // Explicit all-domain mode, never an implicit default.
			}
			if domain == "" || strings.ContainsAny(domain, " \t\r\x00@#=,\\\"") || strings.Contains(strings.TrimPrefix(domain, "*"), "*") {
				return nil, fmt.Errorf("native DNS selector line %d has an invalid domain", number+1)
			}
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// ValidateSelectors checks the directive whitelist, required native capability
// and real dnsmasq syntax before a caller changes policy or configuration. It
// leaves the active selector file and DNS service untouched.
func ValidateSelectors(port int, selectors []byte) error {
	return validateSelectorSyntax(port, selectors)
}

// The Go grammar above limits the plan to server directives before invoking
// dnsmasq's native syntax check. --test does not read --servers-file, so the
// staged bytes must be passed as --conf-file to validate their real syntax.
// An invalid plan never replaces the active file.
func validateSelectorSyntax(port int, data []byte) error {
	rules, err := selectorRules(port, data)
	if err != nil {
		return err
	}
	if err := requireRegexCapability(rules); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "vpn-guardian-dns-selectors-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "proxy.servers")
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	_, err = command("dnsmasq", "--test", "--conf-file="+path)
	return err
}

func requireRegexCapability(rules []selectorRule) error {
	for _, rule := range rules {
		for _, domain := range rule.domains {
			if !strings.HasPrefix(domain, "regex:") {
				continue
			}
			output, err := command("dnsmasq", "--version")
			if err != nil {
				return err
			}
			for _, token := range strings.Fields(string(output)) {
				if token == "regex-server" {
					return nil
				}
			}
			return errors.New("native DNS regex selectors require dnsmasq with the regex-server capability")
		}
	}
	return nil
}

// Local negative answers and private split-horizon overrides must not be
// displaced by a more specific proxy selector. Conversely, a preserved direct
// override must not carve a hole in a protected suffix.
func validateSelectorZones(port int, data, guards []byte, localServers []string) error {
	rules, err := selectorRules(port, data)
	if err != nil {
		return err
	}
	var localZones []string
	for _, line := range strings.Split(string(guards), "\n") {
		if value, ok := strings.CutPrefix(line, "local=/"); ok {
			zone := strings.TrimSuffix(value, "/")
			if zone != "" {
				localZones = append(localZones, strings.ToLower(zone))
			}
		}
	}
	for _, rule := range rules {
		if rule.target == "" {
			continue
		}
		for _, pattern := range rule.domains {
			if strings.HasPrefix(pattern, "regex:") {
				// The native extension checks local/address and explicit suffix
				// servers first. Its regexp is not a DNS suffix and must not be
				// normalized or expanded here.
				continue
			}
			if pattern == "#" {
				continue // Native local/private rules are more specific.
			}
			domain := strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(pattern), "*"), ".")
			for _, local := range localZones {
				if domain == local || strings.HasSuffix(domain, "."+local) {
					return fmt.Errorf("native DNS selector %q overrides local zone %q", pattern, local)
				}
			}
			if rule.target == "#" {
				continue
			}
			for _, local := range localServers {
				parts := strings.Split(local, "/")
				if len(parts) < 3 || parts[len(parts)-1] == "" {
					continue
				}
				for _, zone := range parts[1 : len(parts)-1] {
					zone = strings.TrimPrefix(strings.ToLower(zone), ".")
					if zone != "" && (domain == zone || strings.HasSuffix(domain, "."+zone) || strings.HasSuffix(zone, "."+domain)) {
						return fmt.Errorf("native DNS selector %q overlaps preserved split-horizon server %q", pattern, local)
					}
				}
			}
		}
	}
	return nil
}

// UpdateSelectors changes only native DNS dispatch and clears dnsmasq's cache.
// Its containing directory is bind-mounted into ujail, so atomic replacement
// remains visible to the running daemon. Capable dnsmasq acknowledges commit
// and cache invalidation synchronously; stock dnsmasq requires a restart.
func UpdateSelectors(port int, selectors []byte) error {
	if err := validateSelectorSyntax(port, selectors); err != nil {
		return err
	}
	if err := Check(port); err != nil {
		return fmt.Errorf("native DNS integration is not ready: %w", err)
	}
	s, err := LoadState("/")
	if err != nil {
		return err
	}
	guards, err := os.ReadFile(LocalConfigPath)
	if err != nil {
		return err
	}
	if err := validateSelectorZones(port, selectors, guards, s.Options["server"].Values); err != nil {
		return err
	}
	reload, err := selectorReloadAction(s, port)
	if err != nil {
		return err
	}
	return publishSelectors(SelectorsPath, selectors, reload)
}

func captureSelectors(root string, s *State) error {
	s.SelectorsCaptured = true
	s.SelectorsDirExists, s.SelectorsExists = false, false
	s.SelectorsData = nil
	s.SelectorsDirMode, s.SelectorsMode = 0, 0
	dir, err := os.Lstat(rooted(root, SelectorsDir))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		if !dir.IsDir() {
			return errors.New("native DNS selector directory is not a directory")
		}
		s.SelectorsDirExists, s.SelectorsDirMode = true, dir.Mode().Perm()
	}
	file, err := os.Lstat(rooted(root, SelectorsPath))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !file.Mode().IsRegular() {
		return errors.New("native DNS selector path is not a regular file")
	}
	s.SelectorsData, err = os.ReadFile(rooted(root, SelectorsPath))
	if err != nil {
		return err
	}
	s.SelectorsExists, s.SelectorsMode = true, file.Mode().Perm()
	return nil
}

func restoreSelectors(root string, s State) error {
	if !s.SelectorsCaptured {
		return nil
	}
	dir, path := rooted(root, SelectorsDir), rooted(root, SelectorsPath)
	if s.SelectorsDirExists {
		if err := os.MkdirAll(dir, s.SelectorsDirMode); err != nil {
			return err
		}
		if err := os.Chmod(dir, s.SelectorsDirMode); err != nil {
			return err
		}
	}
	if s.SelectorsExists {
		if err := atomicWrite(path, s.SelectorsData, s.SelectorsMode); err != nil {
			return err
		}
	} else if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	if !s.SelectorsDirExists {
		// Only remove our empty directory, never unrelated files added later.
		if err := os.Remove(dir); err != nil && !os.IsNotExist(err) && !errors.Is(err, syscall.ENOTEMPTY) {
			return err
		}
	}
	return nil
}
