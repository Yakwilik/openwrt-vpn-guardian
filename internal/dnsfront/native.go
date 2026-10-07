package dnsfront

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

var ownedOptions = []string{"server", "noresolv", "resolvfile", "localuse", "extraconftext", "addnmount"}

func isManagedInclude(line string) bool {
	return line == "conf-file="+LocalConfigPath || line == "servers-file="+SelectorsPath
}

func nativeOptions(s State, current map[string]Option, own []netip.Addr) (map[string]Option, error) {
	servers, err := keepLocalServers(s.Options["server"].Values)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, raw := range s.Sources.Servers {
		endpoint, err := Endpoint(raw, own)
		if err != nil || seen[endpoint] {
			continue // Never restore the old loopback dispatcher as a default.
		}
		seen[endpoint] = true
		host, port, err := net.SplitHostPort(endpoint)
		if err != nil {
			return nil, err
		}
		if port != "53" {
			host += "#" + port
		}
		servers = append(servers, host)
	}
	resolvFile := s.Sources.ResolvFile
	if resolvFile != "" && (!filepath.IsAbs(resolvFile) || strings.ContainsAny(resolvFile, "\r\n\x00") || resolvFile == "/etc/resolv.conf" || resolvFile == "/tmp/resolv.conf") {
		return nil, fmt.Errorf("unsafe native DNS resolver file %q", resolvFile)
	}
	if len(seen) == 0 && resolvFile == "" {
		return nil, errors.New("no native system/WAN DNS source configured")
	}
	var extra []string
	for _, line := range strings.Split(strings.Join(current["extraconftext"].Values, "\n"), "\n") {
		if !isManagedInclude(strings.TrimSpace(line)) && strings.TrimSpace(line) != "" {
			extra = append(extra, line)
		}
	}
	extra = append(extra, "conf-file="+LocalConfigPath, "servers-file="+SelectorsPath)
	var mounts []string
	mounted := map[string]bool{}
	for _, path := range current["addnmount"].Values {
		if path != SelectorsPath && path != SelectorsDir && path != LocalConfigPath && !mounted[path] {
			mounts = append(mounts, path)
			mounted[path] = true
		}
	}
	mounts = append(mounts, LocalConfigPath, SelectorsDir)
	return map[string]Option{
		"server":        {Present: len(servers) != 0, Values: servers},
		"noresolv":      {Present: resolvFile == "", Values: []string{"1"}},
		"resolvfile":    {Present: resolvFile != "", Values: []string{resolvFile}},
		"localuse":      {Present: true, Values: []string{"0"}},
		"extraconftext": {Present: true, Values: []string{strings.Join(extra, "\n")}},
		"addnmount":     {Present: true, Values: mounts},
	}, nil
}

func sameNativeOptions(a, b map[string]Option) bool {
	for _, name := range ownedOptions {
		if a[name].Present != b[name].Present || (a[name].Present && !slices.Equal(a[name].Values, b[name].Values)) {
			return false
		}
	}
	return true
}

// Configure installs native dnsmasq split DNS. It restores ordinary upstreams
// and delegates only the supplied domain selectors to Guardian. Runtime changes
// use UpdateSelectors with synchronous acknowledgement where supported.
func Configure(port int, selectors []byte) error {
	if err := validateSelectorSyntax(port, selectors); err != nil {
		return err
	}
	s, err := Prepare()
	if err != nil {
		return err
	}
	before, err := Capture()
	if err != nil {
		return err
	}
	configuration, err := os.ReadFile(s.MainConfig)
	if err != nil {
		return err
	}
	guards := RenderGuards(string(configuration) + "\n" + string(before.LocalConfig))
	if err := validateSelectorZones(port, selectors, guards, s.Options["server"].Values); err != nil {
		return err
	}
	options, err := nativeOptions(s, before.Options, OwnAddresses())
	if err != nil {
		return err
	}
	wiringReady := checkNativeWiring(s, port) == nil && bytes.Equal(before.LocalConfig, guards) && sameNativeOptions(before.Options, options)
	rollback := func(cause error) error {
		if err := RestoreCheckpoint(before); err != nil {
			return errors.Join(cause, fmt.Errorf("restore previous DNS integration: %w", err))
		}
		return cause
	}
	// Managed bootstrap files must converge even when all dnsmasq wiring is
	// already correct; an old script must not survive the idempotent fast path.
	if err := configureBootstrap(s.Sources); err != nil {
		return rollback(err)
	}
	if wiringReady {
		return UpdateSelectors(port, selectors)
	}
	if err := os.MkdirAll(SelectorsDir, 0755); err != nil {
		return rollback(err)
	}
	if err := os.Chmod(SelectorsDir, 0755); err != nil {
		return rollback(err)
	}
	if err := atomicWrite(SelectorsPath, selectors, 0644); err != nil {
		return rollback(err)
	}
	if err := atomicWrite(LocalConfigPath, guards, 0644); err != nil {
		return rollback(err)
	}
	if _, err := command("dnsmasq", "--test", "--conf-file="+LocalConfigPath, "--servers-file="+SelectorsPath); err != nil {
		return rollback(err)
	}
	for _, name := range ownedOptions {
		if err := setOption(s.Section, name, options[name]); err != nil {
			return rollback(err)
		}
	}
	if _, err := command("uci", "commit", "dhcp"); err != nil {
		return rollback(err)
	}
	if err := os.Remove(filepath.Join(s.ConfDir, GuardName)); err != nil && !os.IsNotExist(err) {
		return rollback(err)
	}
	if err := removeOwnedIncludes(s.ConfDir); err != nil {
		return rollback(err)
	}
	if _, err := command("/etc/init.d/dnsmasq", "restart"); err != nil {
		return rollback(err)
	}
	if err := LinkBootstrap(); err != nil {
		return rollback(err)
	}
	if err := waitNativeDNSReady(port); err != nil {
		return rollback(err)
	}
	// Confirm that the jailed process actually read the mounted policy file.
	// Host-side readability and a listening socket alone cannot prove this.
	version, err := command("dnsmasq", "--version")
	if err != nil {
		return rollback(err)
	}
	if slices.Contains(strings.Fields(string(version)), "regex-server-ack") {
		reload, err := selectorReloadAction(s, port)
		if err != nil {
			return rollback(err)
		}
		if err := reload(); err != nil {
			return rollback(err)
		}
	}
	return nil
}

func bootstrapScriptFor(source Sources) string {
	path := source.ResolvFile
	if path == "" {
		path = "/dev/null" // Respect the original explicit noresolv setting.
	}
	quoted := "'" + strings.ReplaceAll(path, "'", "'\"'\"'") + "'"
	return strings.Replace(bootstrapScript, "wan="+WANResolvFile, "wan="+quoted, 1)
}

func configureBootstrap(source Sources) error {
	for _, file := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{BootstrapStatic, BootstrapSources(source, OwnAddresses()), 0644},
		{BootstrapHotplug, []byte(bootstrapHotplug), 0755},
		{BootstrapInit, []byte(bootstrapScriptFor(source)), 0755},
	} {
		have, err := os.ReadFile(file.path)
		if err != nil || !bytes.Equal(have, file.data) {
			if err := atomicWrite(file.path, file.data, file.mode); err != nil {
				return err
			}
		} else if err := os.Chmod(file.path, file.mode); err != nil {
			return err
		}
	}
	if _, err := command(BootstrapInit, "enable"); err != nil {
		return err
	}
	return LinkBootstrap()
}

func checkNativeConfig(configuration []byte, own []netip.Addr) error {
	hasSelectors, hasLocal, noResolv, hasNative := false, false, false, false
	resolvFile := ""
	for _, line := range strings.Split(string(configuration), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "servers-file="+SelectorsPath:
			hasSelectors = true
		case line == "conf-file="+LocalConfigPath:
			hasLocal = true
		case line == "no-resolv":
			noResolv = true
		case strings.HasPrefix(line, "resolv-file="):
			resolvFile = strings.TrimPrefix(line, "resolv-file=")
		case strings.HasPrefix(line, "server="):
			server := strings.TrimPrefix(line, "server=")
			if strings.HasPrefix(server, "/") {
				parts := strings.Split(server, "/")
				upstream := parts[len(parts)-1]
				if upstream != "" && upstream != "#" {
					host := strings.Trim(strings.Split(upstream, "#")[0], "[]")
					if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
						return errors.New("loopback DNS selectors must be managed by servers-file")
					}
				}
				continue
			}
			if _, err := Endpoint(server, own); err != nil {
				return fmt.Errorf("default dnsmasq upstream is not native/non-recursive: %s", server)
			}
			hasNative = true
		}
	}
	if !noResolv && filepath.IsAbs(resolvFile) && resolvFile != "/etc/resolv.conf" && resolvFile != "/tmp/resolv.conf" {
		hasNative = true
	}
	if !hasSelectors || !hasLocal || !hasNative {
		var missing []string
		if !hasSelectors {
			missing = append(missing, "servers-file="+SelectorsPath)
		}
		if !hasLocal {
			missing = append(missing, "conf-file="+LocalConfigPath)
		}
		if !hasNative {
			missing = append(missing, "non-recursive default upstream (server=IP or enabled absolute resolv-file)")
		}
		return fmt.Errorf("native dnsmasq wiring is incomplete: missing %s", strings.Join(missing, "; "))
	}
	return nil
}

// OpenWrt writes extraconftext to extraconfig.conf in the active conf-dir,
// rather than into the main generated configuration. Read only that known
// generated file; unrelated dynamic conf-dir contents are outside our scope.
func checkNativeConfigFile(mainConfig string, own []netip.Addr) error {
	configuration, err := os.ReadFile(mainConfig)
	if err != nil {
		return err
	}
	checked := []string{mainConfig}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(configuration), "\n") {
		value, ok := strings.CutPrefix(strings.TrimSpace(line), "conf-dir=")
		if !ok {
			continue
		}
		parts := strings.Split(value, ",")
		if !filepath.IsAbs(parts[0]) || strings.ContainsAny(value, "\"\\\r\n\x00") {
			return fmt.Errorf("unsupported native dnsmasq conf-dir in %s: %q", mainConfig, value)
		}
		if !confDirIncludesExtraConfig(parts[1:]) {
			continue
		}
		path := filepath.Join(parts[0], "extraconfig.conf")
		if seen[path] {
			continue
		}
		seen[path] = true
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			continue // Optional when the generated main file has the includes.
		}
		if err != nil {
			return fmt.Errorf("inspect active OpenWrt extra configuration %s: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			continue // dnsmasq conf-dir loads only regular files (following links).
		}
		extra, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read active OpenWrt extra configuration %s: %w", path, err)
		}
		checked = append(checked, path)
		configuration = append(configuration, '\n')
		configuration = append(configuration, extra...)
	}
	if err := checkNativeConfig(configuration, own); err != nil {
		return fmt.Errorf("dnsmasq configuration %s: %w", strings.Join(checked, ", "), err)
	}
	return nil
}

// Match dnsmasq's conf-dir suffix rules for its fixed OpenWrt extra filename.
// A bare '*' is a no-op; positive filters require a match, and exclusions win.
func confDirIncludesExtraConfig(filters []string) bool {
	const name = "extraconfig.conf"
	hasRequired, matchesRequired := false, false
	for _, filter := range filters {
		if filter == "" || filter == "*" {
			continue
		}
		if suffix, required := strings.CutPrefix(filter, "*"); required {
			hasRequired = true
			matchesRequired = matchesRequired || len(name) > len(suffix) && strings.HasSuffix(name, suffix)
		} else if len(name) > len(filter) && strings.HasSuffix(name, filter) {
			return false
		}
	}
	return !hasRequired || matchesRequired
}

func checkNativeWiring(s State, port int) error {
	if err := checkNativeConfigFile(s.MainConfig, OwnAddresses()); err != nil {
		return err
	}
	mounts := option(s.Section, "addnmount").Values
	directoryMounted := false
	for _, mount := range mounts {
		if mount == SelectorsPath {
			return errors.New("native DNS selectors require a directory mount, not a file mount")
		}
		if mount == SelectorsDir {
			directoryMounted = true
		}
	}
	if !directoryMounted {
		return errors.New("native DNS selector directory is not mounted into dnsmasq")
	}
	dir, err := os.Lstat(SelectorsDir)
	if err != nil {
		return err
	}
	if !dir.IsDir() || dir.Mode().Perm()&0005 != 0005 {
		return errors.New("native DNS selector directory is not readable by dnsmasq")
	}
	file, err := os.Lstat(SelectorsPath)
	if err != nil {
		return err
	}
	if !file.Mode().IsRegular() || file.Mode().Perm()&0004 == 0 {
		return errors.New("native DNS selectors are not readable by dnsmasq")
	}
	selectors, err := os.ReadFile(SelectorsPath)
	if err != nil {
		return err
	}
	rules, err := selectorRules(port, selectors)
	if err != nil {
		return err
	}
	if err := requireRegexCapability(rules); err != nil {
		return err
	}
	guards, err := os.ReadFile(LocalConfigPath)
	if err != nil {
		return err
	}
	return validateSelectorZones(port, selectors, guards, s.Options["server"].Values)
}

// Check validates active native dispatch, not merely the presence of our files.
// It does not require the protected upstream to be alive: that must not make
// ordinary or local DNS dependent on Guardian's availability.
func Check(port int) error {
	s, err := LoadState("/")
	if err != nil {
		return err
	}
	if err := checkNativeWiring(s, port); err != nil {
		return err
	}
	for _, file := range []struct {
		path string
		data []byte
	}{
		{BootstrapInit, []byte(bootstrapScriptFor(s.Sources))},
		{BootstrapHotplug, []byte(bootstrapHotplug)},
		{BootstrapStatic, BootstrapSources(s.Sources, OwnAddresses())},
	} {
		data, err := os.ReadFile(file.path)
		if err != nil {
			return err
		}
		if !bytes.Equal(data, file.data) {
			return fmt.Errorf("managed bootstrap file is outdated: %s", file.path)
		}
		if file.path != BootstrapStatic {
			info, err := os.Stat(file.path)
			if err != nil {
				return err
			}
			if info.Mode().Perm()&0111 == 0 {
				return fmt.Errorf("managed bootstrap file is not executable: %s", file.path)
			}
		}
	}
	if link, err := os.Readlink("/tmp/resolv.conf"); err != nil || link != BootstrapResolv {
		return errors.New("router bootstrap DNS is not independent")
	}
	return nil
}
