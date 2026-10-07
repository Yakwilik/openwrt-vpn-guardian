package dnsfront

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func command(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".guardian-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
func option(section, name string) Option {
	out, err := command("uci", "-q", "get", "dhcp."+section+"."+name)
	if err != nil {
		return Option{}
	}
	value := strings.TrimSpace(string(out))
	values := []string{value}
	if name == "server" || name == "addnmount" {
		values = strings.Fields(value)
	}
	return Option{Present: true, Values: values}
}

// Prepare saves only the options owned by this integration. It is idempotent;
// an upgrade must not mistake its own 127.0.0.1 upstream for the system source.
func Prepare() (State, error) {
	if s, err := LoadState("/"); err == nil {
		return s, nil
	} else if !os.IsNotExist(err) {
		return State{}, err
	}
	out, err := command("uci", "-X", "show", "dhcp")
	if err != nil {
		return State{}, err
	}
	var sections []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "dhcp.") && strings.HasSuffix(line, "=dnsmasq") {
			sections = append(sections, strings.TrimSuffix(strings.TrimPrefix(line, "dhcp."), "=dnsmasq"))
		}
	}
	if len(sections) != 1 {
		return State{}, fmt.Errorf("DNS migration requires one unambiguous dnsmasq instance, found %d", len(sections))
	}
	s := State{Version: 1, Section: sections[0], Options: map[string]Option{}}
	for _, k := range []string{"server", "noresolv", "localuse", "extraconftext", "addnmount"} {
		s.Options[k] = option(s.Section, k)
	}
	port := option(s.Section, "port")
	if port.Present && strings.Join(port.Values, "") != "53" {
		return State{}, errors.New("client dnsmasq must listen on port 53")
	}
	s.MainConfig = "/var/etc/dnsmasq.conf." + s.Section
	b, err := os.ReadFile(s.MainConfig)
	if err != nil {
		return State{}, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "conf-dir=") {
			s.ConfDir = strings.Split(strings.TrimPrefix(line, "conf-dir="), ",")[0]
		}
	}
	if !filepath.IsAbs(s.ConfDir) {
		return State{}, errors.New("dnsmasq conf-dir is not configured")
	}
	s.Sources.ResolvFile = WANResolvFile
	rf := option(s.Section, "resolvfile")
	if rf.Present {
		s.Sources.ResolvFile = strings.Join(rf.Values, "")
	}
	if strings.Join(s.Options["noresolv"].Values, "") == "1" {
		s.Sources.ResolvFile = ""
	}
	for _, v := range s.Options["server"].Values {
		if !strings.HasPrefix(v, "/") {
			s.Sources.Servers = append(s.Sources.Servers, v)
		}
	}
	if _, err := keepLocalServers(s.Options["server"].Values); err != nil {
		return State{}, err
	}
	s.Guard, err = os.ReadFile(filepath.Join(s.ConfDir, GuardName))
	s.GuardExists = err == nil
	if err != nil && !os.IsNotExist(err) {
		return State{}, err
	}
	s.ResolvLink, err = os.Readlink("/tmp/resolv.conf")
	if err != nil {
		s.ResolvData, err = os.ReadFile("/tmp/resolv.conf")
		if err != nil && !os.IsNotExist(err) {
			return State{}, err
		}
	}
	s.LocalConfig, err = os.ReadFile(LocalConfigPath)
	s.LocalExists = err == nil
	if err != nil && !os.IsNotExist(err) {
		return State{}, err
	}
	s.BootConfig, err = os.ReadFile(BootstrapInit)
	s.BootExists = err == nil
	if err != nil && !os.IsNotExist(err) {
		return State{}, err
	}
	s.StaticData, err = os.ReadFile(BootstrapStatic)
	s.StaticExists = err == nil
	if err != nil && !os.IsNotExist(err) {
		return State{}, err
	}
	s.HookData, err = os.ReadFile(BootstrapHotplug)
	s.HookExists = err == nil
	if err != nil && !os.IsNotExist(err) {
		return State{}, err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return State{}, err
	}
	if err := atomicWrite(StatePath, data, 0600); err != nil {
		return State{}, err
	}
	return s, nil
}

// Only actual local/split-horizon zones may bypass the external policy. Unknown
// external per-domain server overrides fail validation rather than leak DNS.
func keepLocalServers(servers []string) ([]string, error) {
	var result []string
	for _, value := range servers {
		if !strings.HasPrefix(value, "/") {
			continue
		}
		parts := strings.Split(value, "/")
		target := parts[len(parts)-1]
		if target == "" {
			result = append(result, value)
			continue
		}
		host := strings.Split(target, "#")[0]
		host = strings.Trim(host, "[]")
		ip := net.ParseIP(strings.Split(host, "%")[0])
		if ip == nil || ip.IsLoopback() || !(ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
			return nil, fmt.Errorf("external/recursive dnsmasq per-domain override must be removed before migration: %s", value)
		}
		result = append(result, value)
	}
	return result, nil
}
func setOption(section, name string, value Option) error {
	key := "dhcp." + section + "." + name
	if _, err := command("uci", "-q", "get", key); err == nil {
		if _, err = command("uci", "-q", "delete", key); err != nil {
			return err
		}
	}
	if !value.Present {
		return nil
	}
	for _, v := range value.Values {
		verb := "set"
		if name == "server" || name == "addnmount" {
			verb = "add_list"
		}
		if _, err := command("uci", verb, key+"="+v); err != nil {
			return err
		}
	}
	return nil
}

// RenderGuards generates dnsmasq-owned local zones, not a Guardian question
// classifier. Static address-only zones also need local= for non-A queries.
func RenderGuards(configuration string) []byte {
	zones := map[string]bool{"home.arpa": true, "lan": true, "local": true, "localhost": true, "invalid": true, "test": true, "onion": true}
	for _, line := range strings.Split(configuration, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		if k == "domain" {
			zones[strings.Split(v, ",")[0]] = true
		}
		if k == "address" && strings.HasPrefix(v, "/") {
			p := strings.Split(v, "/")
			for _, z := range p[1 : len(p)-1] {
				zones[z] = true
			}
		}
	}
	names := make([]string, 0, len(zones))
	for z := range zones {
		if z != "" && !strings.ContainsAny(z, "/#\r\n =,\t*") {
			names = append(names, z)
		}
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("# Managed by vpn-guardian: dnsmasq owns local answers, including negatives.\ndomain-needed\nbogus-priv\nlocal=//\n")
	for _, z := range names {
		fmt.Fprintf(&b, "local=/%s/\n", z)
	}
	return []byte(b.String())
}

// Configure wires the already-running loopback Guardian upstream into native
// dnsmasq. This is an installation operation; runtime DNS mode changes do NOT
// call it or restart dnsmasq/DHCP/VPN.
func Configure(port int) error {
	if Check(port) == nil {
		return nil
	}
	s, err := Prepare()
	if err != nil {
		return err
	}
	keep, err := keepLocalServers(s.Options["server"].Values)
	if err != nil {
		return err
	}
	desired := append(keep, fmt.Sprintf("127.0.0.1#%d", port))
	extra := strings.Join(s.Options["extraconftext"].Values, "\n")
	extra = strings.TrimSpace(extra + "\nconf-file=" + LocalConfigPath)
	mounts := append([]string{}, s.Options["addnmount"].Values...)
	mounts = append(mounts, LocalConfigPath)

	opts := map[string]Option{"server": {Present: true, Values: desired}, "noresolv": {Present: true, Values: []string{"1"}}, "localuse": {Present: true, Values: []string{"0"}}, "extraconftext": {Present: true, Values: []string{extra}}, "addnmount": {Present: true, Values: mounts}}
	for _, k := range []string{"server", "noresolv", "localuse", "extraconftext", "addnmount"} {
		if err := setOption(s.Section, k, opts[k]); err != nil {
			return err
		}
	}
	if _, err := command("uci", "commit", "dhcp"); err != nil {
		return err
	}
	conf, err := os.ReadFile(s.MainConfig)
	if err != nil {
		return err
	}
	// Preserve existing no-forward guards during migration; hosts/leases themselves
	// remain owned by dnsmasq and never enter the Guardian resolver.
	guards := RenderGuards(string(conf))
	if err := atomicWrite(LocalConfigPath, guards, 0644); err != nil {
		return err
	}
	if _, err := command("dnsmasq", "--test", "--conf-file="+LocalConfigPath); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(s.ConfDir, GuardName)); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := atomicWrite(BootstrapStatic, BootstrapSources(s.Sources, OwnAddresses()), 0644); err != nil {
		return err
	}
	if err := atomicWrite(BootstrapHotplug, []byte(bootstrapHotplug), 0755); err != nil {
		return err
	}
	if err := atomicWrite(BootstrapInit, []byte(bootstrapScript), 0755); err != nil {
		return err
	}
	if _, err := command(BootstrapInit, "enable"); err != nil {
		return err
	}
	if _, err := command("dnsmasq", "--test", "--conf-file="+s.MainConfig); err != nil {
		return err
	}
	if err := LinkBootstrap(); err != nil {
		return err
	}
	if _, err := command("/etc/init.d/dnsmasq", "restart"); err != nil {
		return err
	}
	if err := LinkBootstrap(); err != nil {
		return err
	}
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		c, e := net.DialTimeout("tcp", "127.0.0.1:53", 150*time.Millisecond)
		if e == nil {
			c.Close()
			return Check(port)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("dnsmasq did not become ready")
}

// Refresh is a shell-only operation: original static system servers plus
// current netifd WAN DNS, without any running Guardian resolver or VPN.
func LinkBootstrap() error {
	_, err := command(BootstrapInit, "start")
	return err
}

func Check(port int) error {
	s, err := LoadState("/")
	if err != nil {
		return err
	}
	b, err := os.ReadFile(s.MainConfig)
	if err != nil {
		return err
	}
	needle := fmt.Sprintf("server=127.0.0.1#%d", port)
	hasServer, hasNoResolv := false, false
	for _, line := range strings.Split(string(b), "\n") {
		if line == needle {
			hasServer = true
		}
		if line == "no-resolv" {
			hasNoResolv = true
		}
		if strings.HasPrefix(line, "server=") && !strings.HasPrefix(line, "server=/") && line != needle {
			return fmt.Errorf("unexpected default dnsmasq upstream: %s", line)
		}
	}
	if _, err := os.Stat(LocalConfigPath); err != nil {
		return err
	}
	if _, err := os.Stat(BootstrapInit); err != nil {
		return err
	}
	if !hasServer || !hasNoResolv {
		return errors.New("dnsmasq upstream wiring is incomplete")
	}
	if link, err := os.Readlink("/tmp/resolv.conf"); err != nil || link != BootstrapResolv {
		return errors.New("router bootstrap DNS is not independent")
	}
	return nil
}

// Restore only integration-owned settings; DHCP leases, hosts and unrelated
// administrative changes are never replaced by an old full configuration.
func Restore() error {
	s, err := LoadState("/")
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := RestoreCheckpoint(s); err != nil {
		return err
	}
	return os.Remove(StatePath)
}

func Capture() (State, error) {
	s, err := Prepare()
	if err != nil {
		return s, err
	}
	s.Options = map[string]Option{}
	for _, k := range []string{"server", "noresolv", "localuse", "extraconftext", "addnmount"} {
		s.Options[k] = option(s.Section, k)
	}
	s.Guard, err = os.ReadFile(filepath.Join(s.ConfDir, GuardName))
	s.GuardExists = err == nil
	if err != nil && !os.IsNotExist(err) {
		return s, err
	}
	s.LocalConfig, err = os.ReadFile(LocalConfigPath)
	s.LocalExists = err == nil
	if err != nil && !os.IsNotExist(err) {
		return s, err
	}
	s.BootConfig, err = os.ReadFile(BootstrapInit)
	s.BootExists = err == nil
	if err != nil && !os.IsNotExist(err) {
		return s, err
	}
	s.ResolvLink, err = os.Readlink("/tmp/resolv.conf")
	s.ResolvData = nil
	if err != nil {
		s.ResolvData, err = os.ReadFile("/tmp/resolv.conf")
		if err != nil && !os.IsNotExist(err) {
			return s, err
		}
	}
	s.StaticData, err = os.ReadFile(BootstrapStatic)
	s.StaticExists = err == nil
	if err != nil && !os.IsNotExist(err) {
		return s, err
	}
	s.HookData, err = os.ReadFile(BootstrapHotplug)
	s.HookExists = err == nil
	if err != nil && !os.IsNotExist(err) {
		return s, err
	}
	return s, nil
}
func RestoreCheckpoint(s State) error {
	var err error
	for _, name := range []string{"server", "noresolv", "localuse", "extraconftext", "addnmount"} {
		if err := setOption(s.Section, name, s.Options[name]); err != nil {
			return err
		}
	}
	if _, err := command("uci", "commit", "dhcp"); err != nil {
		return err
	}
	guard := filepath.Join(s.ConfDir, GuardName)
	if s.GuardExists {
		err = atomicWrite(guard, s.Guard, 0644)
	} else {
		err = os.Remove(guard)
		if os.IsNotExist(err) {
			err = nil
		}
	}
	if err != nil {
		return err
	}
	if err := removeOwnedIncludes(s.ConfDir); err != nil {
		return err
	}
	if s.LocalExists {
		if err := atomicWrite(LocalConfigPath, s.LocalConfig, 0644); err != nil {
			return err
		}
	} else {
		_ = os.Remove(LocalConfigPath)
	}
	if s.BootExists {
		if err := atomicWrite(BootstrapInit, s.BootConfig, 0755); err != nil {
			return err
		}
	} else {
		if _, err := os.Stat(BootstrapInit); err == nil {
			_, _ = command(BootstrapInit, "disable")
			_ = os.Remove(BootstrapInit)
		}
	}
	if s.StaticExists {
		if err := atomicWrite(BootstrapStatic, s.StaticData, 0644); err != nil {
			return err
		}
	} else {
		_ = os.Remove(BootstrapStatic)
	}
	if s.HookExists {
		if err := atomicWrite(BootstrapHotplug, s.HookData, 0755); err != nil {
			return err
		}
	} else {
		_ = os.Remove(BootstrapHotplug)
	}
	if _, err := command("/etc/init.d/dnsmasq", "restart"); err != nil {
		return err
	}
	if s.ResolvLink != "" {
		tmp := "/tmp/resolv.conf.guardian-new"
		_ = os.Remove(tmp)
		if err := os.Symlink(s.ResolvLink, tmp); err != nil {
			return err
		}
		if err := os.Rename(tmp, "/tmp/resolv.conf"); err != nil {
			return err
		}
	} else if len(s.ResolvData) > 0 {
		if err := atomicWrite("/tmp/resolv.conf", s.ResolvData, 0644); err != nil {
			return err
		}
	}
	return nil
}

const bootstrapScript = `#!/bin/sh /etc/rc.common
START=18
STOP=99
start() {
  [ -f /etc/vpn-guardian/dnsmasq-state.json ] || return 0
  local own tmp wan
  own=$(mktemp /tmp/vg-dns-own.XXXXXX) || return 1
  tmp=$(mktemp /tmp/vg-dns-resolv.XXXXXX) || { rm -f "$own"; return 1; }
  wan=/tmp/resolv.conf.d/resolv.conf.auto
  [ -r "$wan" ] || wan=/dev/null
  ip -o addr show | awk '{split($4,a,"/"); print a[1]}' >"$own"
  awk 'FNR==NR {own[$1]=1;next} $1=="nameserver" {host=$2;sub(/%.*/,"",host);if(host~/^127\./ || host=="::1" || host=="0.0.0.0" || own[host] || seen[$2]++)next;print "nameserver " $2}' "$own" /etc/vpn-guardian/bootstrap-resolv.static "$wan" >"$tmp"
  rm -f "$own"
  grep -q '^nameserver ' "$tmp" || { rm -f "$tmp"; return 1; }
  chmod 644 "$tmp"
  mv "$tmp" /tmp/vpn-guardian-resolv.conf || return 1
  ln -sfn /tmp/vpn-guardian-resolv.conf /tmp/resolv.conf
}
reload() { start; }
`

const bootstrapHotplug = `#!/bin/sh
case "$ACTION" in ifup|ifupdate) ;; *) exit 0 ;; esac
[ -f /etc/vpn-guardian/dnsmasq-state.json ] || exit 0
[ -x /etc/init.d/vpn-guardian-dns-bootstrap ] || exit 0
/etc/init.d/vpn-guardian-dns-bootstrap start
`

// HUP clears caches without restarting DHCP/DNS. OpenWrt runs dnsmasq
// inside ujail, so its pidfile contains a PID from another PID namespace
// (often 1). Never signal that PID in the host namespace: procd owns delivery.
func ClearCache() error {
	state, err := LoadState("/")
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{"name": "dnsmasq", "instance": state.Section, "signal": 1})
	if err != nil {
		return err
	}
	_, err = command("ubus", "call", "service", "signal", string(body))
	return err
}

func removeOwnedIncludes(directory string) error {
	entries, err := os.ReadDir(directory)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var kept []string
		changed := false
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) == "conf-file="+LocalConfigPath {
				changed = true
				continue
			}
			kept = append(kept, line)
		}
		if !changed {
			continue
		}
		result := strings.Join(kept, "\n")
		if strings.TrimSpace(result) == "" {
			err = os.Remove(path)
		} else {
			err = atomicWrite(path, []byte(result), 0644)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
