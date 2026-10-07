// Package dnsfront owns the dnsmasq integration. The external Guardian resolver
// has no knowledge of DHCP leases, hosts, or local-zone dispatch.
package dnsfront

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const StatePath = "/etc/vpn-guardian/dnsmasq-state.json"
const WANResolvFile = "/tmp/resolv.conf.d/resolv.conf.auto"
const GuardName = "vpn-guardian-local.conf"
const LocalConfigPath = "/etc/vpn-guardian/dnsmasq-local.conf"
const SelectorsDir = "/etc/vpn-guardian/dnsmasq.d"
const SelectorsPath = SelectorsDir + "/proxy.servers"
const BootstrapInit = "/etc/init.d/vpn-guardian-dns-bootstrap"
const BootstrapStatic = "/etc/vpn-guardian/bootstrap-resolv.static"
const BootstrapResolv = "/tmp/vpn-guardian-resolv.conf"
const BootstrapHotplug = "/etc/hotplug.d/iface/98-vpn-guardian-dns-bootstrap"

// Sources are captured before replacing dnsmasq's default upstream. The WAN
// resolver file remains owned and refreshed by netifd, not by Guardian.
type Sources struct {
	Servers    []string `json:"servers"`
	ResolvFile string   `json:"resolvFile"`
}

type Option struct {
	Present bool     `json:"present"`
	Values  []string `json:"values,omitempty"`
}

type State struct {
	SelectorsData      []byte            `json:"selectorsData,omitempty"`
	SelectorsExists    bool              `json:"selectorsExists"`
	SelectorsMode      os.FileMode       `json:"selectorsMode,omitempty"`
	SelectorsDirExists bool              `json:"selectorsDirExists"`
	SelectorsDirMode   os.FileMode       `json:"selectorsDirMode,omitempty"`
	SelectorsCaptured  bool              `json:"selectorsCaptured,omitempty"`
	StaticData         []byte            `json:"staticData,omitempty"`
	StaticExists       bool              `json:"staticExists"`
	HookData           []byte            `json:"hookData,omitempty"`
	HookExists         bool              `json:"hookExists"`
	LocalConfig        []byte            `json:"localConfig,omitempty"`
	LocalExists        bool              `json:"localExists"`
	BootConfig         []byte            `json:"bootConfig,omitempty"`
	BootExists         bool              `json:"bootExists"`
	Version            int               `json:"version"`
	Section            string            `json:"section"`
	MainConfig         string            `json:"mainConfig"`
	ConfDir            string            `json:"confDir"`
	Sources            Sources           `json:"sources"`
	Options            map[string]Option `json:"options"`
	Guard              []byte            `json:"guard,omitempty"`
	GuardExists        bool              `json:"guardExists"`
	ResolvLink         string            `json:"resolvLink,omitempty"`
	ResolvData         []byte            `json:"resolvData,omitempty"`
}

func rooted(root, path string) string { return filepath.Join(root, strings.TrimPrefix(path, "/")) }

func LoadState(root string) (State, error) {
	var s State
	b, err := os.ReadFile(rooted(root, StatePath))
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, err
	}
	if s.Version != 1 || s.Section == "" {
		return s, errors.New("invalid dnsmasq integration state")
	}
	return s, nil
}

// Endpoint never performs name resolution. Rejecting loopback and router-owned
// addresses makes dnsmasq -> Guardian -> dnsmasq recursion impossible.
func Endpoint(value string, own []netip.Addr) (string, error) {
	value = strings.TrimSpace(value)
	host, port := value, "53"
	if i := strings.LastIndex(value, "#"); i >= 0 {
		host, port = value[:i], value[i+1:]
	} else if _, err := netip.ParseAddr(value); err != nil {
		var e error
		host, port, e = net.SplitHostPort(value)
		if e != nil {
			return "", fmt.Errorf("DNS upstream must be a numeric IP: %q", value)
		}
	}
	host = strings.Trim(host, "[]")
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", fmt.Errorf("invalid DNS upstream %q", value)
	}
	addr = addr.Unmap()
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return "", fmt.Errorf("invalid DNS upstream port %q", value)
	}
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || addr.String() == "255.255.255.255" {
		return "", fmt.Errorf("recursive or invalid DNS upstream %q", value)
	}
	for _, local := range own {
		if addr.WithZone("") == local.Unmap().WithZone("") {
			return "", fmt.Errorf("DNS upstream points to this router: %s", value)
		}
	}
	return net.JoinHostPort(addr.String(), strconv.Itoa(int(p))), nil
}

func OwnAddresses() []netip.Addr {
	var own []netip.Addr
	addresses, _ := net.InterfaceAddrs()
	for _, a := range addresses {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			own = append(own, p.Addr())
		}
	}
	return own
}

func ReadResolvers(root string, own []netip.Addr) ([]string, error) {
	state, err := LoadState(root)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	source := state.Sources
	if os.IsNotExist(err) {
		// Used for validation before the first migration, never read /etc/resolv.conf.
		source.ResolvFile = WANResolvFile
		files, _ := filepath.Glob(rooted(root, "/var/etc/dnsmasq.conf.*"))
		for _, file := range files {
			b, e := os.ReadFile(file)
			if e != nil {
				return nil, e
			}
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "server=") {
					v := strings.TrimPrefix(line, "server=")
					if !strings.HasPrefix(v, "/") {
						source.Servers = append(source.Servers, v)
					}
				}
				if strings.HasPrefix(line, "resolv-file=") {
					source.ResolvFile = strings.TrimPrefix(line, "resolv-file=")
				}
				if line == "no-resolv" {
					source.ResolvFile = ""
				}
			}
		}
	}
	values := append([]string{}, source.Servers...)
	if source.ResolvFile != "" {
		f, e := os.Open(rooted(root, source.ResolvFile))
		if e != nil && !os.IsNotExist(e) {
			return nil, e
		}
		if e == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				fields := strings.Fields(sc.Text())
				if len(fields) >= 2 && fields[0] == "nameserver" {
					values = append(values, fields[1])
				}
			}
			e = sc.Err()
			f.Close()
			if e != nil {
				return nil, e
			}
		}
	}
	seen := map[string]bool{}
	var result []string
	for _, raw := range values {
		endpoint, e := Endpoint(raw, own)
		if e != nil {
			continue
		} // Never let a self-reference cause recursive packets.
		if !seen[endpoint] {
			seen[endpoint] = true
			result = append(result, endpoint)
		}
	}
	if len(result) == 0 {
		return nil, errors.New("no non-recursive system/WAN DNS upstream available")
	}
	return result, nil
}

// resolv.conf has no port syntax. Retain all original standard-port static
// upstreams there; non-standard endpoints remain supported by Guardian's direct
// system path, while netifd supplies ordinary WAN bootstrap servers.
func BootstrapSources(source Sources, own []netip.Addr) []byte {
	var b strings.Builder
	seen := map[string]bool{}
	for _, v := range source.Servers {
		ep, err := Endpoint(v, own)
		if err != nil {
			continue
		}
		host, port, err := net.SplitHostPort(ep)
		if err != nil || port != "53" || seen[host] {
			continue
		}
		seen[host] = true
		fmt.Fprintf(&b, "nameserver %s\n", host)
	}
	return []byte(b.String())
}
