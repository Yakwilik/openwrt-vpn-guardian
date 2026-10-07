package dnsproxy

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// LocalNames discovers dnsmasq's actual generated configuration and hosts. It
// does not change dnsmasq upstreams, DHCP or the router's bootstrap resolver.
func LocalNames(root string) (*DomainMatcher, error) {
	m := newMatcher()
	m.internalForward = map[string]bool{}
	for _, s := range []string{"lan", "home.arpa", "localhost", "local", "invalid", "test", "onion"} {
		m.suffix[s] = struct{}{}
	}
	// Reverse addresses are classified against actual local/private prefixes.
	seen := map[string]bool{}
	var load func(string, int) error
	load = func(path string, depth int) error {
		if filepath.Base(path) == "vpn-guardian-local.conf" {
			return nil
		}
		if depth > 8 || seen[path] {
			return nil
		}
		seen[path] = true
		physical := filepath.Join(root, strings.TrimPrefix(path, "/"))
		st, err := os.Stat(physical)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if st.IsDir() {
			entries, err := os.ReadDir(physical)
			if err != nil {
				return err
			}
			for _, e := range entries {
				if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
					if err := load(filepath.Join(path, e.Name()), depth+1); err != nil {
						return err
					}
				}
			}
			return nil
		}
		if st.Size() > 4<<20 {
			return fmt.Errorf("local DNS file too large: %s", path)
		}
		f, err := os.Open(physical)
		if err != nil {
			return err
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value, setting := strings.Cut(line, "=")
			if setting {
				switch key {
				case "domain":
					zone := strings.Split(value, ",")[0]
					m.suffix[canonicalName(zone)] = struct{}{}
				case "local", "server", "address":
					if strings.HasPrefix(value, "/") {
						parts := strings.Split(value, "/")
						upstream := strings.Split(parts[len(parts)-1], "#")[0]
						remote := net.ParseIP(upstream)
						if key == "server" && upstream != "" {
							if remote == nil || !(remote.IsPrivate() || remote.IsLoopback() || remote.IsLinkLocalUnicast()) {
								continue
							}
							for _, zone := range parts[1 : len(parts)-1] {
								m.internalForward[canonicalName(zone)] = true
							}
						}

						// server=/<zone>/<upstream> is a split-horizon zone owned by dnsmasq.
						for _, zone := range parts[1 : len(parts)-1] {
							if zone != "" && zone != "#" {
								m.suffix[canonicalName(zone)] = struct{}{}
							}
						}
					}
				case "host-record", "cname":
					for _, name := range strings.Split(value, ",") {
						if net.ParseIP(name) == nil && strings.ContainsAny(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
							m.full[canonicalName(name)] = struct{}{}
						}
					}
				case "conf-file", "conf-dir", "addn-hosts", "hostsdir", "dhcp-leasefile":
					target := strings.Split(value, ",")[0]
					if filepath.IsAbs(target) {
						if err := load(target, depth+1); err != nil {
							return err
						}
					}
				}
			} else {
				fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
				if len(fields) > 1 && net.ParseIP(fields[0]) != nil {
					for _, name := range fields[1:] {
						m.full[canonicalName(name)] = struct{}{}
					}
				} else if len(fields) >= 4 && net.ParseIP(fields[2]) != nil && fields[3] != "*" {
					m.full[canonicalName(fields[3])] = struct{}{} // dnsmasq lease hostname
				}
			}
		}
		return scanner.Err()
	}
	for _, p := range []string{"/etc/dnsmasq.conf", "/etc/hosts", "/tmp/hosts", "/tmp/dhcp.leases"} {
		if err := load(p, 0); err != nil {
			return nil, err
		}
	}
	configs, err := filepath.Glob(filepath.Join(root, "var/etc/dnsmasq.conf.*"))
	if err != nil {
		return nil, err
	}
	for _, p := range configs {
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil, err
		}
		if err := load("/"+rel, 0); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func isLocalName(m *DomainMatcher, name string) bool {
	name = canonicalName(name)
	return name == "" || !strings.Contains(name, ".") || m.Match(name)
}

func localReverse(rt *Runtime, name string) bool {
	name = canonicalName(name)
	var ip net.IP
	if strings.HasSuffix(name, ".in-addr.arpa") {
		a := strings.Split(strings.TrimSuffix(name, ".in-addr.arpa"), ".")
		if len(a) == 4 {
			ip = net.ParseIP(a[3] + "." + a[2] + "." + a[1] + "." + a[0])
		}
	} else if strings.HasSuffix(name, ".ip6.arpa") {
		a := strings.Split(strings.TrimSuffix(name, ".ip6.arpa"), ".")
		if len(a) == 32 {
			var b strings.Builder
			for i := 31; i >= 0; i-- {
				if len(a[i]) != 1 {
					return false
				}
				b.WriteString(a[i])
				if i%4 == 0 && i != 0 {
					b.WriteByte(':')
				}
			}
			ip = net.ParseIP(b.String())
		}
	}
	if ip == nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	if rt.LAN != nil && rt.LAN.Contains(ip) {
		return true
	}
	for _, n := range rt.LANv6 {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
