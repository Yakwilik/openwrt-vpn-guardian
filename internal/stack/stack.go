package stack

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	stackDir    = "/etc/vpn-stack"
	stackPath   = stackDir + "/stack.json"
	routingPath = stackDir + "/routing.json"
	backupDir   = stackDir + "/backups"
)

type Stack struct {
	Version      int    `json:"version"`
	HomeIP       string `json:"homeIp"`
	LANInterface string `json:"lanInterface"`
	LANCIDR      string `json:"lanCidr"`
	WANInterface string `json:"wanInterface"`
	AssetsDir    string `json:"assetsDir"`
	Front        struct {
		SocksPort        int `json:"socksPort"`
		TProxyPort       int `json:"tproxyPort"`
		PolicyPort       int `json:"policyPort"`
		Mark             int `json:"mark"`
		RouteTable       int `json:"routeTable"`
		DirectSocketMark int `json:"directSocketMark"`
	} `json:"front"`
	Backend struct {
		SocksPort        int    `json:"socksPort"`
		WatchdogInterval string `json:"watchdogInterval"`
	} `json:"backend"`
	Dashboard struct {
		CollectorInterval string `json:"collectorInterval"`
	} `json:"dashboard"`
	Policy struct {
		Default       string `json:"default"`
		ProbeURL      string `json:"probeUrl"`
		ProbeInterval string `json:"probeInterval"`
	} `json:"policy"`
	Bypass4 []string `json:"bypass4"`
}

type Routing struct {
	Version      int      `json:"version"`
	ProxyDomains []string `json:"proxyDomains"`
	ProxyIPs     []string `json:"proxyIps"`
}

type Status struct {
	ManifestVersion                             int    `json:"manifestVersion"`
	Mode                                        string `json:"mode"`
	Runtime                                     string `json:"runtime"`
	Front, Policy, Backend, Watchdog, Collector bool
	NFT, PolicyRule, RouteTable, NoLANBlackhole bool
	Backups                                     int `json:"backups"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "status":
		err = statusCmd()
	case "validate":
		err = validateCmd()
	case "apply":
		err = applyCmd()
	case "backup":
		var out string
		out, err = backup("manual")
		if err == nil {
			fmt.Println(out)
		}
	case "restore":
		if len(os.Args) < 3 {
			err = errors.New("restore requires archive path")
		} else {
			err = restore(os.Args[2], true)
		}
	case "selftest":
		err = runSelftest()
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpn-stack:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: vpn-stack {status|validate|apply|backup|restore <archive>|selftest}")
	os.Exit(2)
}

func loadConfig() (Stack, Routing, error) {
	var s Stack
	var r Routing
	b, err := os.ReadFile(stackPath)
	if err != nil {
		return s, r, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, r, err
	}
	b, err = os.ReadFile(routingPath)
	if err != nil {
		return s, r, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return s, r, err
	}
	if s.Version != 1 || r.Version != 1 {
		return s, r, errors.New("unsupported manifest version")
	}
	if s.LANInterface == "" || s.LANCIDR == "" {
		return s, r, errors.New("LAN config missing")
	}
	if s.Front.SocksPort <= 0 || s.Front.TProxyPort <= 0 || s.Front.PolicyPort <= 0 {
		return s, r, errors.New("front ports invalid")
	}
	if s.Backend.SocksPort <= 0 || s.Front.RouteTable <= 0 {
		return s, r, errors.New("backend/table invalid")
	}
	if s.Policy.Default != "killswitch" && s.Policy.Default != "failopen" && s.Policy.Default != "direct" {
		return s, r, fmt.Errorf("invalid default policy %q", s.Policy.Default)
	}
	if _, err := time.ParseDuration(s.Backend.WatchdogInterval); err != nil {
		return s, r, fmt.Errorf("watchdogInterval: %w", err)
	}
	if _, err := time.ParseDuration(s.Dashboard.CollectorInterval); err != nil {
		return s, r, fmt.Errorf("collectorInterval: %w", err)
	}
	return s, r, nil
}
func jsonWrite(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0600)
}

func run(name string, args ...string) (string, error) {
	b, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(b)), err
}

func serviceRunning(name string) bool {
	out, err := run("/etc/init.d/"+name, "status")
	return err == nil && strings.Contains(out, "running")
}

func generate(dir string, s Stack, r Routing) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	front := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{
			map[string]any{"tag": "front-socks", "listen": "127.0.0.1", "port": s.Front.SocksPort, "protocol": "socks", "settings": map[string]any{"udp": true}},
			map[string]any{
				"tag": "front-tproxy", "listen": "0.0.0.0", "port": s.Front.TProxyPort, "protocol": "dokodemo-door",
				"settings":       map[string]any{"network": "tcp,udp", "followRedirect": true},
				"streamSettings": map[string]any{"sockopt": map[string]any{"tproxy": "tproxy"}},
				"sniffing":       map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": false},
			},
		},
		"outbounds": []any{
			map[string]any{"tag": "direct", "protocol": "freedom", "streamSettings": map[string]any{"sockopt": map[string]any{"mark": s.Front.DirectSocketMark}}},
			map[string]any{"tag": "policy-gateway", "protocol": "socks", "settings": map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": s.Front.PolicyPort}}}},
			map[string]any{"tag": "blocked", "protocol": "blackhole"},
		},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules": []any{
				map[string]any{"type": "field", "domain": r.ProxyDomains, "outboundTag": "policy-gateway"},
				map[string]any{"type": "field", "ip": r.ProxyIPs, "outboundTag": "policy-gateway"},
				map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
			},
		},
	}
	if err := jsonWrite(filepath.Join(dir, "vpn-front.json"), front); err != nil {
		return err
	}
	for _, mode := range []string{"failopen", "killswitch", "killswitch-blocked", "direct"} {
		if err := jsonWrite(filepath.Join(dir, "vpn-policy-"+mode+".json"), makePolicy(s, mode)); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "vpn-front.nft"), []byte(makeNFT(s)+"\n"), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "vpn-front-routing.init"), []byte(makeRoutingInit(s)), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "vpn-backend-watchdog.init"), []byte(makeWatchdogInit(s)), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "vpn-dashboard-collector.init"), []byte(makeCollectorInit(s)), 0755); err != nil {
		return err
	}
	return nil
}
func commonOutbounds(s Stack) []any {
	return []any{
		map[string]any{"tag": "direct", "protocol": "freedom", "streamSettings": map[string]any{"sockopt": map[string]any{"mark": s.Front.DirectSocketMark}}},
		map[string]any{"tag": "vpn-backend", "protocol": "socks", "settings": map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": s.Backend.SocksPort}}}},
		map[string]any{"tag": "blocked", "protocol": "blackhole", "settings": map[string]any{"response": map[string]any{"type": "http"}}},
	}
}

func makePolicy(s Stack, mode string) map[string]any {
	cfg := map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  []any{map[string]any{"tag": "policy-socks", "listen": "127.0.0.1", "port": s.Front.PolicyPort, "protocol": "socks", "settings": map[string]any{"udp": true}}},
		"outbounds": commonOutbounds(s),
	}
	switch mode {
	case "failopen":
		cfg["routing"] = map[string]any{
			"domainStrategy": "AsIs",
			"rules":          []any{map[string]any{"type": "field", "inboundTag": []string{"policy-socks"}, "balancerTag": "vpn-failopen"}},
			"balancers":      []any{map[string]any{"tag": "vpn-failopen", "selector": []string{"vpn-backend"}, "fallbackTag": "direct", "strategy": map[string]any{"type": "random"}}},
		}
		cfg["observatory"] = map[string]any{"subjectSelector": []string{"vpn-backend"}, "probeUrl": s.Policy.ProbeURL, "probeInterval": s.Policy.ProbeInterval, "enableConcurrency": true}
	case "killswitch":
		cfg["routing"] = policyRoute("vpn-backend")
	case "killswitch-blocked":
		cfg["routing"] = policyRoute("blocked")
	case "direct":
		cfg["routing"] = policyRoute("direct")
	}
	return cfg
}

func policyRoute(tag string) map[string]any {
	return map[string]any{"domainStrategy": "AsIs", "rules": []any{map[string]any{"type": "field", "inboundTag": []string{"policy-socks"}, "outboundTag": tag}}}
}

func makeNFT(s Stack) string {
	var b strings.Builder
	b.WriteString("table inet vpn_front {\n  set bypass4 {\n    type ipv4_addr\n    flags interval\n    elements = { ")
	for i, x := range s.Bypass4 {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(x)
	}
	b.WriteString(" }\n  }\n  chain prerouting {\n")
	b.WriteString("    type filter hook prerouting priority mangle - 10; policy accept;\n")
	fmt.Fprintf(&b, "    iifname %q ip saddr %s ip daddr @bypass4 return\n", s.LANInterface, s.LANCIDR)
	fmt.Fprintf(&b, "    iifname %q ip saddr %s meta nfproto ipv4 meta l4proto { tcp, udp } meta mark set 0x%x ct mark set meta mark tproxy ip to 127.0.0.1:%d accept\n", s.LANInterface, s.LANCIDR, s.Front.Mark, s.Front.TProxyPort)
	b.WriteString("  }\n}\n")
	return b.String()
}
func makeRoutingInit(s Stack) string {
	lines := []string{
		"#!/bin/sh /etc/rc.common",
		"START=99",
		"STOP=5",
		"",
		"apply_rules() {",
		"  [ -f /etc/vpn-front-enabled ] || return 0",
		"  uci -q set network.vpn_block_lan_leak.disabled='1' 2>/dev/null || true",
		"  uci -q set network.vpn_block_lan_leak_6.disabled='1' 2>/dev/null || true",
		"  uci -q commit network 2>/dev/null || true",
		fmt.Sprintf("  while ip -4 rule del priority 9920 iif %q 2>/dev/null; do :; done", s.LANInterface),
		fmt.Sprintf("  while ip -6 rule del priority 9920 iif %q 2>/dev/null; do :; done", s.LANInterface),
		"  nft delete table inet vpn_front 2>/dev/null || true",
		"  while ip rule del priority 5 2>/dev/null; do :; done",
		fmt.Sprintf("  ip route flush table %d 2>/dev/null || true", s.Front.RouteTable),
		fmt.Sprintf("  ip rule add priority 5 fwmark 0x%x/0x%x table %d", s.Front.Mark, s.Front.Mark, s.Front.RouteTable),
		fmt.Sprintf("  ip route add local 0.0.0.0/0 dev lo table %d", s.Front.RouteTable),
		"  nft -f /etc/vpn-front.nft",
		"}",
		"start() { apply_rules; }",
		"reload() { apply_rules; }",
		"restart() { apply_rules; }",
		"stop() {",
		"  nft delete table inet vpn_front 2>/dev/null || true",
		"  while ip rule del priority 5 2>/dev/null; do :; done",
		fmt.Sprintf("  ip route flush table %d 2>/dev/null || true", s.Front.RouteTable),
		"}",
		"",
	}
	return strings.Join(lines, "\n")
}

func makeWatchdogInit(s Stack) string {
	lines := []string{
		"#!/bin/sh /etc/rc.common",
		"USE_PROCD=1",
		"START=99",
		"STOP=6",
		"PROG=/usr/bin/vpn-backend-watchdog",
		"start_service() {",
		"  procd_open_instance vpn-backend-watchdog",
		fmt.Sprintf("  procd_set_param command \"$PROG\" -mode daemon -interval %s", s.Backend.WatchdogInterval),
		"  procd_set_param stdout 1",
		"  procd_set_param stderr 1",
		"  procd_set_param respawn 5 5 0",
		"  procd_set_param limits nofile=\"65535 65535\"",
		"  procd_close_instance",
		"}",
		"",
	}
	return strings.Join(lines, "\n")
}

func makeCollectorInit(s Stack) string {
	lines := []string{
		"#!/bin/sh /etc/rc.common",
		"USE_PROCD=1",
		"START=99",
		"STOP=7",
		"PROG=/usr/bin/vpn-status-collector",
		"start_service() {",
		"  procd_open_instance vpn-dashboard-collector",
		fmt.Sprintf("  procd_set_param command \"$PROG\" -mode collect -interval %s", s.Dashboard.CollectorInterval),
		"  procd_set_param stdout 1",
		"  procd_set_param stderr 1",
		"  procd_set_param respawn 5 5 0",
		"  procd_close_instance",
		"}",
		"",
	}
	return strings.Join(lines, "\n")
}
func validateGenerated(dir string) error {
	for _, f := range []string{
		"vpn-front.json",
		"vpn-policy-failopen.json",
		"vpn-policy-killswitch.json",
		"vpn-policy-killswitch-blocked.json",
		"vpn-policy-direct.json",
	} {
		if out, err := run("/usr/bin/xray", "run", "-test", "-config", filepath.Join(dir, f)); err != nil {
			return fmt.Errorf("%s invalid: %v: %s", f, err, out)
		}
	}
	if out, err := run("nft", "-c", "-f", filepath.Join(dir, "vpn-front.nft")); err != nil {
		return fmt.Errorf("vpn-front.nft invalid: %v: %s", err, out)
	}
	return nil
}

func validateCmd() error {
	s, r, err := loadConfig()
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("/tmp", "vpn-stack-validate-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := generate(dir, s, r); err != nil {
		return err
	}
	if err := validateGenerated(dir); err != nil {
		return err
	}
	fmt.Printf("OK manifest=v%d domains=%d ips=%d\n", s.Version, len(r.ProxyDomains), len(r.ProxyIPs))
	return nil
}

func applyCmd() error {
	s, r, err := loadConfig()
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("/tmp", "vpn-stack-apply-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	if err := generate(dir, s, r); err != nil {
		return err
	}
	if err := validateGenerated(dir); err != nil {
		return err
	}

	snapshot, err := backup("pre-apply")
	if err != nil {
		return fmt.Errorf("backup before apply: %w", err)
	}
	fmt.Println("snapshot:", snapshot)

	files := map[string]string{
		"vpn-front.json":                     "/etc/xray/vpn-front.json",
		"vpn-policy-failopen.json":           "/etc/xray/vpn-policy-failopen.json",
		"vpn-policy-killswitch.json":         "/etc/xray/vpn-policy-killswitch.json",
		"vpn-policy-killswitch-blocked.json": "/etc/xray/vpn-policy-killswitch-blocked.json",
		"vpn-policy-direct.json":             "/etc/xray/vpn-policy-direct.json",
		"vpn-front.nft":                      "/etc/vpn-front.nft",
		"vpn-front-routing.init":             "/etc/init.d/vpn-front-routing",
		"vpn-backend-watchdog.init":          "/etc/init.d/vpn-backend-watchdog",
		"vpn-dashboard-collector.init":       "/etc/init.d/vpn-dashboard-collector",
	}
	for src, dst := range files {
		mode := fs.FileMode(0644)
		if strings.HasSuffix(src, ".init") {
			mode = 0755
		}
		if err := copyAtomic(filepath.Join(dir, src), dst, mode); err != nil {
			_ = restore(snapshot, false)
			return err
		}
	}
	if err := restartStack(); err != nil {
		_ = restore(snapshot, false)
		return fmt.Errorf("restart after apply: %w", err)
	}
	if err := runSelftest(); err != nil {
		_ = restore(snapshot, false)
		return fmt.Errorf("selftest failed; rolled back: %w", err)
	}
	fmt.Println("apply OK")
	return nil
}
func restartStack() error {
	for _, svc := range []string{"vpn-front", "vpn-front-routing", "vpn-backend-watchdog", "vpn-dashboard-collector"} {
		if out, err := run("/etc/init.d/"+svc, "restart"); err != nil {
			return fmt.Errorf("restart %s: %v: %s", svc, err, out)
		}
	}
	mode := strings.TrimSpace(readFile("/etc/vpn-policy-mode"))
	if mode != "killswitch" && mode != "failopen" && mode != "direct" {
		s, _, err := loadConfig()
		if err != nil {
			return err
		}
		mode = s.Policy.Default
	}
	if out, err := run("/usr/bin/vpn-policy-mode", mode); err != nil {
		return fmt.Errorf("vpn-policy-mode %s: %v: %s", mode, err, out)
	}
	return nil
}

func copyAtomic(src, dst string, mode fs.FileMode) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	tmp := dst + ".vpn-stack-new"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func readFile(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

var backupFiles = []string{
	"/etc/vpn-stack/stack.json",
	"/etc/vpn-stack/routing.json",
	"/etc/xray/vpn-front.json",
	"/etc/xray/vpn-policy-failopen.json",
	"/etc/xray/vpn-policy-killswitch.json",
	"/etc/xray/vpn-policy-killswitch-blocked.json",
	"/etc/xray/vpn-policy-direct.json",
	"/etc/vpn-front.nft",
	"/etc/vpn-front-enabled",
	"/etc/vpn-policy-mode",
	"/etc/vpn-policy-runtime",
	"/etc/v2raya-failover-control.json",
	"/etc/v2raya/v2raya.db",
	"/etc/init.d/vpn-front",
	"/etc/init.d/vpn-policy",
	"/etc/init.d/vpn-front-routing",
	"/etc/init.d/vpn-backend-watchdog",
	"/etc/init.d/vpn-dashboard-collector",
	"/etc/hotplug.d/iface/99-vpn-front-routing",
	"/usr/bin/vpn-policy-mode",
	"/usr/bin/vpn-backend-watchdog",
	"/usr/bin/vpn-selftest",
	"/usr/bin/vpn-status-collector",
	"/usr/bin/vpn-stack",
	"/www/cgi-bin/vpn-status",
	"/www/cgi-bin/vpn-control",
	"/www/cgi-bin/vpn-history",
	"/www/vpn-dashboard/index.html",
}

func backup(reason string) (string, error) {
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return "", err
	}
	name := fmt.Sprintf("vpn-stack-%s-%s.tar.gz", time.Now().Format("20060102-150405"), reason)
	path := filepath.Join(backupDir, name)
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	for _, p := range backupFiles {
		info, err := os.Stat(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			tw.Close()
			gz.Close()
			f.Close()
			return "", err
		}
		h, err := tar.FileInfoHeader(info, "")
		if err != nil {
			tw.Close()
			gz.Close()
			f.Close()
			return "", err
		}
		h.Name = strings.TrimPrefix(p, "/")
		if err := tw.WriteHeader(h); err != nil {
			tw.Close()
			gz.Close()
			f.Close()
			return "", err
		}
		if info.Mode().IsRegular() {
			in, err := os.Open(p)
			if err != nil {
				tw.Close()
				gz.Close()
				f.Close()
				return "", err
			}
			_, err = io.Copy(tw, in)
			in.Close()
			if err != nil {
				tw.Close()
				gz.Close()
				f.Close()
				return "", err
			}
		}
	}
	if err := tw.Close(); err != nil {
		gz.Close()
		f.Close()
		return "", err
	}
	if err := gz.Close(); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return path, nil
}

func restore(archive string, preBackup bool) error {
	if _, err := os.Stat(archive); err != nil {
		return err
	}
	var rollback string
	var err error
	if preBackup {
		rollback, err = backup("pre-restore")
		if err != nil {
			return err
		}
		fmt.Println("snapshot:", rollback)
	}

	dir, err := os.MkdirTemp("/tmp", "vpn-stack-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := extractArchive(archive, dir); err != nil {
		return err
	}

	for _, f := range []string{
		"etc/xray/vpn-front.json",
		"etc/xray/vpn-policy-failopen.json",
		"etc/xray/vpn-policy-killswitch.json",
		"etc/xray/vpn-policy-killswitch-blocked.json",
		"etc/xray/vpn-policy-direct.json",
	} {
		p := filepath.Join(dir, f)
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("archive missing %s", f)
		}
		if out, err := run("/usr/bin/xray", "run", "-test", "-config", p); err != nil {
			return fmt.Errorf("staged %s invalid: %v: %s", f, err, out)
		}
	}
	nftPath := filepath.Join(dir, "etc/vpn-front.nft")
	if out, err := run("nft", "-c", "-f", nftPath); err != nil {
		return fmt.Errorf("staged nft invalid: %v: %s", err, out)
	}

	if err := installExtracted(dir); err != nil {
		if rollback != "" {
			_ = restore(rollback, false)
		}
		return err
	}
	if err := restartStack(); err != nil {
		if rollback != "" {
			_ = restore(rollback, false)
		}
		return err
	}
	if preBackup {
		if err := runSelftest(); err != nil {
			_ = restore(rollback, false)
			return fmt.Errorf("restore selftest failed; rollback applied: %w", err)
		}
	}
	fmt.Println("restore OK")
	return nil
}
func extractArchive(path, dir string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		clean := filepath.Clean(h.Name)
		if clean == "." || strings.HasPrefix(clean, "../") || filepath.IsAbs(clean) {
			return fmt.Errorf("unsafe archive path %q", h.Name)
		}
		dst := filepath.Join(dir, clean)
		if !strings.HasPrefix(dst, dir+string(os.PathSeparator)) {
			return errors.New("archive traversal")
		}
		if h.FileInfo().IsDir() {
			if err := os.MkdirAll(dst, h.FileInfo().Mode()); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return err
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, h.FileInfo().Mode())
		if err != nil {
			return err
		}
		_, cpErr := io.Copy(out, tr)
		out.Close()
		if cpErr != nil {
			return cpErr
		}
	}
	return nil
}

func installExtracted(dir string) error {
	return filepath.WalkDir(dir, func(path string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if de.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		dst := "/" + rel
		info, err := de.Info()
		if err != nil {
			return err
		}
		return copyAtomic(path, dst, info.Mode())
	})
}

func runSelftest() error {
	out, err := run("/usr/bin/vpn-selftest")
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	fmt.Println(out)
	return nil
}

func statusCmd() error {
	s, _, err := loadConfig()
	if err != nil {
		return err
	}
	rules := readCmd("ip", "rule", "show")
	rules6 := readCmd("ip", "-6", "rule", "show")
	route := readCmd("ip", "route", "show", "table", strconv.Itoa(s.Front.RouteTable))
	entries, _ := os.ReadDir(backupDir)
	st := Status{
		ManifestVersion: s.Version,
		Mode:            strings.TrimSpace(readFile("/etc/vpn-policy-mode")),
		Runtime:         strings.TrimSpace(readFile("/etc/vpn-policy-runtime")),
		Front:           serviceRunning("vpn-front"),
		Policy:          serviceRunning("vpn-policy"),
		Backend:         serviceRunning("v2raya"),
		Watchdog:        serviceRunning("vpn-backend-watchdog"),
		Collector:       serviceRunning("vpn-dashboard-collector"),
		NFT:             exec.Command("nft", "list", "table", "inet", "vpn_front").Run() == nil,
		PolicyRule:      strings.Contains(rules, fmt.Sprintf("fwmark 0x%x/0x%x", s.Front.Mark, s.Front.Mark)) && strings.Contains(rules, fmt.Sprintf("lookup %d", s.Front.RouteTable)),
		RouteTable:      strings.Contains(route, "local default dev lo"),
		NoLANBlackhole:  !strings.Contains(rules, "iif "+s.LANInterface+" blackhole") && !strings.Contains(rules6, "iif "+s.LANInterface+" blackhole"),
		Backups:         len(entries),
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	fmt.Println(string(b))
	return nil
}

func readCmd(name string, args ...string) string {
	b, _ := exec.Command(name, args...).CombinedOutput()
	return string(b)
}

// Run executes the stack manager with legacy-compatible arguments.
func Run(args []string) {
	oldArgs := os.Args
	os.Args = append([]string{"vpn-stack"}, args...)
	defer func() { os.Args = oldArgs }()
	main()
}
