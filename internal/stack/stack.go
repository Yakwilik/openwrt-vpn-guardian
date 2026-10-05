package stack

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/policy"
	v2rayautil "github.com/Yakwilik/openwrt-vpn-guardian/internal/v2raya"
)

const (
	stackDir                = paths.ConfigDir
	stackPath               = paths.StackConfig
	routingPath             = paths.RoutingConfig
	backupDir               = paths.BackupDir
	bootstrapMarker         = paths.BootstrapMarker
	defaultDashboardAPIAddr = "127.0.0.1:20175"
)

type Stack = config.Stack

type Routing = config.Routing

type Status struct {
	ManifestVersion                             int    `json:"manifestVersion"`
	Mode                                        string `json:"mode"`
	Runtime                                     string `json:"runtime"`
	Front, Policy, Backend, Watchdog, Collector bool
	NFT, PolicyRule, RouteTable, NoLANBlackhole bool
	Backups                                     int `json:"backups"`
}

const usageText = "vpn-guardian stack {bootstrap [--dry-run]|init [--dry-run] [--force]|status|validate|apply|backup|restore <archive>|selftest|cleanup}"

func Run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("stack command required; usage: %s", usageText)
	}

	command := args[0]
	commandArgs := args[1:]

	switch command {
	case "bootstrap":
		dryRun, err := parseBootstrapArgs(commandArgs)
		if err != nil {
			return err
		}
		return bootstrapCmd(dryRun)

	case "init":
		force, dryRun, err := parseInitArgs(commandArgs)
		if err != nil {
			return err
		}
		return initCmd(force, dryRun)

	case "status":
		if err := requireNoArgs(command, commandArgs); err != nil {
			return err
		}
		return statusCmd()

	case "cleanup":
		if err := requireNoArgs(command, commandArgs); err != nil {
			return err
		}
		return cleanupCmd()

	case "validate":
		if err := requireNoArgs(command, commandArgs); err != nil {
			return err
		}
		return validateCmd()

	case "apply":
		if err := requireNoArgs(command, commandArgs); err != nil {
			return err
		}
		return applyCmd()

	case "backup":
		if err := requireNoArgs(command, commandArgs); err != nil {
			return err
		}
		path, err := backup("manual")
		if err != nil {
			return err
		}
		fmt.Println(path)
		return nil

	case "restore":
		if len(commandArgs) != 1 {
			return errors.New("restore requires exactly one archive path")
		}
		return restore(commandArgs[0], true)

	case "selftest":
		if err := requireNoArgs(command, commandArgs); err != nil {
			return err
		}
		return runSelftest()

	default:
		return fmt.Errorf("unknown stack command %q; usage: %s", command, usageText)
	}
}

func parseBootstrapArgs(args []string) (bool, error) {
	switch len(args) {
	case 0:
		return false, nil
	case 1:
		if args[0] == "--dry-run" {
			return true, nil
		}
	}
	return false, fmt.Errorf("invalid bootstrap arguments %q; usage: vpn-guardian stack bootstrap [--dry-run]", args)
}

func parseInitArgs(args []string) (force, dryRun bool, err error) {
	for _, arg := range args {
		switch arg {
		case "--force":
			if force {
				return false, false, errors.New("init option --force specified more than once")
			}
			force = true
		case "--dry-run":
			if dryRun {
				return false, false, errors.New("init option --dry-run specified more than once")
			}
			dryRun = true
		default:
			return false, false, fmt.Errorf("unknown init option %q", arg)
		}
	}
	return force, dryRun, nil
}

func requireNoArgs(command string, args []string) error {
	if len(args) == 0 {
		return nil
	}
	return fmt.Errorf("%s does not accept arguments: %q", command, args)
}

func bootstrapCmd(dryRun bool) error {
	if os.Geteuid() != 0 {
		return errors.New("bootstrap must run as root")
	}
	if err := checkBootstrapDependencies(); err != nil {
		return err
	}
	_, stackErr := os.Stat(stackPath)
	_, routingErr := os.Stat(routingPath)
	stackExists := stackErr == nil
	routingExists := routingErr == nil

	if dryRun {
		lan := detectLANInterface()
		wan := detectWANInterface()
		lanCIDR := ""
		lanIP := ""
		if lan != "" {
			lanCIDR = detectLANCIDR(lan)
			lanIP = detectLANAddress(lan)
		}
		if stackExists && routingExists {
			if err := validateCmd(); err != nil {
				return fmt.Errorf("validate manifests: %w", err)
			}
		}
		socksReady := v2rayautil.BackendSOCKSReady()
		backendUsable := v2rayautil.BackendUsable()
		plan := map[string]any{
			"dryRun":             true,
			"stackManifest":      stackExists,
			"routingManifest":    routingExists,
			"lanInterface":       lan,
			"lanCIDR":            lanCIDR,
			"lanAddress":         lanIP,
			"wanInterface":       wan,
			"dashboardDNS":       "vpn.home.arpa",
			"backendSOCKSReady":  socksReady,
			"backendUsable":      backendUsable,
			"wouldActivateFront": backendUsable && stackExists && routingExists,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(plan)
	}

	if err := os.MkdirAll(stackDir, 0700); err != nil {
		return err
	}

	switch {
	case !stackExists && !routingExists:
		if err := initCmd(false, false); err != nil {
			return fmt.Errorf("initialize manifests: %w", err)
		}
	case stackExists != routingExists:
		return errors.New("only one manifest exists; restore the missing manifest or run init --force explicitly")
	}

	if err := validateCmd(); err != nil {
		return fmt.Errorf("validate manifests: %w", err)
	}
	if err := ensureV2rayAService(); err != nil {
		return err
	}
	if err := v2rayautil.EnsureBackendOnly(); err != nil {
		return fmt.Errorf("configure v2rayA backend-only mode: %w", err)
	}
	if _, err := v2rayautil.RepairBackendListener(false); err != nil {
		return fmt.Errorf("repair v2rayA backend listener: %w", err)
	}
	if err := setupDashboardDNS(); err != nil {
		return fmt.Errorf("configure dashboard DNS: %w", err)
	}
	if err := setupDashboardRuntime(); err != nil {
		return fmt.Errorf("configure dashboard runtime: %w", err)
	}

	if !v2rayautil.BackendUsable() {
		_ = os.Remove(bootstrapMarker)
		fmt.Println("bootstrap pending: v2rayA backend is not usable through SOCKS 127.0.0.1:20173")
		fmt.Println("front remains inactive; the bootstrap service will retry automatically")
		return nil
	}

	if err := applyCmd(); err != nil {
		return fmt.Errorf("activate generated stack: %w", err)
	}
	if err := setupDashboardRuntime(); err != nil {
		return fmt.Errorf("reload dashboard after activation: %w", err)
	}
	if err := os.WriteFile(bootstrapMarker, []byte(time.Now().Format(time.RFC3339)+"\n"), 0600); err != nil {
		return fmt.Errorf("write bootstrap marker: %w", err)
	}
	fmt.Println("bootstrap OK")
	return nil
}

func checkBootstrapDependencies() error {
	required := []string{"xray", "v2raya", "nft", "ip", "uci", "ubus"}
	var missing []string
	for _, name := range required {
		if _, err := exec.LookPath(name); err != nil {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing runtime dependencies: %s", strings.Join(missing, ", "))
	}
	return nil
}

func ensureV2rayAService() error {
	if out, err := run("uci", "-q", "set", "v2raya.config.enabled=1"); err != nil {
		return fmt.Errorf("enable v2rayA in UCI: %v: %s", err, out)
	}
	if out, err := run("uci", "-q", "commit", "v2raya"); err != nil {
		return fmt.Errorf("commit v2rayA UCI: %v: %s", err, out)
	}
	if out, err := run("/etc/init.d/v2raya", "enable"); err != nil {
		return fmt.Errorf("enable v2rayA service: %v: %s", err, out)
	}
	if !serviceRunning("v2raya") {
		if out, err := run("/etc/init.d/v2raya", "start"); err != nil {
			return fmt.Errorf("start v2rayA service: %v: %s", err, out)
		}
	}

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat("/etc/v2raya/v2raya.db"); err == nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("v2rayA database did not become ready")
}

func detectLANAddress(iface string) string {
	out, err := run("ip", "-4", "-o", "addr", "show", "dev", iface)
	if err != nil {
		return ""
	}
	fields := strings.Fields(out)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "inet" {
			if ip, _, err := net.ParseCIDR(fields[i+1]); err == nil {
				return ip.String()
			}
		}
	}
	return ""
}

func setupDashboardDNS() error {
	if _, err := os.Stat("/etc/init.d/dnsmasq"); err != nil {
		return nil
	}

	s, _, err := loadConfig()
	if err != nil {
		return err
	}
	lanIP := detectLANAddress(s.LANInterface)
	if lanIP == "" {
		return fmt.Errorf("cannot determine LAN address for %s", s.LANInterface)
	}

	commands := [][]string{
		{"-q", "delete", "dhcp.vpn_guardian"},
		{"set", "dhcp.vpn_guardian=domain"},
		{"set", "dhcp.vpn_guardian.name=vpn.home.arpa"},
		{"set", "dhcp.vpn_guardian.ip=" + lanIP},
	}
	for i, args := range commands {
		out, cmdErr := run("uci", args...)
		if i == 0 && cmdErr != nil {
			continue
		}
		if cmdErr != nil {
			return fmt.Errorf("uci %s: %v: %s", strings.Join(args, " "), cmdErr, out)
		}
	}
	if out, err := run("uci", "commit", "dhcp"); err != nil {
		return fmt.Errorf("commit dashboard DNS: %v: %s", err, out)
	}
	if out, err := run("/etc/init.d/dnsmasq", "reload"); err != nil {
		return fmt.Errorf("reload dnsmasq: %v: %s", err, out)
	}
	return nil
}

func setupDashboardRuntime() error {
	if out, err := run("/etc/init.d/vpn-guardian-api", "enable"); err != nil {
		return fmt.Errorf("enable vpn-guardian-api: %v: %s", err, out)
	}
	if out, err := run("/etc/init.d/vpn-guardian-api", "restart"); err != nil {
		return fmt.Errorf("start vpn-guardian-api: %v: %s", err, out)
	}

	deadline := time.Now().Add(5 * time.Second)
	apiReady := false
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", defaultDashboardAPIAddr, 300*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			apiReady = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !apiReady {
		return fmt.Errorf("vpn-guardian-api did not listen on %s", defaultDashboardAPIAddr)
	}

	if _, err := exec.LookPath("nginx"); err != nil {
		return nil
	}
	if _, err := os.Stat("/etc/init.d/nginx"); err != nil {
		return nil
	}
	if out, err := run("nginx", "-t", "-c", "/etc/nginx/nginx.conf"); err != nil {
		return fmt.Errorf("nginx config invalid: %v: %s", err, out)
	}
	if err := reloadNginx(); err != nil {
		return err
	}
	return nil
}

func reloadNginx() error {
	for _, pidPath := range []string{"/var/run/nginx.pid", "/run/nginx.pid"} {
		data, err := os.ReadFile(pidPath)
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || pid <= 1 {
			continue
		}
		if err := syscall.Kill(pid, syscall.SIGHUP); err == nil {
			return nil
		}
	}

	out, err := run("/etc/init.d/nginx", "restart")
	if err != nil {
		return fmt.Errorf("reload nginx: HUP unavailable and restart failed: %v: %s", err, out)
	}
	return nil
}

func initCmd(force, dryRun bool) error {
	if !force && !dryRun {
		if _, err := os.Stat(stackPath); err == nil {
			return fmt.Errorf("%s already exists; use init --force to replace manifests", stackPath)
		}
		if _, err := os.Stat(routingPath); err == nil {
			return fmt.Errorf("%s already exists; use init --force to replace manifests", routingPath)
		}
	}

	lan := detectLANInterface()
	if lan == "" {
		return errors.New("unable to detect LAN interface")
	}
	lanCIDR := detectLANCIDR(lan)
	if lanCIDR == "" {
		return fmt.Errorf("unable to detect IPv4 CIDR for LAN interface %s", lan)
	}
	wan := detectWANInterface()
	if wan == "" {
		return errors.New("unable to detect WAN interface")
	}

	assetsDir := detectAssetsDir()
	s := defaultStack(lan, lanCIDR, wan, assetsDir)
	r := defaultRouting()

	if dryRun {
		out := struct {
			Stack   Stack   `json:"stack"`
			Routing Routing `json:"routing"`
		}{Stack: s, Routing: r}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	if err := os.MkdirAll(stackDir, 0700); err != nil {
		return err
	}
	if err := jsonWrite(stackPath, s); err != nil {
		return err
	}
	if err := jsonWrite(routingPath, r); err != nil {
		return err
	}

	fmt.Printf("initialized %s and %s\n", stackPath, routingPath)
	fmt.Printf("detected lan=%s cidr=%s wan=%s assets=%s\n", lan, lanCIDR, wan, assetsDir)
	fmt.Println("next: vpn-guardian validate && vpn-guardian apply")
	return nil
}

func detectAssetsDir() string {
	for _, dir := range []string{"/usr/share/xray", "/usr/share/v2ray"} {
		if _, err := os.Stat(filepath.Join(dir, "geosite.dat")); err == nil {
			return dir
		}
	}
	return "/usr/share/xray"
}

func defaultStack(lanInterface, lanCIDR, wanInterface, assetsDir string) Stack {
	return config.DefaultStack(lanInterface, lanCIDR, wanInterface, assetsDir)
}

func defaultRouting() Routing {
	return config.DefaultRouting()
}

func detectLANInterface() string {
	for _, key := range []string{"network.lan.device", "network.lan.ifname"} {
		if out, err := run("uci", "-q", "get", key); err == nil && strings.TrimSpace(out) != "" {
			return strings.Fields(out)[0]
		}
	}
	if _, err := os.Stat("/sys/class/net/br-lan"); err == nil {
		return "br-lan"
	}
	return ""
}

func detectLANCIDR(iface string) string {
	out, err := run("ip", "-4", "-o", "addr", "show", "dev", iface)
	if err != nil {
		return ""
	}
	fields := strings.Fields(out)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "inet" {
			_, network, err := net.ParseCIDR(fields[i+1])
			if err == nil {
				return network.String()
			}
			return fields[i+1]
		}
	}
	return ""
}

func detectWANInterface() string {
	if out, err := run("ubus", "call", "network.interface.wan", "status"); err == nil {
		var st struct {
			L3Device string `json:"l3_device"`
			Device   string `json:"device"`
		}
		if json.Unmarshal([]byte(out), &st) == nil {
			if st.L3Device != "" {
				return st.L3Device
			}
			if st.Device != "" {
				return st.Device
			}
		}
	}
	if out, err := run("ip", "-4", "route", "show", "default"); err == nil {
		fields := strings.Fields(out)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "dev" {
				return fields[i+1]
			}
		}
	}
	return ""
}

func loadConfig() (Stack, Routing, error) {
	return config.Load()
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

	files := []struct {
		name string
		data any
	}{
		{filepath.Base(paths.FrontConfig), front},
		{filepath.Base(paths.PolicyFailOpen), makePolicy(s, "failopen")},
		{filepath.Base(paths.PolicyVPNOnly), makePolicy(s, "killswitch")},
		{filepath.Base(paths.PolicyBlocked), makePolicy(s, "killswitch-blocked")},
		{filepath.Base(paths.PolicyDirect), makePolicy(s, "direct")},
	}
	for _, file := range files {
		if err := jsonWrite(filepath.Join(dir, file.name), file.data); err != nil {
			return err
		}
	}

	if err := os.WriteFile(filepath.Join(dir, filepath.Base(paths.FrontNFT)), []byte(makeNFT(s)+"\n"), 0644); err != nil {
		return err
	}

	scripts := []struct {
		name string
		body string
	}{
		{"vpn-front.init", makeXrayInit("vpn-front", paths.FrontConfig, s.AssetsDir, 98, 10)},
		{"vpn-policy.init", makeXrayInit("vpn-policy", paths.PolicyConfig, s.AssetsDir, 97, 11)},
		{"vpn-front-routing.init", makeRoutingInit(s)},
		{"vpn-backend-watchdog.init", makeWatchdogInit(s)},
		{"vpn-dashboard-collector.init", makeCollectorInit(s)},
	}
	for _, script := range scripts {
		if err := os.WriteFile(filepath.Join(dir, script.name), []byte(script.body), 0755); err != nil {
			return err
		}
	}

	return nil
}

func makeXrayInit(instance, config, assets string, start, stop int) string {
	lines := []string{
		"#!/bin/sh /etc/rc.common",
		"USE_PROCD=1",
		fmt.Sprintf("START=%d", start),
		fmt.Sprintf("STOP=%d", stop),
		"",
		"PROG=/usr/bin/xray",
		fmt.Sprintf("CONF=%q", config),
		fmt.Sprintf("ASSETS=%q", assets),
		"",
		"start_service() {",
		"  [ -f \"$CONF\" ] || return 1",
		fmt.Sprintf("  procd_open_instance %s", instance),
		"  procd_set_param command \"$PROG\" run -config \"$CONF\"",
		"  procd_set_param env XRAY_LOCATION_ASSET=\"$ASSETS\"",
		"  procd_set_param file \"$CONF\"",
		"  procd_set_param limits nofile=\"1000000 1000000\"",
		"  procd_set_param stdout 1",
		"  procd_set_param stderr 1",
		"  procd_set_param respawn",
		"  procd_close_instance",
		"}",
		"",
		"reload_service() { stop; start; }",
		"",
	}
	return strings.Join(lines, "\n")
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
		fmt.Sprintf("  [ -f %q ] || return 0", paths.FrontEnabled),
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
		fmt.Sprintf("  nft -f %q", paths.FrontNFT),
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
		"PROG=/usr/bin/vpn-guardian",
		"start_service() {",
		"  procd_open_instance vpn-backend-watchdog",
		fmt.Sprintf("  procd_set_param command \"$PROG\" watchdog -mode daemon -interval %s", s.Backend.WatchdogInterval),
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
		"PROG=/usr/bin/vpn-guardian",
		"start_service() {",
		"  procd_open_instance vpn-dashboard-collector",
		fmt.Sprintf("  procd_set_param command \"$PROG\" collector -mode collect -interval %s", s.Dashboard.CollectorInterval),
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
	xrayConfigs := []string{
		filepath.Base(paths.FrontConfig),
		filepath.Base(paths.PolicyFailOpen),
		filepath.Base(paths.PolicyVPNOnly),
		filepath.Base(paths.PolicyBlocked),
		filepath.Base(paths.PolicyDirect),
	}
	for _, name := range xrayConfigs {
		config := filepath.Join(dir, name)
		if out, err := run("/usr/bin/xray", "run", "-test", "-config", config); err != nil {
			return fmt.Errorf("%s invalid: %v: %s", name, err, out)
		}
	}

	nftConfig := filepath.Join(dir, filepath.Base(paths.FrontNFT))
	if out, err := run("nft", "-c", "-f", nftConfig); err != nil {
		return fmt.Errorf("%s invalid: %v: %s", filepath.Base(paths.FrontNFT), err, out)
	}
	return nil
}

func validateCmd() error {
	s, r, err := loadConfig()
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("/tmp", "vpn-guardian-validate-")
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
	dir, err := os.MkdirTemp("/tmp", "vpn-guardian-apply-")
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

	_, markerErr := os.Stat(paths.FrontEnabled)
	frontWasEnabled := markerErr == nil

	files := map[string]string{
		filepath.Base(paths.FrontConfig):    paths.FrontConfig,
		filepath.Base(paths.PolicyFailOpen): paths.PolicyFailOpen,
		filepath.Base(paths.PolicyVPNOnly):  paths.PolicyVPNOnly,
		filepath.Base(paths.PolicyBlocked):  paths.PolicyBlocked,
		filepath.Base(paths.PolicyDirect):   paths.PolicyDirect,
		filepath.Base(paths.FrontNFT):       paths.FrontNFT,
		"vpn-front.init":                    paths.FrontServiceInit,
		"vpn-policy.init":                   paths.PolicyServiceInit,
		"vpn-front-routing.init":            paths.FrontRoutingInit,
		"vpn-backend-watchdog.init":         paths.WatchdogServiceInit,
		"vpn-dashboard-collector.init":      paths.CollectorServiceInit,
	}
	for src, dst := range files {
		mode := fs.FileMode(0644)
		if strings.HasSuffix(src, ".init") {
			mode = 0755
		}
		if err := copyAtomic(filepath.Join(dir, src), dst, mode); err != nil {
			rollbackApply(snapshot, frontWasEnabled)
			return err
		}
	}
	if err := os.WriteFile(paths.FrontEnabled, nil, 0644); err != nil {
		rollbackApply(snapshot, frontWasEnabled)
		return fmt.Errorf("enable front marker: %w", err)
	}
	if err := restartStack(); err != nil {
		rollbackApply(snapshot, frontWasEnabled)
		return fmt.Errorf("restart after apply: %w", err)
	}
	if err := runSelftest(); err != nil {
		rollbackApply(snapshot, frontWasEnabled)
		return fmt.Errorf("selftest failed; rolled back: %w", err)
	}
	if err := enableStackServices(); err != nil {
		rollbackApply(snapshot, frontWasEnabled)
		return fmt.Errorf("enabling boot services failed; rolled back: %w", err)
	}
	fmt.Println("apply OK")
	return nil
}
func rollbackApply(snapshot string, frontWasEnabled bool) {
	if !frontWasEnabled {
		cleanupGeneratedRuntime()
	}

	_ = restoreSnapshotSparse(snapshot)

	if frontWasEnabled {
		_ = restartStack()
	}
}

func cleanupCmd() error {
	if os.Geteuid() != 0 {
		return errors.New("cleanup must run as root")
	}
	cleanupGeneratedRuntime()
	_ = os.Remove(bootstrapMarker)
	fmt.Println("cleanup OK")
	return nil
}

func cleanupGeneratedRuntime() {
	for _, svc := range []string{"vpn-dashboard-collector", "vpn-backend-watchdog", "vpn-front-routing", "vpn-front", "vpn-policy"} {
		initPath := "/etc/init.d/" + svc
		if _, err := os.Stat(initPath); err == nil {
			_, _ = run(initPath, "stop")
		}
	}

	_ = exec.Command("nft", "delete", "table", "inet", "vpn_front").Run()
	for i := 0; i < 4; i++ {
		_ = exec.Command("ip", "rule", "del", "priority", "5").Run()
	}
	if s, _, err := loadConfig(); err == nil && s.Front.RouteTable > 0 {
		_ = exec.Command("ip", "route", "flush", "table", strconv.Itoa(s.Front.RouteTable)).Run()
	}

	_ = os.RemoveAll(paths.GeneratedDir)
	for _, path := range []string{
		paths.FrontEnabled,
		paths.PolicyMode,
		paths.PolicyRuntime,
		paths.FrontServiceInit,
		paths.PolicyServiceInit,
		paths.FrontRoutingInit,
		paths.WatchdogServiceInit,
		paths.CollectorServiceInit,
	} {
		_ = os.Remove(path)
	}
}

func restoreSnapshotSparse(archive string) error {
	dir, err := os.MkdirTemp("/tmp", "vpn-guardian-rollback-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	if err := extractArchive(archive, dir); err != nil {
		return err
	}
	return installExtracted(dir)
}

func enableStackServices() error {
	for _, svc := range []string{
		"vpn-policy",
		"vpn-front",
		"vpn-front-routing",
		"vpn-backend-watchdog",
		"vpn-dashboard-collector",
	} {
		if out, err := run("/etc/init.d/"+svc, "enable"); err != nil {
			return fmt.Errorf("enable %s: %v: %s", svc, err, out)
		}
	}
	return nil
}

func restartStack() error {
	mode := strings.TrimSpace(readFile(paths.PolicyMode))
	if mode != "killswitch" && mode != "failopen" && mode != "direct" {
		s, _, err := loadConfig()
		if err != nil {
			return err
		}
		mode = s.Policy.Default
	}
	if err := policy.Apply(mode); err != nil {
		return fmt.Errorf("apply policy mode %s: %w", mode, err)
	}

	for _, svc := range []string{"vpn-front", "vpn-front-routing", "vpn-backend-watchdog", "vpn-dashboard-collector"} {
		if out, err := run("/etc/init.d/"+svc, "restart"); err != nil {
			return fmt.Errorf("restart %s: %v: %s", svc, err, out)
		}
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
	tmp := dst + ".vpn-guardian-new"
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
	paths.StackConfig,
	paths.RoutingConfig,
	paths.ControlConfig,
	paths.AuthConfig,
	paths.FrontConfig,
	paths.PolicyConfig,
	paths.PolicyFailOpen,
	paths.PolicyVPNOnly,
	paths.PolicyBlocked,
	paths.PolicyDirect,
	paths.FrontNFT,
	paths.FrontEnabled,
	paths.PolicyMode,
	paths.PolicyRuntime,
	"/etc/v2raya/v2raya.db",
	paths.FrontServiceInit,
	paths.PolicyServiceInit,
	paths.FrontRoutingInit,
	paths.WatchdogServiceInit,
	paths.CollectorServiceInit,
}

func backup(reason string) (string, error) {
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return "", err
	}
	name := fmt.Sprintf("vpn-guardian-%s-%s.tar.gz", time.Now().Format("20060102-150405"), reason)
	path := filepath.Join(backupDir, name)
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	for _, p := range backupFiles {
		info, err := os.Lstat(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			tw.Close()
			gz.Close()
			f.Close()
			return "", err
		}
		linkTarget := ""
		if info.Mode()&os.ModeSymlink != 0 {
			linkTarget, err = os.Readlink(p)
			if err != nil {
				tw.Close()
				gz.Close()
				f.Close()
				return "", err
			}
		}
		h, err := tar.FileInfoHeader(info, linkTarget)
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

	dir, err := os.MkdirTemp("/tmp", "vpn-guardian-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := extractArchive(archive, dir); err != nil {
		return err
	}

	for _, source := range []string{
		paths.FrontConfig,
		paths.PolicyFailOpen,
		paths.PolicyVPNOnly,
		paths.PolicyBlocked,
		paths.PolicyDirect,
	} {
		rel := strings.TrimPrefix(filepath.Clean(source), string(os.PathSeparator))
		staged := filepath.Join(dir, rel)
		if _, err := os.Stat(staged); err != nil {
			return fmt.Errorf("archive missing %s", rel)
		}
		if out, err := run("/usr/bin/xray", "run", "-test", "-config", staged); err != nil {
			return fmt.Errorf("staged %s invalid: %v: %s", rel, err, out)
		}
	}
	nftPath := filepath.Join(dir, strings.TrimPrefix(filepath.Clean(paths.FrontNFT), string(os.PathSeparator)))
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
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, h.FileInfo().Mode()); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if filepath.IsAbs(h.Linkname) {
				return fmt.Errorf("unsafe absolute symlink target %q", h.Linkname)
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
				return err
			}
			resolved := filepath.Clean(filepath.Join(filepath.Dir(dst), h.Linkname))
			if resolved != dir && !strings.HasPrefix(resolved, dir+string(os.PathSeparator)) {
				return fmt.Errorf("unsafe symlink target %q", h.Linkname)
			}
			_ = os.Remove(dst)
			if err := os.Symlink(h.Linkname, dst); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
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
		default:
			return fmt.Errorf("unsupported archive entry type %d for %s", h.Typeflag, h.Name)
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
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
				return err
			}
			tmp := dst + ".vpn-guardian-new"
			_ = os.Remove(tmp)
			if err := os.Symlink(target, tmp); err != nil {
				return err
			}
			_ = os.Remove(dst)
			return os.Rename(tmp, dst)
		}
		return copyAtomic(path, dst, info.Mode())
	})
}

func runSelftest() error {
	out, err := run("/usr/bin/vpn-guardian", "selftest")
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
		Mode:            policy.Status(),
		Runtime:         policy.Runtime(),
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
