package selftest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"

	"golang.org/x/net/proxy"
	"golang.org/x/sys/unix"
)

const (
	testPolicyPort      = 20178
	testFrontPort       = 20179
	testDeadBackendPort = 29999
)

var homeIP string

type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type Report struct {
	OK         bool    `json:"ok"`
	StartedAt  int64   `json:"startedAt"`
	FinishedAt int64   `json:"finishedAt"`
	Checks     []Check `json:"checks"`
}

func main() {
	rep := Report{StartedAt: time.Now().Unix()}

	cfg, err := config.LoadStack()
	if err != nil {
		rep.Checks = append(rep.Checks, Check{Name: "stack config", OK: false, Detail: err.Error()})
		finish(rep)
		return
	}

	lock, err := acquireLock()
	if err != nil {
		rep.Checks = append(rep.Checks, Check{Name: "lock", OK: false, Detail: err.Error()})
		finish(rep)
		return
	}
	defer func() { unix.Flock(int(lock.Fd()), unix.LOCK_UN); lock.Close() }()

	runStaticChecks(&rep, cfg)
	runHealthyProduction(&rep, cfg)

	tmpDir, err := os.MkdirTemp("/tmp", "vpn-guardian-selftest-")
	if err != nil {
		rep.Checks = append(rep.Checks, Check{Name: "tempdir", OK: false, Detail: err.Error()})
		finish(rep)
		return
	}
	defer os.RemoveAll(tmpDir)

	if err := runIsolatedPolicyTests(&rep, tmpDir, cfg.AssetsDir); err != nil {
		rep.Checks = append(rep.Checks, Check{Name: "isolated-tests", OK: false, Detail: err.Error()})
	}
	finish(rep)
}

func acquireLock() (*os.File, error) {
	f, err := os.OpenFile(paths.SelftestLock, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("self-test already running: %w", err)
	}
	return f, nil
}

func finish(rep Report) {
	rep.FinishedAt = time.Now().Unix()
	rep.OK = true
	for _, c := range rep.Checks {
		if !c.OK {
			rep.OK = false
			break
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(rep)
	if !rep.OK {
		os.Exit(1)
	}
}
func add(rep *Report, name string, ok bool, detail string) {
	rep.Checks = append(rep.Checks, Check{Name: name, OK: ok, Detail: detail})
}

func cmdOK(name string, args ...string) (bool, string) {
	b, err := exec.Command(name, args...).CombinedOutput()
	return err == nil, strings.TrimSpace(string(b))
}

func runStaticChecks(rep *Report, cfg config.Stack) {
	if ok, out := cmdOK("nft", "list", "table", "inet", "vpn_front"); ok {
		add(rep, "nft vpn_front", true, "present")
	} else {
		add(rep, "nft vpn_front", false, out)
	}

	rules, _ := exec.Command("ip", "rule", "show").CombinedOutput()
	ruleText := string(rules)
	expectedMark := fmt.Sprintf("fwmark 0x%x/0x%x", cfg.Front.Mark, cfg.Front.Mark)
	expectedTable := fmt.Sprintf("lookup %d", cfg.Front.RouteTable)
	add(rep, "front policy rule",
		strings.Contains(ruleText, expectedMark) && strings.Contains(ruleText, expectedTable),
		strings.TrimSpace(ruleText))
	add(rep, "no global LAN blackhole IPv4",
		!strings.Contains(ruleText, "iif "+cfg.LANInterface+" blackhole"),
		strings.TrimSpace(ruleText))

	rules6, _ := exec.Command("ip", "-6", "rule", "show").CombinedOutput()
	rule6Text := string(rules6)
	add(rep, "no global LAN blackhole IPv6",
		!strings.Contains(rule6Text, "iif "+cfg.LANInterface+" blackhole"),
		strings.TrimSpace(rule6Text))

	route, _ := exec.Command("ip", "route", "show", "table", fmt.Sprint(cfg.Front.RouteTable)).CombinedOutput()
	routeText := string(route)
	add(rep, "front route table",
		strings.Contains(routeText, "local default dev lo"),
		strings.TrimSpace(routeText))

	for _, svc := range []string{"vpn-front", "vpn-policy", "v2raya", "vpn-backend-watchdog", "vpn-dashboard-collector", "vpn-guardian-api"} {
		ok, out := cmdOK("/etc/init.d/"+svc, "status")
		add(rep, "service "+svc, ok && strings.Contains(out, "running"), out)
	}

	testJSONAPI(rep, "status", "http://127.0.0.1:20175/api/status")
	testJSONAPI(rep, "control", "http://127.0.0.1:20175/api/control")
}
func testJSONAPI(rep *Report, name, url string) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Host = "vpn.home.arpa"
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		add(rep, "api "+name, false, err.Error())
		return
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	var v any
	err = json.Unmarshal(b, &v)
	add(rep, "api "+name, err == nil && resp.StatusCode == 200,
		fmt.Sprintf("http=%d bytes=%d err=%v", resp.StatusCode, len(b), err))
}

func runHealthyProduction(rep *Report, cfg config.Stack) {
	direct, err := fetchHomeIPViaSocks(fmt.Sprintf("127.0.0.1:%d", cfg.Front.SocksPort), 4*time.Second)
	if err == nil && direct != "" {
		homeIP = direct
	}
	add(rep, "healthy direct egress discovered", err == nil && homeIP != "",
		fmt.Sprintf("ip=%s err=%v", direct, err))

	vpnIP, err := fetchHomeIPViaSocks(fmt.Sprintf("127.0.0.1:%d", cfg.Backend.SocksPort), 6*time.Second)
	add(rep, "healthy VPN backend leaves via VPN",
		err == nil && vpnIP != "" && vpnIP != homeIP,
		fmt.Sprintf("ip=%s err=%v", vpnIP, err))
}
func fetchHomeIPViaSocks(socksAddr string, timeout time.Duration) (string, error) {
	urls := []string{"https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip"}
	var errs []string
	for _, u := range urls {
		ip, err := fetchIPViaSocks(socksAddr, u, timeout)
		if err == nil && ip != "" {
			return ip, nil
		}
		if err != nil {
			errs = append(errs, u+": "+err.Error())
		}
	}
	return "", errors.New(strings.Join(errs, "; "))
}

func fetchIPViaSocks(socksAddr, url string, timeout time.Duration) (string, error) {
	b, err := fetchViaSocks(socksAddr, url, timeout)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func fetchViaSocks(socksAddr, url string, timeout time.Duration) ([]byte, error) {
	base := &net.Dialer{Timeout: 1500 * time.Millisecond}
	d, err := proxy.SOCKS5("tcp", socksAddr, nil, base)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			type result struct {
				c   net.Conn
				err error
			}
			ch := make(chan result, 1)
			go func() { c, e := d.Dial(network, address); ch <- result{c, e} }()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case r := <-ch:
				return r.c, r.err
			}
		},
		TLSHandshakeTimeout: 2 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<10))
}
func runIsolatedPolicyTests(rep *Report, tmpDir, assetsDir string) error {
	frontCfg, err := loadJSON(paths.FrontConfig)
	if err != nil {
		return err
	}
	failCfg, err := loadJSON(paths.PolicyFailOpen)
	if err != nil {
		return err
	}
	killCfg, err := loadJSON(paths.PolicyVPNOnly)
	if err != nil {
		return err
	}
	blockCfg, err := loadJSON(paths.PolicyBlocked)
	if err != nil {
		return err
	}

	prepareFront(frontCfg)
	preparePolicy(failCfg)
	preparePolicy(killCfg)
	preparePolicy(blockCfg)

	frontPath := filepath.Join(tmpDir, "front.json")
	failPath := filepath.Join(tmpDir, "policy-failopen.json")
	killPath := filepath.Join(tmpDir, "policy-killswitch.json")
	blockPath := filepath.Join(tmpDir, "policy-blocked.json")
	if err := writeJSON(frontPath, frontCfg); err != nil {
		return err
	}
	if err := writeJSON(failPath, failCfg); err != nil {
		return err
	}
	if err := writeJSON(killPath, killCfg); err != nil {
		return err
	}
	if err := writeJSON(blockPath, blockCfg); err != nil {
		return err
	}

	policyCmd, err := startXray(failPath, assetsDir)
	if err != nil {
		return err
	}
	defer stopProcess(policyCmd)
	frontCmd, err := startXray(frontPath, assetsDir)
	if err != nil {
		return err
	}
	defer stopProcess(frontCmd)

	if err := waitPort(testPolicyPort, 3*time.Second); err != nil {
		return err
	}
	if err := waitPort(testFrontPort, 3*time.Second); err != nil {
		return err
	}

	runFailopenChecks(rep)

	stopProcess(policyCmd)
	policyCmd, err = startXray(killPath, assetsDir)
	if err != nil {
		return err
	}
	if err := waitPort(testPolicyPort, 3*time.Second); err != nil {
		return err
	}
	runVPNOnlyChecks(rep)

	stopProcess(policyCmd)
	policyCmd, err = startXray(blockPath, assetsDir)
	if err != nil {
		return err
	}
	if err := waitPort(testPolicyPort, 3*time.Second); err != nil {
		return err
	}
	runBlockedChecks(rep)
	stopProcess(policyCmd)
	policyCmd = nil
	return nil
}
func prepareFront(cfg map[string]any) {
	inbounds, _ := cfg["inbounds"].([]any)
	var kept []any
	for _, raw := range inbounds {
		m, _ := raw.(map[string]any)
		if fmt.Sprint(m["tag"]) != "front-socks" {
			continue
		}
		m["port"] = testFrontPort
		kept = append(kept, m)
	}
	cfg["inbounds"] = kept

	outbounds, _ := cfg["outbounds"].([]any)
	for _, raw := range outbounds {
		m, _ := raw.(map[string]any)
		if fmt.Sprint(m["tag"]) != "policy-gateway" {
			continue
		}
		settings, _ := m["settings"].(map[string]any)
		servers, _ := settings["servers"].([]any)
		if len(servers) > 0 {
			s, _ := servers[0].(map[string]any)
			s["port"] = testPolicyPort
		}
	}

	// Isolated policy tests need one deterministic proxy-class destination that
	// is also reachable without VPN. This makes fail-open semantics testable
	// without depending on a service that may itself be blocked by the ISP.
	cfg["routing"] = map[string]any{
		"domainStrategy": "AsIs",
		"rules": []any{
			map[string]any{
				"type":        "field",
				"domain":      []string{"domain:api.ipify.org"},
				"outboundTag": "policy-gateway",
			},
			map[string]any{
				"type":        "field",
				"network":     "tcp,udp",
				"outboundTag": "direct",
			},
		},
	}
}

func preparePolicy(cfg map[string]any) {
	inbounds, _ := cfg["inbounds"].([]any)
	for _, raw := range inbounds {
		m, _ := raw.(map[string]any)
		if fmt.Sprint(m["tag"]) == "policy-socks" {
			m["port"] = testPolicyPort
		}
	}
	outbounds, _ := cfg["outbounds"].([]any)
	for _, raw := range outbounds {
		m, _ := raw.(map[string]any)
		if fmt.Sprint(m["tag"]) != "vpn-backend" {
			continue
		}
		settings, _ := m["settings"].(map[string]any)
		servers, _ := settings["servers"].([]any)
		if len(servers) > 0 {
			s, _ := servers[0].(map[string]any)
			s["port"] = testDeadBackendPort
		}
	}
}
func runFailopenChecks(rep *Report) {
	direct, err := fetchIPViaSocks("127.0.0.1:20179", "https://icanhazip.com", 4*time.Second)
	add(rep, "failopen direct stays home", err == nil && direct == homeIP,
		fmt.Sprintf("ip=%s err=%v", direct, err))

	deadline := time.Now().Add(15 * time.Second)
	var ip string
	for time.Now().Before(deadline) {
		ip, err = fetchIPViaSocks("127.0.0.1:20179", "https://api.ipify.org", 4*time.Second)
		if err == nil && ip == homeIP {
			break
		}
		time.Sleep(time.Second)
	}
	add(rep, "failopen proxy falls back direct", err == nil && ip == homeIP,
		fmt.Sprintf("ip=%s err=%v", ip, err))
}

func runVPNOnlyChecks(rep *Report) {
	direct, err := fetchIPViaSocks("127.0.0.1:20179", "https://icanhazip.com", 4*time.Second)
	add(rep, "vpn-only direct stays home with dead backend", err == nil && direct == homeIP,
		fmt.Sprintf("ip=%s err=%v", direct, err))

	start := time.Now()
	ip, err := fetchIPViaSocks("127.0.0.1:20179", "https://api.ipify.org", 4*time.Second)
	dur := time.Since(start)
	add(rep, "vpn-only proxy fails closed without direct fallback", err != nil && ip != homeIP,
		fmt.Sprintf("ip=%s failed_in=%s err=%v", ip, dur.Round(time.Millisecond), err))
}

func runBlockedChecks(rep *Report) {
	direct, err := fetchIPViaSocks("127.0.0.1:20179", "https://icanhazip.com", 4*time.Second)
	add(rep, "emergency block direct stays home", err == nil && direct == homeIP,
		fmt.Sprintf("ip=%s err=%v", direct, err))

	start := time.Now()
	_, err = fetchIPViaSocks("127.0.0.1:20179", "https://api.ipify.org", 2*time.Second)
	dur := time.Since(start)
	add(rep, "emergency block rejects proxy class", err != nil && dur < 1500*time.Millisecond,
		fmt.Sprintf("blocked_in=%s err=%v", dur.Round(time.Millisecond), err))
}
func loadJSON(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

func startXray(config, assetsDir string) (*exec.Cmd, error) {
	cmd := exec.Command("/usr/bin/xray", "run", "-config", config)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+assetsDir)
	var stderr bytes.Buffer
	cmd.Stdout = &stderr
	cmd.Stderr = &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	time.Sleep(250 * time.Millisecond)
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return nil, fmt.Errorf("xray exited: %s", stderr.String())
	}
	return cmd, nil
}

func stopProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
func waitPort(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 150*time.Millisecond)
		if err == nil {
			c.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("port %d not ready", port)
}

func errString(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

// Run executes the isolated production self-test.
func Run(args []string) {
	_ = args
	main()
}
