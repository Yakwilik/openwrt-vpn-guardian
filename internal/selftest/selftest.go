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

	"golang.org/x/net/proxy"
	"golang.org/x/sys/unix"
)

const (
	prodFrontSocks      = "127.0.0.1:20174"
	testPolicyPort      = 20178
	testFrontPort       = 20179
	testDeadBackendPort = 29999
	lockPath            = "/tmp/vpn-selftest.lock"
)

var homeIP = configuredHomeIP()

func configuredHomeIP() string {
	var cfg struct {
		HomeIP string `json:"homeIp"`
	}
	b, err := os.ReadFile("/etc/vpn-stack/stack.json")
	if err != nil {
		return ""
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return ""
	}
	return strings.TrimSpace(cfg.HomeIP)
}

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
	lock, err := acquireLock()
	if err != nil {
		rep.Checks = append(rep.Checks, Check{Name: "lock", OK: false, Detail: err.Error()})
		finish(rep)
		return
	}
	defer func() { unix.Flock(int(lock.Fd()), unix.LOCK_UN); lock.Close() }()

	runStaticChecks(&rep)
	runHealthyProduction(&rep)

	tmpDir, err := os.MkdirTemp("/tmp", "vpn-selftest-")
	if err != nil {
		rep.Checks = append(rep.Checks, Check{Name: "tempdir", OK: false, Detail: err.Error()})
		finish(rep)
		return
	}
	defer os.RemoveAll(tmpDir)

	if err := runIsolatedPolicyTests(&rep, tmpDir); err != nil {
		rep.Checks = append(rep.Checks, Check{Name: "isolated-tests", OK: false, Detail: err.Error()})
	}
	finish(rep)
}

func acquireLock() (*os.File, error) {
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
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

func runStaticChecks(rep *Report) {
	if ok, out := cmdOK("nft", "list", "table", "inet", "vpn_front"); ok {
		add(rep, "nft vpn_front", true, "present")
	} else {
		add(rep, "nft vpn_front", false, out)
	}

	rules, _ := exec.Command("ip", "rule", "show").CombinedOutput()
	ruleText := string(rules)
	add(rep, "policy rule table 101",
		strings.Contains(ruleText, "fwmark 0xc0/0xc0") && strings.Contains(ruleText, "lookup 101"),
		strings.TrimSpace(ruleText))
	add(rep, "no global LAN blackhole IPv4",
		!strings.Contains(ruleText, "iif br-lan blackhole"),
		strings.TrimSpace(ruleText))

	rules6, _ := exec.Command("ip", "-6", "rule", "show").CombinedOutput()
	rule6Text := string(rules6)
	add(rep, "no global LAN blackhole IPv6",
		!strings.Contains(rule6Text, "iif br-lan blackhole"),
		strings.TrimSpace(rule6Text))

	u4, _ := exec.Command("uci", "-q", "get", "network.vpn_block_lan_leak.disabled").CombinedOutput()
	u6, _ := exec.Command("uci", "-q", "get", "network.vpn_block_lan_leak_6.disabled").CombinedOutput()
	add(rep, "GL.iNet LAN leak guard disabled",
		strings.TrimSpace(string(u4)) == "1" && strings.TrimSpace(string(u6)) == "1",
		fmt.Sprintf("ipv4=%q ipv6=%q", strings.TrimSpace(string(u4)), strings.TrimSpace(string(u6))))

	route, _ := exec.Command("ip", "route", "show", "table", "101").CombinedOutput()
	routeText := string(route)
	add(rep, "route table 101",
		strings.Contains(routeText, "local default dev lo"),
		strings.TrimSpace(routeText))

	for _, svc := range []string{"vpn-front", "vpn-policy", "v2raya", "vpn-backend-watchdog", "vpn-dashboard-collector"} {
		ok, out := cmdOK("/etc/init.d/"+svc, "status")
		add(rep, "service "+svc, ok && strings.Contains(out, "running"), out)
	}

	for _, addr := range []string{"192.168.8.1:22", "192.168.8.1:80"} {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			c.Close()
		}
		add(rep, "router reachable "+addr, err == nil, errString(err))
	}

	testJSONAPI(rep, "status", "http://127.0.0.1/api/status")
	testJSONAPI(rep, "control", "http://127.0.0.1/api/control")
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

func runHealthyProduction(rep *Report) {
	direct, err := fetchHomeIPViaSocks(prodFrontSocks, 4*time.Second)
	add(rep, "healthy direct stays home", err == nil && direct == homeIP,
		fmt.Sprintf("ip=%s err=%v", direct, err))

	chatIP, err := fetchTraceIPViaSocks(prodFrontSocks, 6*time.Second)
	add(rep, "healthy proxy leaves via VPN",
		err == nil && chatIP != "" && chatIP != homeIP,
		fmt.Sprintf("ip=%s err=%v", chatIP, err))
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

func fetchTraceIPViaSocks(socksAddr string, timeout time.Duration) (string, error) {
	b, err := fetchViaSocks(socksAddr, "https://chatgpt.com/cdn-cgi/trace", timeout)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "ip=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "ip=")), nil
		}
	}
	return "", errors.New("trace response missing ip=")
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
func runIsolatedPolicyTests(rep *Report, tmpDir string) error {
	frontCfg, err := loadJSON("/etc/xray/vpn-front.json")
	if err != nil {
		return err
	}
	failCfg, err := loadJSON("/etc/xray/vpn-policy-failopen.json")
	if err != nil {
		return err
	}
	killCfg, err := loadJSON("/etc/xray/vpn-policy-killswitch.json")
	if err != nil {
		return err
	}
	blockCfg, err := loadJSON("/etc/xray/vpn-policy-killswitch-blocked.json")
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

	policyCmd, err := startXray(failPath)
	if err != nil {
		return err
	}
	defer stopProcess(policyCmd)
	frontCmd, err := startXray(frontPath)
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
	policyCmd, err = startXray(killPath)
	if err != nil {
		return err
	}
	if err := waitPort(testPolicyPort, 3*time.Second); err != nil {
		return err
	}
	runVPNOnlyChecks(rep)

	stopProcess(policyCmd)
	policyCmd, err = startXray(blockPath)
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
	direct, err := fetchHomeIPViaSocks("127.0.0.1:20179", 4*time.Second)
	add(rep, "failopen direct stays home", err == nil && direct == homeIP,
		fmt.Sprintf("ip=%s err=%v", direct, err))

	deadline := time.Now().Add(15 * time.Second)
	var ip string
	for time.Now().Before(deadline) {
		ip, err = fetchTraceIPViaSocks("127.0.0.1:20179", 4*time.Second)
		if err == nil && ip == homeIP {
			break
		}
		time.Sleep(time.Second)
	}
	add(rep, "failopen proxy falls back direct", err == nil && ip == homeIP,
		fmt.Sprintf("ip=%s err=%v", ip, err))
}

func runVPNOnlyChecks(rep *Report) {
	direct, err := fetchHomeIPViaSocks("127.0.0.1:20179", 4*time.Second)
	add(rep, "vpn-only direct stays home with dead backend", err == nil && direct == homeIP,
		fmt.Sprintf("ip=%s err=%v", direct, err))

	start := time.Now()
	ip, err := fetchTraceIPViaSocks("127.0.0.1:20179", 4*time.Second)
	dur := time.Since(start)
	add(rep, "vpn-only proxy fails closed without direct fallback", err != nil && ip != homeIP,
		fmt.Sprintf("ip=%s failed_in=%s err=%v", ip, dur.Round(time.Millisecond), err))
}

func runBlockedChecks(rep *Report) {
	direct, err := fetchHomeIPViaSocks("127.0.0.1:20179", 4*time.Second)
	add(rep, "killswitch direct stays home", err == nil && direct == homeIP,
		fmt.Sprintf("ip=%s err=%v", direct, err))

	start := time.Now()
	_, err = fetchTraceIPViaSocks("127.0.0.1:20179", 2*time.Second)
	dur := time.Since(start)
	add(rep, "killswitch proxy blocked", err != nil && dur < 1500*time.Millisecond,
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

func startXray(config string) (*exec.Cmd, error) {
	cmd := exec.Command("/usr/bin/xray", "run", "-config", config)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET=/usr/share/xray")
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
