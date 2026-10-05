package collector

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/netstate"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
	v2rayautil "github.com/Yakwilik/openwrt-vpn-guardian/internal/v2raya"

	"golang.org/x/net/proxy"
	_ "modernc.org/sqlite"
)

const (
	dbPath      = "/etc/v2raya/v2raya.db"
	controlPath = paths.ControlConfig
	statePath   = paths.WatchdogState
	cachePath   = paths.StatusCache
	historyPath = paths.History
)

type ProbeResult struct {
	Name  string `json:"name"`
	Code  int    `json:"code"`
	MS    int64  `json:"ms"`
	Error string `json:"error,omitempty"`
}
type HealthResult struct {
	Healthy bool          `json:"healthy"`
	Status  string        `json:"status"`
	Passed  int           `json:"passed"`
	Total   int           `json:"total"`
	Results []ProbeResult `json:"results"`
}

type WatchdogState struct {
	Failures       int          `json:"failures"`
	LastCheck      int64        `json:"lastCheck"`
	LastHealthy    int64        `json:"lastHealthy"`
	LastFailure    int64        `json:"lastFailure"`
	LastSwitch     int64        `json:"lastSwitch"`
	LastNode       string       `json:"lastNode"`
	LastFailedNode string       `json:"lastFailedNode,omitempty"`
	LastHealth     HealthResult `json:"lastHealth"`
}

type Control struct {
	Mode          string `json:"mode"`
	FailurePolicy string `json:"failurePolicy"`
}

type ServiceStatus struct {
	V2rayA    string `json:"v2raya"`
	Front     string `json:"front"`
	Policy    string `json:"policy"`
	Watchdog  string `json:"watchdog"`
	Collector string `json:"collector"`
	API       string `json:"api"`
}

type TProxyStatus struct {
	NFT          bool `json:"nft"`
	Policy       bool `json:"policy"`
	Route        bool `json:"route"`
	BackendSOCKS bool `json:"backend_socks"`
	FrontPort    bool `json:"front_port"`
	RouteTable   int  `json:"route_table"`
}

type HealthBrief struct {
	Code int   `json:"code"`
	MS   int64 `json:"ms"`
}

type Status struct {
	Now                int64                  `json:"now"`
	Overall            string                 `json:"overall"`
	Architecture       string                 `json:"architecture"`
	ControlMode        string                 `json:"control_mode"`
	FailurePolicy      string                 `json:"failure_policy"`
	PolicyMode         string                 `json:"policy_mode"`
	PolicyRuntime      string                 `json:"policy_runtime"`
	Node               string                 `json:"node"`
	Protocol           string                 `json:"protocol"`
	Endpoint           string                 `json:"endpoint"`
	EgressIP           string                 `json:"vpn_ip"`
	HomeIP             string                 `json:"home_ip"`
	Transparent        string                 `json:"transparent"`
	PACMode            string                 `json:"pac_mode"`
	DesiredTransparent string                 `json:"desired_transparent"`
	TProxyActive       bool                   `json:"tproxy_active"`
	FallbackDirect     bool                   `json:"fallback_direct"`
	Failures           int                    `json:"failures"`
	LastSwitch         int64                  `json:"last_switch"`
	LastFailedNode     string                 `json:"last_failed_node"`
	LastFailedAt       int64                  `json:"last_failed_at"`
	Candidates         int                    `json:"candidates"`
	NodesTotal         int                    `json:"nodes_total"`
	Services           ServiceStatus          `json:"services"`
	TProxy             TProxyStatus           `json:"tproxy"`
	HealthCount        int                    `json:"health_count"`
	Health             map[string]HealthBrief `json:"health"`
	Events             []string               `json:"events,omitempty"`
}
type runtimeState struct {
	lastEgressAt time.Time
	lastEgress   string
	lastHomeAt   time.Time
	lastHome     string
	lastHistory  time.Time
	lastNode     string
}

func Run(args []string) {
	fs := flag.NewFlagSet("vpn-guardian collector", flag.ExitOnError)
	mode := fs.String("mode", "collect", "collect|once")
	interval := fs.Duration("interval", 3*time.Second, "snapshot interval")
	cache := fs.String("cache", cachePath, "status cache path")
	history := fs.String("history", historyPath, "history TSV path")
	_ = fs.Parse(args)

	switch *mode {
	case "once":
		s, err := collectSnapshot(&runtimeState{})
		if err != nil {
			fmt.Fprintln(os.Stderr, "collector:", err)
			return
		}
		_ = json.NewEncoder(os.Stdout).Encode(s)
	case "collect":
		if *interval < time.Second {
			*interval = time.Second
		}
		runDaemon(*interval, *cache, *history)
	default:
		fmt.Fprintln(os.Stderr, "collector: unknown mode", *mode)
	}
}

func runDaemon(interval time.Duration, cache, history string) {
	rt := &runtimeState{}
	for {
		s, err := collectSnapshot(rt)
		if err != nil {
			fmt.Fprintln(os.Stderr, "collector:", err)
		} else if err := writeJSONAtomic(cache, s); err != nil {
			fmt.Fprintln(os.Stderr, "collector cache:", err)
		} else {
			appendHistory(rt, s, history)
		}
		time.Sleep(interval)
	}
}
func collectSnapshot(rt *runtimeState) (Status, error) {
	var out Status
	out.Now = time.Now().Unix()
	out.Architecture = "front"

	stack, err := config.LoadStack()
	if err != nil {
		return out, fmt.Errorf("load stack config: %w", err)
	}

	var ctrl Control
	_ = readJSON(controlPath, &ctrl)
	if ctrl.Mode == "" {
		ctrl.Mode = "auto"
	}
	if ctrl.FailurePolicy == "" {
		ctrl.FailurePolicy = "killswitch"
	}
	out.ControlMode = ctrl.Mode
	out.FailurePolicy = ctrl.FailurePolicy
	out.PolicyMode = readTrimmed(paths.PolicyMode)
	out.PolicyRuntime = readTrimmed(paths.PolicyRuntime)

	var state WatchdogState
	_ = readJSON(statePath, &state)
	out.Failures = state.Failures
	out.LastSwitch = state.LastSwitch
	out.LastFailedAt = state.LastFailure
	out.LastFailedNode = state.LastFailedNode
	out.HealthCount = state.LastHealth.Passed
	out.Health = make(map[string]HealthBrief, len(state.LastHealth.Results))
	for _, p := range state.LastHealth.Results {
		out.Health[p.Name] = HealthBrief{Code: p.Code, MS: p.MS}
	}
	db, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return out, err
	}
	defer db.Close()

	selection, err := v2rayautil.NewCandidatePolicy(stack.Selection)
	if err != nil {
		return out, err
	}
	node, protocol, endpoint, candidates, total, transparent, pacMode, err := dbStatus(db, selection)
	if err != nil {
		return out, err
	}
	out.Node = node
	out.Protocol = protocol
	out.Endpoint = endpoint
	out.Candidates = candidates
	out.NodesTotal = total
	out.Transparent = transparent
	out.PACMode = pacMode
	out.DesiredTransparent = "close"

	out.Services = ServiceStatus{
		V2rayA:    serviceState("v2raya"),
		Front:     serviceState("vpn-front"),
		Policy:    serviceState("vpn-policy"),
		Watchdog:  serviceState("vpn-backend-watchdog"),
		Collector: serviceState("vpn-dashboard-collector"),
		API:       serviceState("vpn-guardian-api"),
	}
	out.TProxy = inspectTProxy(stack)
	out.TProxyActive = out.TProxy.NFT && out.TProxy.Policy && out.TProxy.Route && out.TProxy.FrontPort

	if rt.lastHome == "" || time.Since(rt.lastHomeAt) >= 30*time.Second {
		if ip, err := fetchDirectIP(); err == nil {
			rt.lastHome = ip
			rt.lastHomeAt = time.Now()
		}
	}
	out.HomeIP = rt.lastHome

	if rt.lastEgress == "" || time.Since(rt.lastEgressAt) >= 30*time.Second {
		if ip, err := fetchEgressIP(stack.Backend.SocksPort); err == nil {
			rt.lastEgress = ip
			rt.lastEgressAt = time.Now()
		}
	}
	out.EgressIP = rt.lastEgress

	out.FallbackDirect = ctrl.FailurePolicy == "failopen" && state.LastHealth.Status == "down"
	out.Overall = overallStatus(ctrl, state.LastHealth, out.TProxyActive)
	return out, nil
}
func dbStatus(db *sql.DB, selection v2rayautil.CandidatePolicy) (node, protocol, endpoint string, candidates, total int, transparent, pacMode string, err error) {
	var connectedRaw string
	if err = db.QueryRow("SELECT value FROM system_config WHERE key='outbound.proxy:connectedServers'").Scan(&connectedRaw); err != nil {
		return
	}

	var connected struct {
		Touches []struct {
			ID  int `json:"id"`
			Sub int `json:"sub"`
		} `json:"touches"`
	}
	_ = json.Unmarshal([]byte(connectedRaw), &connected)

	var subIDs []int
	rows, qerr := db.Query("SELECT id FROM subscriptions ORDER BY sort,id")
	if qerr != nil {
		err = qerr
		return
	}
	for rows.Next() {
		var id int
		if rows.Scan(&id) == nil {
			subIDs = append(subIDs, id)
		}
	}
	rows.Close()

	if len(connected.Touches) > 0 {
		t := connected.Touches[0]
		if t.Sub >= 0 && t.Sub < len(subIDs) {
			var raw string
			qerr = db.QueryRow("SELECT config_json FROM servers WHERE type='subscription_server' AND sub_id=? AND sort=? LIMIT 1", subIDs[t.Sub], t.ID-1).Scan(&raw)
			if qerr == nil {
				node, protocol, endpoint = parseNode(raw)
			}
		}
	}
	if err = db.QueryRow("SELECT count(*) FROM servers WHERE type='subscription_server'").Scan(&total); err != nil {
		return
	}
	eligible, candidateErr := v2rayautil.ListCandidates(context.Background(), db, selection)
	if candidateErr != nil {
		err = candidateErr
		return
	}
	candidates = len(eligible)

	var settingRaw string
	if db.QueryRow("SELECT value FROM system_config WHERE key='system:setting'").Scan(&settingRaw) == nil {
		var settings map[string]any
		if json.Unmarshal([]byte(settingRaw), &settings) == nil {
			transparent = fmt.Sprint(settings["transparent"])
			pacMode = fmt.Sprint(settings["pacMode"])
		}
	}
	return
}

func parseNode(raw string) (name, protocol, endpoint string) {
	var root map[string]any
	if json.Unmarshal([]byte(raw), &root) != nil {
		return
	}
	obj := root
	if v, ok := root["serverObj"].(map[string]any); ok {
		obj = v
	}
	name = field(obj, "ps", "name", "remarks")
	proto := strings.ToLower(field(obj, "protocol"))
	network := strings.ToLower(field(obj, "net", "network"))
	security := strings.ToLower(field(obj, "tls", "security"))
	protocol = proto
	if network != "" || security != "" {
		protocol = fmt.Sprintf("%s(%s+%s)", proto, network, security)
	}
	host := field(obj, "add", "address", "host")
	port := field(obj, "port")
	if host != "" {
		endpoint = host
		if port != "" {
			endpoint += ":" + port
		}
	}
	return
}

func field(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := m[key]; ok && v != nil {
			return fmt.Sprint(v)
		}
	}
	return ""
}

func overallStatus(ctrl Control, health HealthResult, frontOK bool) string {
	if ctrl.Mode == "direct" {
		return "direct"
	}
	if !frontOK {
		return "down"
	}
	switch health.Status {
	case "down":
		if ctrl.FailurePolicy == "failopen" {
			return "failopen"
		}
		return "degraded"
	case "degraded":
		return "degraded"
	default:
		return "ok"
	}
}
func inspectTProxy(stack config.Stack) TProxyStatus {
	return TProxyStatus{
		NFT:          commandOK("nft", "list", "table", "inet", "vpn_front"),
		Policy:       commandContains("ip", []string{"rule", "show"}, fmt.Sprintf("lookup %d", stack.Front.RouteTable)),
		Route:        commandContains("ip", []string{"route", "show", "table", fmt.Sprint(stack.Front.RouteTable)}, "local default dev lo"),
		BackendSOCKS: portReady(fmt.Sprintf("127.0.0.1:%d", stack.Backend.SocksPort)),
		FrontPort:    netstate.TCPListening(stack.Front.TProxyPort),
		RouteTable:   stack.Front.RouteTable,
	}
}

func serviceState(name string) string {
	out, err := exec.Command("/etc/init.d/"+name, "status").CombinedOutput()
	if err == nil && strings.Contains(string(out), "running") {
		return "running"
	}
	return "stopped"
}

func commandOK(name string, args ...string) bool {
	return exec.Command(name, args...).Run() == nil
}

func commandContains(name string, args []string, needle string) bool {
	out, err := exec.Command(name, args...).CombinedOutput()
	return err == nil && strings.Contains(string(out), needle)
}

func portReady(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
func fetchDirectIP() (string, error) {
	tr := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 1500 * time.Millisecond}).DialContext,
		TLSHandshakeTimeout: 3 * time.Second,
	}
	defer tr.CloseIdleConnections()
	return fetchPublicIP(&http.Client{Transport: tr, Timeout: 5 * time.Second})
}

func fetchEgressIP(socksPort int) (string, error) {
	base := &net.Dialer{Timeout: 1500 * time.Millisecond}
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, base)
	if err != nil {
		return "", err
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.Dial(network, address)
		},
		TLSHandshakeTimeout: 3 * time.Second,
	}
	defer tr.CloseIdleConnections()
	return fetchPublicIP(&http.Client{Transport: tr, Timeout: 5 * time.Second})
}

func fetchPublicIP(client *http.Client) (string, error) {
	for _, u := range []string{"https://api.ipify.org", "https://icanhazip.com"} {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		b, readErr := io.ReadAll(io.LimitReader(resp.Body, 256))
		_ = resp.Body.Close()
		if readErr == nil && resp.StatusCode < 500 {
			if ip := strings.TrimSpace(string(b)); ip != "" {
				return ip, nil
			}
		}
	}
	return "", fmt.Errorf("no public IP endpoint succeeded")
}

func appendHistory(rt *runtimeState, s Status, path string) {
	if !rt.lastHistory.IsZero() && time.Since(rt.lastHistory) < time.Minute {
		return
	}
	availability := 0
	if s.HealthCount >= 2 {
		availability = 100
	} else if s.HealthCount > 0 {
		availability = s.HealthCount * 25
	}
	failed := 4 - s.HealthCount
	if failed < 0 {
		failed = 0
	}
	switchFlag := 0
	if rt.lastNode != "" && s.Node != "" && s.Node != rt.lastNode {
		switchFlag = 1
	}
	line := fmt.Sprintf("%d\t%d\t%d\t%d\t%s\t%d\t%s\n",
		s.Now, availability, s.HealthCount, failed, s.Overall, switchFlag,
		strings.NewReplacer("\t", " ", "\n", " ").Replace(s.Node))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		_, _ = f.WriteString(line)
		_ = f.Close()
	}
	rt.lastHistory = time.Now()
	rt.lastNode = s.Node
}
func readJSON(path string, dst any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

func readTrimmed(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func writeJSONAtomic(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := path + ".new"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
