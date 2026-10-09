package watchdog

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/lockfile"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/policy"
	v2rayautil "github.com/Yakwilik/openwrt-vpn-guardian/internal/v2raya"

	"golang.org/x/net/proxy"
	"golang.org/x/sys/unix"
)

const (
	dbPath            = "/etc/v2raya/v2raya.db"
	controlPath       = paths.ControlConfig
	statePath         = paths.WatchdogState
	eventPath         = paths.Events
	proxyAddr         = "127.0.0.1:20173"
	tag               = "vpn-guardian-watchdog"
	policyRuntimePath = paths.PolicyRuntime
	policyModePath    = paths.PolicyMode
	lockPath          = paths.WatchdogLock
)

type Candidate = v2rayautil.Candidate

type Control struct {
	Mode          string `json:"mode"`
	FailurePolicy string `json:"failurePolicy"`
}

type NodeStats struct {
	Successes           int     `json:"successes"`
	Failures            int     `json:"failures"`
	ConsecutiveFailures int     `json:"consecutiveFailures"`
	LastSuccess         int64   `json:"lastSuccess,omitempty"`
	LastFailure         int64   `json:"lastFailure,omitempty"`
	CooldownUntil       int64   `json:"cooldownUntil,omitempty"`
	EWMALatencyMS       float64 `json:"ewmaLatencyMs,omitempty"`
}

type State struct {
	Failures       int                  `json:"failures"`
	LastCheck      int64                `json:"lastCheck"`
	LastHealthy    int64                `json:"lastHealthy,omitempty"`
	LastFailure    int64                `json:"lastFailure,omitempty"`
	LastSwitch     int64                `json:"lastSwitch,omitempty"`
	LastNode       string               `json:"lastNode,omitempty"`
	LastFailedNode string               `json:"lastFailedNode,omitempty"`
	LastError      string               `json:"lastError,omitempty"`
	LastHealth     HealthResult         `json:"lastHealth"`
	Nodes          map[string]NodeStats `json:"nodes,omitempty"`
}

type RankedCandidate struct {
	Candidate
	Score         float64 `json:"score"`
	CooldownUntil int64   `json:"cooldownUntil,omitempty"`
	Cooling       bool    `json:"cooling"`
}

type ProbeResult struct {
	Name  string `json:"name"`
	URL   string `json:"url"`
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

type healthTarget struct {
	Name           string
	URL            string
	Required       bool
	ExpectedStatus []int
}

func (t healthTarget) accepts(code int) bool {
	for _, expected := range t.ExpectedStatus {
		if code == expected {
			return true
		}
	}
	return false
}

func healthTargetByName(name string) (healthTarget, bool) {
	for _, target := range healthTargets {
		if target.Name == name {
			return target, true
		}
	}
	return healthTarget{}, false
}

func probeAccepted(result ProbeResult) bool {
	target, ok := healthTargetByName(result.Name)
	return ok && target.accepts(result.Code)
}

var healthTargets = []healthTarget{
	{
		Name:           "google",
		URL:            "https://connectivitycheck.gstatic.com/generate_204",
		ExpectedStatus: []int{http.StatusNoContent},
	},
	{
		Name:           "cloudflare",
		URL:            "https://cp.cloudflare.com/generate_204",
		ExpectedStatus: []int{http.StatusNoContent},
	},
	{
		Name:           "telegram",
		URL:            "https://api.telegram.org/bot0:invalid/getMe",
		Required:       true,
		ExpectedStatus: []int{http.StatusUnauthorized},
	},
	{
		Name:           "openai",
		URL:            "https://api.openai.com/v1/models",
		Required:       true,
		ExpectedStatus: []int{http.StatusUnauthorized},
	},
	{
		Name:           "chatgpt",
		URL:            "https://chatgpt.com/backend-api/me",
		Required:       true,
		ExpectedStatus: []int{http.StatusUnauthorized},
	},
}

func main() {
	mode := flag.String("mode", "run", "run|daemon|health|inspect")
	interval := flag.Duration("interval", 10*time.Second, "daemon interval between completed checks")
	flag.Parse()

	var err error
	switch *mode {
	case "run":
		var lock *os.File
		lock, err = acquireInstanceLock(false)
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			fmt.Println("daemon already running")
			return
		}
		if err == nil {
			defer releaseInstanceLock(lock)
			err = run(true)
		}
	case "daemon":
		err = daemon(*interval)
	case "health":
		h := healthNow()
		_ = json.NewEncoder(os.Stdout).Encode(h)
		if !h.Healthy {
			os.Exit(2)
		}
	case "inspect":
		err = inspect()
	default:
		err = fmt.Errorf("unknown mode %q", *mode)
	}
	if err != nil {
		logLine("error: %v", err)
		os.Exit(1)
	}
}

func acquireInstanceLock(block bool) (*os.File, error) {
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	op := unix.LOCK_EX
	if !block {
		op |= unix.LOCK_NB
	}
	if err := unix.Flock(int(f.Fd()), op); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func releaseInstanceLock(f *os.File) {
	if f == nil {
		return
	}
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	_ = f.Close()
}

func daemon(interval time.Duration) error {
	if interval < time.Second {
		interval = time.Second
	}
	lock, err := acquireInstanceLock(false)
	if err != nil {
		return fmt.Errorf("acquire daemon lock: %w", err)
	}
	defer releaseInstanceLock(lock)
	logLine("daemon started interval=%s", interval)
	for {
		if err := run(false); err != nil {
			logLine("daemon iteration error: %v", err)
		}
		time.Sleep(interval)
	}
}

func openDB() (*sql.DB, error) {
	return v2rayautil.OpenDB()
}

func getRaw(db *sql.DB, key string) (string, error) {
	return v2rayautil.GetRaw(db, key)
}

func candidates(db *sql.DB) ([]Candidate, error) {
	cfg, err := config.LoadStack()
	if err != nil {
		return nil, fmt.Errorf("load candidate selection: %w", err)
	}
	selection, err := v2rayautil.NewCandidatePolicy(cfg.Selection)
	if err != nil {
		return nil, err
	}
	return v2rayautil.ListCandidates(context.Background(), db, selection)
}

func current(db *sql.DB) (id, sub int, ok bool) {
	touch, found, err := v2rayautil.ConnectedTouch(context.Background(), db)
	if err != nil {
		return 0, 0, false
	}
	return touch.ID, touch.Sub, found
}

func loadControl() Control {
	c := Control{Mode: "auto", FailurePolicy: "killswitch"}
	b, err := os.ReadFile(controlPath)
	if err == nil {
		_ = json.Unmarshal(b, &c)
	}
	if c.Mode == "" {
		c.Mode = "auto"
	}
	if c.FailurePolicy == "" {
		c.FailurePolicy = "killswitch"
	}
	return c
}

func loadState() State {
	var s State
	if b, err := os.ReadFile(statePath); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	if s.Nodes == nil {
		s.Nodes = map[string]NodeStats{}
	}
	return s
}
func saveState(s State) {
	s.LastCheck = time.Now().Unix()
	b, _ := json.Marshal(s)
	tmp := statePath + ".new"
	_ = os.WriteFile(tmp, b, 0600)
	_ = os.Rename(tmp, statePath)
}

func candidateKey(c Candidate) string {
	if c.Key != "" {
		return c.Key
	}
	return fmt.Sprintf("%d:%d", c.SubscriptionID, c.TouchID)
}

func averageLatency(h HealthResult) float64 {
	var sum int64
	n := 0
	for _, p := range h.Results {
		if probeAccepted(p) {
			sum += p.MS
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return float64(sum) / float64(n)
}

func cooldownDuration(consecutive int) time.Duration {
	if consecutive < 1 {
		consecutive = 1
	}
	mins := 5 << min(consecutive-1, 3)
	if mins > 30 {
		mins = 30
	}
	return time.Duration(mins) * time.Minute
}

func markCandidateFailure(s *State, c Candidate) {
	if s.Nodes == nil {
		s.Nodes = map[string]NodeStats{}
	}
	k := candidateKey(c)
	st := s.Nodes[k]
	st.Failures++
	st.ConsecutiveFailures++
	st.LastFailure = time.Now().Unix()
	st.CooldownUntil = time.Now().Add(cooldownDuration(st.ConsecutiveFailures)).Unix()
	s.Nodes[k] = st
}

func markCandidateSuccess(s *State, c Candidate, h HealthResult) {
	if s.Nodes == nil {
		s.Nodes = map[string]NodeStats{}
	}
	k := candidateKey(c)
	st := s.Nodes[k]
	st.Successes++
	st.ConsecutiveFailures = 0
	st.LastSuccess = time.Now().Unix()
	st.CooldownUntil = 0
	lat := averageLatency(h)
	if lat > 0 {
		if st.EWMALatencyMS == 0 {
			st.EWMALatencyMS = lat
		} else {
			st.EWMALatencyMS = st.EWMALatencyMS*0.7 + lat*0.3
		}
	}
	s.Nodes[k] = st
}

func candidateScore(c Candidate, st NodeStats) float64 {
	score := float64(c.Priority)
	if st.EWMALatencyMS > 0 {
		score += st.EWMALatencyMS / 100.0
	}
	score += float64(st.ConsecutiveFailures) * 25
	bonus := st.Successes
	if bonus > 5 {
		bonus = 5
	}
	score -= float64(bonus) * 0.4
	return score
}

func rankCandidates(cs []Candidate, s State, activeID, activeSub int) ([]RankedCandidate, []RankedCandidate) {
	now := time.Now().Unix()
	ready := make([]RankedCandidate, 0, len(cs))
	cooling := make([]RankedCandidate, 0)
	for _, c := range cs {
		if c.TouchID == activeID && c.Sub == activeSub {
			continue
		}
		st := s.Nodes[candidateKey(c)]
		r := RankedCandidate{Candidate: c, Score: candidateScore(c, st), CooldownUntil: st.CooldownUntil, Cooling: st.CooldownUntil > now}
		if r.Cooling {
			cooling = append(cooling, r)
		} else {
			ready = append(ready, r)
		}
	}
	sort.SliceStable(ready, func(i, j int) bool {
		if ready[i].Score != ready[j].Score {
			return ready[i].Score < ready[j].Score
		}
		return ready[i].Priority < ready[j].Priority
	})
	sort.SliceStable(cooling, func(i, j int) bool {
		if cooling[i].CooldownUntil != cooling[j].CooldownUntil {
			return cooling[i].CooldownUntil < cooling[j].CooldownUntil
		}
		return cooling[i].Score < cooling[j].Score
	})
	return ready, cooling
}

func dashboardEventType(msg string) string {
	switch {
	case strings.Contains(msg, "health failed (1/2)"):
		// A single missed probe is not an event until confirmed.
		return ""
	case strings.HasPrefix(msg, "front "):
		return "front"
	case strings.Contains(msg, "backend listener recovered"):
		return "recovery"
	case strings.Contains(msg, "backend runtime repair failed"):
		return "backend"
	case strings.Contains(msg, "health confirmation failed"):
		return "outage"
	case strings.Contains(msg, "health failed ("),
		strings.Contains(msg, "health degraded:"):
		return "health"
	case strings.Contains(msg, "recovered on confirmation"),
		strings.Contains(msg, "health recovered:"):
		return "recovery"
	case strings.Contains(msg, "candidate unhealthy"),
		strings.Contains(msg, "active node cooldown"):
		return "health"
	case strings.Contains(msg, "switched successfully id="):
		return "switch"
	case strings.Contains(msg, "trying id="),
		strings.Contains(msg, "emergency retry cooling node"),
		strings.Contains(msg, "switch failed id="):
		return "switch_attempt"
	case strings.Contains(msg, "no healthy backend node found"),
		strings.Contains(msg, "pinned mode: backend unhealthy"):
		return "outage"
	case strings.Contains(msg, "backend listener missing"),
		strings.Contains(msg, "backend listener unavailable"):
		return "backend"
	case strings.Contains(msg, "policy runtime ->"):
		return "policy"
	default:
		return ""
	}
}

func appendDashboardEvent(msg string) {
	typ := dashboardEventType(msg)
	if typ == "" {
		return
	}
	clean := strings.NewReplacer("\t", " ", "\r", " ", "\n", " ").Replace(msg)
	line := fmt.Sprintf("%d\t%s\t%s\n", time.Now().Unix(), typ, clean)
	f, err := os.OpenFile(eventPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err == nil {
		_, _ = f.WriteString(line)
		_ = f.Close()
	}
	if st, err := os.Stat(eventPath); err == nil && st.Size() > 512*1024 {
		if b, err := os.ReadFile(eventPath); err == nil {
			lines := strings.Split(strings.TrimSpace(string(b)), "\n")
			if len(lines) > 500 {
				lines = lines[len(lines)-500:]
			}
			_ = os.WriteFile(eventPath, []byte(strings.Join(lines, "\n")+"\n"), 0600)
		}
	}
}

func logLine(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Println(msg)
	_ = exec.Command("logger", "-t", tag, msg).Run()
	appendDashboardEvent(msg)
}

func apiCall(method, path string, payload any, timeout time.Duration) (map[string]any, error) {
	return v2rayautil.CallAPI("vpn-guardian-watchdog", method, path, payload, timeout)
}
func setCandidate(c Candidate) error {
	_, err := v2rayautil.SelectCandidate(context.Background(), c)
	return err
}

func listenerReady() bool {
	conn, err := net.DialTimeout("tcp", proxyAddr, 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func ensureBackend() bool {
	if listenerReady() {
		return true
	}
	logLine("backend listener missing; attempting v2rayA runtime repair")
	ready, err := v2rayautil.RepairBackendListener(false)
	if err != nil {
		logLine("backend runtime repair failed: %v", err)
		return false
	}
	if ready {
		logLine("backend listener recovered after runtime repair")
	}
	return ready
}
func backendUnavailableHealth(reason string) HealthResult {
	result := HealthResult{
		Status:  "down",
		Healthy: false,
		Total:   len(healthTargets),
		Results: make([]ProbeResult, len(healthTargets)),
	}
	for i, target := range healthTargets {
		result.Results[i] = ProbeResult{
			Name:  target.Name,
			URL:   target.URL,
			Error: reason,
		}
	}
	return result
}

func health(timeout time.Duration) HealthResult {
	result := HealthResult{Status: "down", Total: len(healthTargets), Results: make([]ProbeResult, len(healthTargets))}

	base := &net.Dialer{Timeout: 2500 * time.Millisecond}
	socks, err := proxy.SOCKS5("tcp", proxyAddr, nil, base)
	if err != nil {
		for i, t := range healthTargets {
			result.Results[i] = ProbeResult{Name: t.Name, URL: t.URL, Error: err.Error()}
		}
		return result
	}
	tr := &http.Transport{
		DialContext:         socks.(proxy.ContextDialer).DialContext,
		TLSHandshakeTimeout: 4 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: timeout}
	var wg sync.WaitGroup
	for i, t := range healthTargets {
		i, t := i, t
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			p := ProbeResult{Name: t.Name, URL: t.URL}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			// A read-only unauthorized request avoids posting to the
			// private Codex API on every 10-second watchdog interval.
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.URL, nil)
			if err != nil {
				p.Error = err.Error()
				p.MS = time.Since(start).Milliseconds()
				result.Results[i] = p
				return
			}
			resp, err := client.Do(req)
			p.MS = time.Since(start).Milliseconds()
			if err != nil {
				p.Error = err.Error()
				result.Results[i] = p
				return
			}
			p.Code = resp.StatusCode
			_, _ = io.CopyN(io.Discard, resp.Body, 1024)
			_ = resp.Body.Close()
			result.Results[i] = p
		}()
	}
	wg.Wait()
	classifyHealth(&result)
	return result
}

func classifyHealth(result *HealthResult) {
	result.Passed = 0
	requiredOK := true
	for _, probe := range result.Results {
		accepted := probeAccepted(probe)
		if accepted {
			result.Passed++
		}
		target, ok := healthTargetByName(probe.Name)
		if ok && target.Required && !accepted {
			requiredOK = false
		}
	}

	switch {
	case !requiredOK:
		result.Status = "down"
		result.Healthy = false
	case result.Passed >= result.Total-1:
		result.Status = "healthy"
		result.Healthy = true
	case result.Passed >= result.Total-2:
		result.Status = "degraded"
		result.Healthy = false
	default:
		result.Status = "down"
		result.Healthy = false
	}
}

func healthSummary(h HealthResult) string {
	parts := []string{fmt.Sprintf("status=%s passed=%d/%d", h.Status, h.Passed, h.Total)}
	for _, p := range h.Results {
		if probeAccepted(p) {
			parts = append(parts, fmt.Sprintf("%s=%d/%dms", p.Name, p.Code, p.MS))
			continue
		}
		err := p.Error
		if len(err) > 80 {
			err = err[:80]
		}
		if err == "" {
			err = fmt.Sprintf("http=%d", p.Code)
		}
		parts = append(parts, fmt.Sprintf("%s=FAIL/%dms(%s)", p.Name, p.MS, err))
	}
	return strings.Join(parts, " ")
}

func healthNow() HealthResult { return health(5 * time.Second) }
func healthyNow() bool        { return healthNow().Healthy }
func readTrimmed(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func desiredPolicyRuntime(ctrl Control, backendHealthy bool) string {
	if ctrl.Mode == "direct" {
		return "direct"
	}
	if ctrl.FailurePolicy == "killswitch" {
		// Keep the proxy class routed only through the VPN backend even while
		// health is degraded. A dead/unhealthy backend therefore fails closed.
		return "killswitch"
	}
	if !backendHealthy {
		// Stabilize fail-open after the first observed failure. Xray's balancer
		// can provide a faster best-effort fallback, but it does not retry an
		// already selected dead outbound and can oscillate while probing.
		return "failopen-direct"
	}
	return "failopen"
}

func syncPolicyRuntime(ctrl Control, backendHealthy bool) error {
	want := desiredPolicyRuntime(ctrl, backendHealthy)
	if readTrimmed(policyRuntimePath) == want {
		return nil
	}
	if err := policy.Apply(want); err != nil {
		return fmt.Errorf("apply policy runtime %s: %w", want, err)
	}
	logLine("policy runtime -> %s", want)
	return nil
}

func findCandidate(cs []Candidate, id, sub int) (Candidate, bool) {
	for _, c := range cs {
		if c.TouchID == id && c.Sub == sub {
			return c, true
		}
	}
	return Candidate{}, false
}

// A reachable but forbidden backend must never restore proxy-class routing.
func healthForActiveCandidate(eligible bool, probe func() HealthResult) HealthResult {
	if !eligible {
		return backendUnavailableHealth("active node is not allowed by selection.allowedTransports")
	}
	return probe()
}

func run(logHealthy bool) error {
	// The daemon instance lock lives for the process, but the control lock
	// belongs only to an iteration. Never lock dashboard writes forever.
	controlLock, err := lockfile.Try(paths.ControlLock)
	if lockfile.Busy(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("lock control for watchdog: %w", err)
	}
	defer lockfile.Release(controlLock)

	s := loadState()
	s.LastCheck = time.Now().Unix()
	wasUnhealthy := s.Failures > 0 || s.LastError != ""
	ctrl := loadControl()

	if err := ensureFrontInvariant(ctrl); err != nil {
		s.LastError = "front recovery: " + err.Error()
		s.LastFailure = time.Now().Unix()
		saveState(s)
		logLine("front invariant recovery failed: %v", err)
		return err
	}

	if !listenerReady() {
		if err := syncPolicyRuntime(ctrl, false); err != nil {
			logLine("policy sync before backend recovery failed: %v", err)
		}
	}
	if !ensureBackend() {
		now := time.Now().Unix()
		s.Failures++
		s.LastCheck = now
		s.LastFailure = now
		s.LastError = "backend listener unavailable after runtime repair"
		s.LastHealth = backendUnavailableHealth(s.LastError)
		saveState(s)
		logLine("backend health -> %s", healthSummary(s.LastHealth))
		return errors.New(s.LastError)
	}

	db, err := openDB()
	if err != nil {
		return err
	}
	cs, err := candidates(db)
	if err != nil {
		db.Close()
		return err
	}
	activeID, activeSub, _ := current(db)
	db.Close()
	active, activeKnown := findCandidate(cs, activeID, activeSub)

	previousHealthStatus := s.LastHealth.Status
	h := healthForActiveCandidate(activeKnown, healthNow)
	s.LastHealth = h
	if h.Healthy {
		if err := syncPolicyRuntime(ctrl, true); err != nil {
			return err
		}
		s.Failures = 0
		s.LastHealthy = time.Now().Unix()
		s.LastError = ""
		if activeKnown {
			markCandidateSuccess(&s, active, h)
		}
		if h.Status == "degraded" && previousHealthStatus != "degraded" {
			logLine("health degraded: %s", healthSummary(h))
		} else if h.Status == "healthy" && previousHealthStatus == "degraded" {
			logLine("health recovered: %s", healthSummary(h))
		}
		saveState(s)
		if logHealthy || wasUnhealthy {
			logLine("health %s", healthSummary(h))
		}
		return nil
	}

	s.Failures++
	s.LastFailure = time.Now().Unix()
	s.LastError = "health failed"
	if !activeKnown {
		s.LastError = "active node is not allowed by selection.allowedTransports"
	}
	if err := syncPolicyRuntime(ctrl, false); err != nil {
		logLine("policy sync on health failure failed: %v", err)
	}
	saveState(s)
	logLine("health failed (%d/2): %s", s.Failures, healthSummary(h))

	// Confirm failure on the next daemon iteration, without monopolizing the
	// control lock during an eight-second sleep and an unbounded candidate scan.
	if s.Failures < 2 && activeKnown {
		return nil
	}
	if activeKnown {
		markCandidateFailure(&s, active)
		s.LastFailedNode = active.Name
		saveState(s)
	}

	if ctrl.Mode == "pinned" {
		s.Failures = 0
		s.LastError = "pinned node unhealthy; auto-switch suppressed"
		if !activeKnown {
			s.LastError = "pinned node is not allowed by selection.allowedTransports; auto-switch suppressed"
		}
		saveState(s)
		logLine("pinned mode: backend unhealthy, automatic node switch suppressed")
		return nil
	}

	ready, cooling := rankCandidates(cs, s, activeID, activeSub)
	try := func(r RankedCandidate, emergency bool) bool {
		if emergency {
			logLine("emergency retry cooling node id=%d sub=%d score=%.2f cooldownUntil=%d %s", r.TouchID, r.Sub, r.Score, r.CooldownUntil, r.Name)
		} else {
			logLine("trying id=%d sub=%d score=%.2f %s", r.TouchID, r.Sub, r.Score, r.Name)
		}
		if err := setCandidate(r.Candidate); err != nil {
			markCandidateFailure(&s, r.Candidate)
			s.LastFailedNode = r.Name
			saveState(s)
			logLine("switch failed id=%d sub=%d: %v", r.TouchID, r.Sub, err)
			return false
		}
		h := healthNow()
		s.LastHealth = h
		if !h.Healthy {
			markCandidateFailure(&s, r.Candidate)
			s.LastFailedNode = r.Name
			saveState(s)
			st := s.Nodes[candidateKey(r.Candidate)]
			logLine("candidate unhealthy id=%d sub=%d; cooldown until %d: %s", r.TouchID, r.Sub, st.CooldownUntil, healthSummary(h))
			return false
		}
		if err := syncPolicyRuntime(ctrl, true); err != nil {
			logLine("policy restore after healthy switch failed: %v", err)
			return false
		}
		markCandidateSuccess(&s, r.Candidate, h)
		s.Failures = 0
		s.LastHealthy = time.Now().Unix()
		s.LastSwitch = time.Now().Unix()
		s.LastNode = r.Name
		s.LastError = ""
		saveState(s)
		logLine("switched successfully id=%d sub=%d score=%.2f %s", r.TouchID, r.Sub, r.Score, r.Name)
		return true
	}

	// Try a bounded batch instead of waiting for two more failed daemon
	// iterations after each rejected candidate.
	batch := candidateAttemptBatch(ready)
	for _, r := range batch {
		if try(r, false) {
			return nil
		}
	}
	if len(ready) == 0 && len(cooling) > 0 {
		if try(cooling[0], true) {
			return nil
		}
	}

	// A large subscription must not spend two additional confirmations
	// between batches of already ranked, untried nodes.
	if len(batch) < len(ready) {
		s.Failures = 1
		s.LastError = "no healthy backend node found in tested batch"
		saveState(s)
		logLine("no healthy backend node found in tested batch; continuing candidate scan")
		return nil
	}
	s.Failures = 0
	s.LastError = "no healthy backend node found"
	saveState(s)
	logLine("no healthy backend node found")
	return nil
}

const maxCandidateAttemptsPerIteration = 3

func candidateAttemptBatch(ready []RankedCandidate) []RankedCandidate {
	if len(ready) > maxCandidateAttemptsPerIteration {
		return ready[:maxCandidateAttemptsPerIteration]
	}
	return ready
}

func inspect() error {
	db, err := openDB()
	if err != nil {
		return err
	}
	defer db.Close()
	cs, err := candidates(db)
	if err != nil {
		return err
	}
	activeID, activeSub, _ := current(db)
	state := loadState()
	ready, cooling := rankCandidates(cs, state, activeID, activeSub)
	out := struct {
		Control  Control           `json:"control"`
		State    State             `json:"state"`
		Listener bool              `json:"listener"`
		Active   map[string]int    `json:"active"`
		Ready    []RankedCandidate `json:"ready"`
		Cooling  []RankedCandidate `json:"cooling"`
	}{
		Control: loadControl(), State: state, Listener: listenerReady(),
		Active: map[string]int{"id": activeID, "sub": activeSub},
		Ready:  ready, Cooling: cooling,
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

// Run executes the vpn-guardian watchdog command.
func Run(args []string) {
	oldArgs := os.Args
	oldFlags := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet("vpn-guardian watchdog", flag.ExitOnError)
	os.Args = append([]string{"vpn-guardian watchdog"}, args...)
	defer func() {
		os.Args = oldArgs
		flag.CommandLine = oldFlags
	}()
	main()
}
