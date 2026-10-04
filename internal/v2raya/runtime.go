package v2raya

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	databasePath       = "/etc/v2raya/v2raya.db"
	backendSOCKSAddr   = "127.0.0.1:20173"
	backendProxyURL    = "socks5://127.0.0.1:20173"
	repairAttemptPath  = "/tmp/vpn-guardian-backend-repair-attempt"
	repairMinInterval  = time.Minute
	managerReadyWindow = 15 * time.Second
)

type RuntimeState struct {
	Transparent string `json:"transparent"`
	Running     bool   `json:"running"`
	Selected    bool   `json:"selected"`
	Manager     bool   `json:"manager"`
	Core        bool   `json:"core"`
	SOCKS       bool   `json:"socks"`
}

func BackendSOCKSReady() bool {
	conn, err := net.DialTimeout("tcp", backendSOCKSAddr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func BackendUsable() bool {
	if !BackendSOCKSReady() {
		return false
	}
	p, err := url.Parse(backendProxyURL)
	if err != nil {
		return false
	}
	tr := &http.Transport{
		Proxy:               http.ProxyURL(p),
		TLSHandshakeTimeout: 3 * time.Second,
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	for _, endpoint := range []string{"https://api.ipify.org", "https://icanhazip.com"} {
		resp, err := client.Get(endpoint)
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 256))
		_ = resp.Body.Close()
		if readErr == nil && resp.StatusCode < 500 && net.ParseIP(strings.TrimSpace(string(body))) != nil {
			return true
		}
	}
	return false
}

func InspectRuntime() (RuntimeState, error) {
	var out RuntimeState
	out.Manager = processAlive("v2raya")
	out.Core = processAlive("v2raya_core")
	out.SOCKS = BackendSOCKSReady()

	db, err := openRuntimeDB()
	if err != nil {
		return out, err
	}
	defer db.Close()

	settingRaw, err := getRuntimeRaw(db, "system:setting")
	if err != nil {
		return out, err
	}
	var setting map[string]any
	if err := json.Unmarshal([]byte(settingRaw), &setting); err != nil {
		return out, err
	}
	out.Transparent = fmt.Sprint(setting["transparent"])

	runningRaw, err := getRuntimeRaw(db, "system:running")
	if err == nil {
		out.Running = strings.EqualFold(strings.TrimSpace(runningRaw), "true")
	}

	selectedRaw, err := getRuntimeRaw(db, "outbound.proxy:connectedServers")
	if err == nil {
		var selected struct {
			Touches []json.RawMessage `json:"touches"`
		}
		if json.Unmarshal([]byte(selectedRaw), &selected) == nil {
			out.Selected = len(selected.Touches) > 0
		}
	}
	return out, nil
}

// EnsureBackendOnly makes v2rayA a backend-only SOCKS provider. It does not
// require a configured or healthy VPN node, so it is safe during first install.
func EnsureBackendOnly() error {
	if !processAlive("v2raya") {
		if err := service("start"); err != nil {
			return fmt.Errorf("start v2rayA: %w", err)
		}
	}
	if err := waitDatabase(managerReadyWindow); err != nil {
		return err
	}

	state, err := InspectRuntime()
	if err != nil {
		return err
	}
	if state.Transparent == "close" && state.Running {
		cleanupTransparentHostRules()
		return nil
	}

	if processAlive("v2raya") || processAlive("v2raya_core") {
		if err := service("stop"); err != nil {
			return err
		}
		if err := waitStopped(20 * time.Second); err != nil {
			return err
		}
	}

	db, err := openRuntimeDB()
	if err != nil {
		return err
	}
	if err = setBackendOnly(db); err == nil {
		err = putRuntimeRaw(db, "system:running", "true")
	}
	_ = db.Close()
	if err != nil {
		return err
	}

	if err := service("start"); err != nil {
		return err
	}
	if err := waitManagerState(managerReadyWindow); err != nil {
		return err
	}
	cleanupTransparentHostRules()
	return nil
}

// RepairBackendListener repairs the state where the v2rayA manager is alive
// but its core/SOCKS listener disappeared. Repeated automatic repair attempts
// are rate limited; force bypasses that cooldown for explicit operator repair.
func RepairBackendListener(force bool) (bool, error) {
	if BackendSOCKSReady() {
		return true, nil
	}

	state, err := InspectRuntime()
	if err != nil {
		return false, err
	}
	if !state.Selected {
		return false, nil
	}
	if !force && repairThrottled() {
		return false, nil
	}
	recordRepairAttempt()

	if state.Transparent != "close" || !state.Running {
		if err := EnsureBackendOnly(); err != nil {
			return false, err
		}
		state, _ = InspectRuntime()
	}

	if BackendSOCKSReady() {
		return true, nil
	}

	// Give a freshly started manager a brief chance to spawn the core before
	// deciding that the manager itself is stuck.
	graceDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(graceDeadline) {
		if BackendSOCKSReady() {
			return true, nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	state, _ = InspectRuntime()

	// system:running=true with no core means the manager got stuck after the
	// core exited. Restart only in that state; a live core without a listener
	// may simply have no usable outbound.
	if !state.Core {
		if err := service("restart"); err != nil {
			return false, err
		}
	}

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if BackendSOCKSReady() {
			return true, nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false, nil
}

func setBackendOnly(db *sql.DB) error {
	raw, err := getRuntimeRaw(db, "system:setting")
	if err != nil {
		return err
	}
	var setting map[string]any
	if err := json.Unmarshal([]byte(raw), &setting); err != nil {
		return err
	}
	setting["transparent"] = "close"
	setting["transparentType"] = "tproxy"
	b, err := json.Marshal(setting)
	if err != nil {
		return err
	}
	return putRuntimeRaw(db, "system:setting", string(b))
}

func cleanupTransparentHostRules() {
	for i := 0; i < 4; i++ {
		_ = exec.Command("ip", "rule", "del", "fwmark", "0x40/0xc0", "table", "100").Run()
		_ = exec.Command("ip", "-6", "rule", "del", "fwmark", "0x40/0xc0", "table", "100").Run()
	}
	_ = exec.Command("ip", "route", "flush", "table", "100").Run()
	_ = exec.Command("ip", "-6", "route", "flush", "table", "100").Run()
	_ = exec.Command("nft", "delete", "table", "inet", "v2raya").Run()
}

func openRuntimeDB() (*sql.DB, error) {
	return sql.Open("sqlite", "file:"+databasePath+"?_pragma=busy_timeout(5000)")
}

func getRuntimeRaw(db *sql.DB, key string) (string, error) {
	var value string
	err := db.QueryRow("SELECT value FROM system_config WHERE key=?", key).Scan(&value)
	return value, err
}

func putRuntimeRaw(db *sql.DB, key, value string) error {
	_, err := db.Exec("INSERT OR REPLACE INTO system_config(key,value) VALUES(?,?)", key, value)
	return err
}

func service(action string) error {
	out, err := exec.Command("/etc/init.d/v2raya", action).CombinedOutput()
	if err != nil {
		return fmt.Errorf("v2raya %s: %w: %s", action, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func processAlive(name string) bool {
	return exec.Command("pidof", name).Run() == nil
}

func waitStopped(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !processAlive("v2raya") && !processAlive("v2raya_core") {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("v2rayA processes did not stop")
}

func waitDatabase(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		db, err := openRuntimeDB()
		if err == nil {
			_, queryErr := getRuntimeRaw(db, "system:setting")
			_ = db.Close()
			if queryErr == nil {
				return nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("v2rayA database did not become ready")
}

func waitManagerState(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if processAlive("v2raya") {
			state, err := InspectRuntime()
			if err == nil && state.Transparent == "close" && state.Running {
				return nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("v2rayA did not enter backend-only running state")
}

func repairThrottled() bool {
	b, err := os.ReadFile(repairAttemptPath)
	if err != nil {
		return false
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return false
	}
	return time.Since(time.Unix(ts, 0)) < repairMinInterval
}

func recordRepairAttempt() {
	_ = os.WriteFile(repairAttemptPath, []byte(strconv.FormatInt(time.Now().Unix(), 10)+"\n"), 0600)
}
