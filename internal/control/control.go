package control

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/policy"
	v2rayautil "github.com/Yakwilik/openwrt-vpn-guardian/internal/v2raya"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

const dbPath = "/etc/v2raya/v2raya.db"
const statePath = "/tmp/vpn-guardian-control-state.json"
const controlPath = "/etc/vpn-stack/control.json"
const proxyURL = "socks5://127.0.0.1:20173"

type Candidate struct {
	TouchID, Sub, SubscriptionID, Priority, Sort int
	Name, Protocol, Network, Security, Address   string
}
type State struct {
	Failures           int
	FallbackDirect     bool
	DesiredTransparent string
	LastSwitch         int64
	LastNode           string
	LastFailedNode     string
	LastFailedAt       int64
	ScanOffset         int
}

type Control struct {
	Mode              string `json:"mode"`
	PinName           string `json:"pinName,omitempty"`
	PinProtocol       string `json:"pinProtocol,omitempty"`
	PinNetwork        string `json:"pinNetwork,omitempty"`
	PinSecurity       string `json:"pinSecurity,omitempty"`
	PinSubscriptionID int    `json:"pinSubscriptionId,omitempty"`
	FailurePolicy     string `json:"failurePolicy"`
	UpdatedAt         int64  `json:"updatedAt"`
}

func main() {
	mode := flag.String("mode", "run", "run|inspect|set-name|set-id|auto|direct|pin|control-json|api-touch|latency-json|sub-add|sub-update|sub-edit|sub-delete|killswitch-on|killswitch-off|set-touch")
	name := flag.String("name", "", "node name substring")
	id := flag.Int("id", 0, "1-based subscription node id or subscription id")
	sub := flag.Int("sub", 0, "0-based subscription index for node")
	address := flag.String("address", "", "subscription URL")
	remarks := flag.String("remarks", "", "subscription remarks")
	autoSelect := flag.Bool("auto-select", false, "subscription auto-select")
	flag.Parse()
	var err error
	switch *mode {
	case "run":
		err = run()
	case "inspect":
		err = inspect()
	case "set-name":
		if *name == "" {
			log.Fatal("-name required")
		}
		err = setByName(*name)
	case "set-id":
		if *id <= 0 {
			log.Fatal("-id required")
		}
		err = setByTouch(*id, *sub)
	case "set-touch":
		if *id <= 0 {
			log.Fatal("-id required")
		}
		err = setTouchRaw(*id, *sub)
	case "auto":
		err = setControlAuto()
	case "direct":
		err = setControlDirect()
	case "pin":
		if *id <= 0 {
			log.Fatal("-id required")
		}
		err = setControlPin(*id, *sub)
	case "control-json":
		b, _ := json.Marshal(loadControl())
		fmt.Println(string(b))
	case "api-touch":
		var out any
		out, err = apiCall(http.MethodGet, "touch", nil, 10*time.Second)
		if err == nil {
			b, _ := json.Marshal(out)
			fmt.Println(string(b))
		}
	case "sub-add":
		if *address == "" {
			log.Fatal("-address required")
		}
		_, err = apiCall(http.MethodPost, "import", map[string]any{"url": *address, "kind": "subscription"}, 120*time.Second)
	case "latency-json":
		var out any
		out, err = latencyAll()
		if err == nil {
			b, _ := json.Marshal(out)
			fmt.Println(string(b))
		}
	case "sub-update":
		if *id <= 0 {
			log.Fatal("-id required")
		}
		_, err = apiCall(http.MethodPut, "subscription", map[string]any{"_type": "subscription", "id": *id}, 120*time.Second)
	case "sub-edit":
		if *id <= 0 || *address == "" {
			log.Fatal("-id and -address required")
		}
		err = editSubscription(*id, *address, *remarks, *autoSelect)
	case "sub-delete":
		if *id <= 0 {
			log.Fatal("-id required")
		}
		_, err = apiCall(http.MethodDelete, "touch", map[string]any{"touches": []any{map[string]any{"_type": "subscription", "id": *id}}}, 30*time.Second)
	case "killswitch-on":
		err = setFailurePolicy("killswitch")
	case "killswitch-off":
		err = setFailurePolicy("failopen")
	default:
		log.Fatalf("unknown mode %s", *mode)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func openDB() (*sql.DB, error) {
	return sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)")
}
func getRaw(db *sql.DB, key string) (string, error) {
	var v string
	err := db.QueryRow("SELECT value FROM system_config WHERE key=?", key).Scan(&v)
	return v, err
}
func putRaw(db *sql.DB, key, value string) error {
	_, err := db.Exec("INSERT OR REPLACE INTO system_config(key,value) VALUES(?,?)", key, value)
	return err
}

func str(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			return fmt.Sprint(v)
		}
	}
	return ""
}

func candidates(db *sql.DB) ([]Candidate, error) {
	sr, err := db.Query("SELECT id FROM subscriptions ORDER BY sort,id")
	if err != nil {
		return nil, err
	}
	subOrd := map[int]int{}
	n := 0
	for sr.Next() {
		var id int
		if err := sr.Scan(&id); err != nil {
			sr.Close()
			return nil, err
		}
		subOrd[id] = n
		n++
	}
	sr.Close()
	rows, err := db.Query("SELECT sub_id,sort,config_json FROM servers WHERE type='subscription_server' ORDER BY sub_id,sort,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Candidate
	for rows.Next() {
		var subID sql.NullInt64
		var s int
		var raw string
		if err := rows.Scan(&subID, &s, &raw); err != nil {
			return nil, err
		}
		var root map[string]any
		if json.Unmarshal([]byte(raw), &root) != nil {
			continue
		}
		obj := root
		if x, ok := root["serverObj"].(map[string]any); ok {
			obj = x
		}
		proto := strings.ToLower(str(obj, "protocol"))
		network := strings.ToLower(str(obj, "net", "network"))
		security := strings.ToLower(str(obj, "tls", "security"))
		name := str(obj, "ps", "name", "remarks")
		host := str(obj, "add", "address", "host")
		port := str(obj, "port")
		address := host
		if host != "" && port != "" {
			address = host + ":" + port
		}
		pri, eligible := v2rayautil.CandidatePriority(proto, network, security, s)
		if !eligible {
			continue
		}
		sub := 0
		actualSubID := 0
		if subID.Valid {
			actualSubID = int(subID.Int64)
			sub = subOrd[actualSubID]
		}
		out = append(out, Candidate{TouchID: s + 1, Sub: sub, SubscriptionID: actualSubID, Priority: pri, Sort: s, Name: name, Protocol: proto, Network: network, Security: security, Address: address})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].Sort < out[j].Sort
	})
	return out, rows.Err()
}

func current(db *sql.DB) (id, sub int, ok bool) {
	raw, err := getRaw(db, "outbound.proxy:connectedServers")
	if err != nil {
		return
	}
	var x map[string]any
	if json.Unmarshal([]byte(raw), &x) != nil {
		return
	}
	arr, yes := x["touches"].([]any)
	if !yes || len(arr) == 0 {
		return
	}
	m, yes := arr[0].(map[string]any)
	if !yes {
		return
	}
	id = int(m["id"].(float64))
	if v, yes := m["sub"].(float64); yes {
		sub = int(v)
	}
	ok = true
	return
}

func setConnected(db *sql.DB, c Candidate) error {
	x := map[string]any{"touches": []any{map[string]any{"_type": "subscriptionServer", "id": c.TouchID, "sub": c.Sub, "outbound": "proxy"}}}
	b, _ := json.Marshal(x)
	if err := putRaw(db, "outbound.proxy:connectedServers", string(b)); err != nil {
		return err
	}
	if raw, err := getRaw(db, "outbound.proxy:setting"); err == nil {
		var m map[string]any
		if json.Unmarshal([]byte(raw), &m) == nil {
			delete(m, "selected")
			nb, _ := json.Marshal(m)
			_ = putRaw(db, "outbound.proxy:setting", string(nb))
		}
	}
	return nil
}

func signLocalJWT(db *sql.DB) (string, error) {
	raw, err := getRaw(db, "system:jwtSecret")
	if err != nil {
		return "", fmt.Errorf("read local JWT secret: %w", err)
	}
	var secretHex string
	if err := json.Unmarshal([]byte(raw), &secretHex); err != nil {
		return "", fmt.Errorf("decode local JWT secret: %w", err)
	}
	secret, err := hex.DecodeString(secretHex)
	if err != nil || len(secret) == 0 {
		return "", fmt.Errorf("invalid local JWT secret")
	}

	headerJSON := "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
	header := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	payloadBytes, _ := json.Marshal(map[string]any{
		"uname": "vpn-guardian",
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
	})
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	unsigned := header + "." + payload
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(unsigned))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return unsigned + "." + sig, nil
}

func apiCall(method, path string, payload any, timeout time.Duration) (any, error) {
	db, err := openDB()
	if err != nil {
		return nil, err
	}
	token, err := signLocalJWT(db)
	db.Close()
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://127.0.0.1:2017/api/"+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("v2rayA API %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var env map[string]any
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, fmt.Errorf("v2rayA API %s returned invalid JSON: HTTP %d", path, resp.StatusCode)
	}
	if resp.StatusCode >= 400 || fmt.Sprint(env["code"]) != "SUCCESS" {
		return nil, fmt.Errorf("v2rayA API %s failed: HTTP %d code=%v error=%v message=%v", path, resp.StatusCode, env["code"], env["errorCode"], env["message"])
	}
	return env["data"], nil
}

func touchData() (map[string]any, error) {
	d, err := apiCall(http.MethodGet, "touch", nil, 10*time.Second)
	if err != nil {
		return nil, err
	}
	m, ok := d.(map[string]any)
	if !ok {
		return nil, errors.New("unexpected touch response")
	}
	return m, nil
}
func editSubscription(id int, address, remarks string, autoSelect bool) error {
	d, err := touchData()
	if err != nil {
		return err
	}
	t, ok := d["touch"].(map[string]any)
	if !ok {
		return errors.New("touch missing")
	}
	arr, ok := t["subscriptions"].([]any)
	if !ok {
		return errors.New("subscriptions missing")
	}
	for _, v := range arr {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		n, ok := m["id"].(float64)
		if !ok || int(n) != id {
			continue
		}
		m["address"] = address
		m["remarks"] = remarks
		m["autoSelect"] = autoSelect
		m["servers"] = []any{}
		_, err = apiCall(http.MethodPatch, "subscription", map[string]any{"subscription": m}, 30*time.Second)
		return err
	}
	return fmt.Errorf("subscription %d not found", id)
}
func latencyAll() (any, error) {
	d, err := touchData()
	if err != nil {
		return nil, err
	}
	t, ok := d["touch"].(map[string]any)
	if !ok {
		return nil, errors.New("touch missing")
	}
	subs, ok := t["subscriptions"].([]any)
	if !ok {
		return nil, errors.New("subscriptions missing")
	}
	var whiches []any
	for si, sv := range subs {
		sm, ok := sv.(map[string]any)
		if !ok {
			continue
		}
		servers, _ := sm["servers"].([]any)
		for _, vv := range servers {
			vm, ok := vv.(map[string]any)
			if !ok {
				continue
			}
			id, ok := vm["id"].(float64)
			if !ok {
				continue
			}
			whiches = append(whiches, map[string]any{"_type": "subscriptionServer", "id": int(id), "sub": si})
		}
	}
	b, _ := json.Marshal(whiches)
	return apiCall(http.MethodGet, "pingLatency?whiches="+url.QueryEscape(string(b)), nil, 45*time.Second)
}

func loadControl() Control {
	c := Control{Mode: "auto", FailurePolicy: "killswitch"}
	if b, err := os.ReadFile(controlPath); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	if c.Mode != "auto" && c.Mode != "pinned" && c.Mode != "direct" {
		c.Mode = "auto"
	}
	if c.FailurePolicy != "killswitch" && c.FailurePolicy != "failopen" {
		c.FailurePolicy = "killswitch"
	}
	return c
}
func saveControl(c Control) error {
	c.UpdatedAt = time.Now().Unix()
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tmp := controlPath + ".new"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, controlPath)
}
func candidateByTouch(id, sub int) (Candidate, error) {
	db, err := openDB()
	if err != nil {
		return Candidate{}, err
	}
	defer db.Close()
	cs, err := candidates(db)
	if err != nil {
		return Candidate{}, err
	}
	for _, c := range cs {
		if c.TouchID == id && c.Sub == sub {
			return c, nil
		}
	}
	return Candidate{}, fmt.Errorf("node id=%d sub=%d not found", id, sub)
}
func candidateForControl(ctrl Control) (Candidate, error) {
	db, err := openDB()
	if err != nil {
		return Candidate{}, err
	}
	defer db.Close()
	cs, err := candidates(db)
	if err != nil {
		return Candidate{}, err
	}
	for _, c := range cs {
		if (ctrl.PinSubscriptionID == 0 || c.SubscriptionID == ctrl.PinSubscriptionID) && c.Name == ctrl.PinName && c.Protocol == ctrl.PinProtocol && c.Network == ctrl.PinNetwork && c.Security == ctrl.PinSecurity {
			return c, nil
		}
	}
	return Candidate{}, fmt.Errorf("pinned node no longer exists: %s", ctrl.PinName)
}
func setTouchRaw(id, sub int) error {
	body := map[string]any{"outbound": "proxy", "touches": []any{map[string]any{"_type": "subscriptionServer", "id": id, "sub": sub, "outbound": "proxy"}}}
	if _, err := apiCall(http.MethodPut, "outboundConnections", body, 10*time.Second); err != nil {
		return err
	}
	if err := waitReady(8 * time.Second); err != nil {
		return err
	}
	db, err := openDB()
	if err != nil {
		return err
	}
	defer db.Close()
	aid, asub, ok := current(db)
	if !ok || aid != id || asub != sub {
		return fmt.Errorf("v2rayA selected id=%d sub=%d, expected id=%d sub=%d", aid, asub, id, sub)
	}
	return nil
}

func setByTouch(id, sub int) error {
	c, err := candidateByTouch(id, sub)
	if err != nil {
		return err
	}
	if err = setOne(c); err == nil {
		fmt.Println("selected", c.Name)
	}
	return err
}
func setControlDirect() error {
	hardKillSwitchOff()
	ctrl := loadControl()
	ctrl.Mode = "direct"
	ctrl.PinName = ""
	ctrl.PinProtocol = ""
	ctrl.PinNetwork = ""
	ctrl.PinSecurity = ""
	ctrl.PinSubscriptionID = 0
	if err := saveControl(ctrl); err != nil {
		return err
	}
	s := loadState()
	s.FallbackDirect = false
	s.Failures = 0
	s.DesiredTransparent = "pac"
	saveState(s)
	db, err := openDB()
	if err != nil {
		return err
	}
	mode, _ := transparent(db)
	db.Close()
	if mode != "close" {
		return changeTransparent("close")
	}
	return nil
}
func setControlAuto() error {
	ctrl := loadControl()
	ctrl.Mode = "auto"
	ctrl.PinName = ""
	ctrl.PinProtocol = ""
	ctrl.PinNetwork = ""
	ctrl.PinSecurity = ""
	ctrl.PinSubscriptionID = 0
	if err := saveControl(ctrl); err != nil {
		return err
	}
	s := loadState()
	s.FallbackDirect = false
	s.Failures = 0
	s.DesiredTransparent = "pac"
	saveState(s)
	db, err := openDB()
	if err != nil {
		return err
	}
	mode, _ := transparent(db)
	db.Close()
	if mode == "close" {
		if err := changeTransparent("pac"); err != nil {
			return err
		}
	}
	if ctrl.FailurePolicy == "killswitch" && hostPathReady() {
		hardKillSwitchOff()
	}
	return run()
}
func setControlPin(id, sub int) error {
	c, err := candidateByTouch(id, sub)
	if err != nil {
		return err
	}
	if err := setOne(c); err != nil {
		return err
	}
	ctrl := loadControl()
	ctrl.Mode = "pinned"
	ctrl.PinName = c.Name
	ctrl.PinProtocol = c.Protocol
	ctrl.PinNetwork = c.Network
	ctrl.PinSecurity = c.Security
	ctrl.PinSubscriptionID = c.SubscriptionID
	if err := saveControl(ctrl); err != nil {
		return err
	}
	s := loadState()
	s.FallbackDirect = false
	s.Failures = 0
	s.DesiredTransparent = "pac"
	s.LastNode = c.Name
	saveState(s)
	db, err := openDB()
	if err != nil {
		return err
	}
	mode, _ := transparent(db)
	db.Close()
	if mode == "close" {
		if err := changeTransparent("pac"); err != nil {
			return err
		}
	}
	if ctrl.FailurePolicy == "killswitch" && hostPathReady() {
		hardKillSwitchOff()
	}
	fmt.Println("pinned", c.Name)
	return nil
}

func setFailurePolicy(policy string) error {
	if policy != "killswitch" && policy != "failopen" {
		return fmt.Errorf("invalid failure policy %q", policy)
	}
	ctrl := loadControl()
	ctrl.FailurePolicy = policy
	if err := saveControl(ctrl); err != nil {
		return err
	}
	if ctrl.Mode == "direct" {
		hardKillSwitchOff()
		return nil
	}
	if policy == "killswitch" {
		s := loadState()
		s.FallbackDirect = false
		s.DesiredTransparent = "pac"
		saveState(s)
		db, err := openDB()
		if err != nil {
			return err
		}
		mode, _ := transparent(db)
		db.Close()
		if mode == "close" {
			if err := changeTransparent("pac"); err != nil {
				_ = hardKillSwitchOn()
				return err
			}
		}
		if hostPathReady() {
			hardKillSwitchOff()
			return nil
		}
		return hardKillSwitchOn()
	}
	hardKillSwitchOff()
	return nil
}

func killSwitch(ctrl Control) bool { return ctrl.FailurePolicy == "killswitch" }

func hardKillSwitchOn() error    { return nil }
func hardKillSwitchOff()         {}
func hardKillSwitchActive() bool { return false }

func runPinned(ctrl Control, s State) error {
	pin, err := candidateForControl(ctrl)
	if err != nil {
		return err
	}
	db, err := openDB()
	if err != nil {
		return err
	}
	cur, ok, curErr := currentCandidate(db)
	mode, _ := transparent(db)
	db.Close()
	if curErr != nil {
		return curErr
	}
	if !ok || cur.Name != pin.Name || cur.Protocol != pin.Protocol || cur.Network != pin.Network || cur.Security != pin.Security {
		if err := setOne(pin); err != nil {
			return err
		}
		mode = "pac"
	}
	if mode == "close" || s.FallbackDirect {
		if health(4*time.Second, true) {
			note("pinned node %s recovered; restoring transparent mode pac", pin.Name)
			if err := changeTransparent("pac"); err != nil {
				return err
			}
			s.FallbackDirect = false
			s.Failures = 0
			s.DesiredTransparent = "pac"
			s.LastNode = pin.Name
			s.LastSwitch = time.Now().Unix()
			saveState(s)
			return nil
		}
		s.Failures++
		s.FallbackDirect = true
		s.LastFailedNode = pin.Name
		s.LastFailedAt = time.Now().Unix()
		saveState(s)
		return nil
	}
	if err := repairHostPath(); err != nil {
		s.Failures++
		saveState(s)
		if killSwitch(ctrl) {
			_ = hardKillSwitchOn()
			note("TPROXY unavailable; hard kill switch enabled")
		}
		if s.Failures < 2 {
			return nil
		}
	} else if killSwitch(ctrl) {
		hardKillSwitchOff()
	}
	if health(5*time.Second, false) {
		if killSwitch(ctrl) {
			hardKillSwitchOff()
		}
		s.Failures = 0
		s.FallbackDirect = false
		s.LastNode = pin.Name
		saveState(s)
		return nil
	}
	s.Failures++
	note("pinned node health check failed (%d/2): %s", s.Failures, pin.Name)
	saveState(s)
	if s.Failures < 2 {
		time.Sleep(8 * time.Second)
		if health(4*time.Second, false) {
			s.Failures = 0
			saveState(s)
			return nil
		}
		s.Failures++
	}
	s.LastFailedNode = pin.Name
	s.LastFailedAt = time.Now().Unix()
	s.Failures = 0
	if killSwitch(ctrl) {
		note("pinned node %s unavailable; kill switch active, protected traffic remains blocked", pin.Name)
		s.FallbackDirect = false
		saveState(s)
		return nil
	}
	note("pinned node %s unavailable; fail-open to direct without switching", pin.Name)
	if err := changeTransparent("close"); err != nil {
		return err
	}
	s.FallbackDirect = true
	saveState(s)
	return nil
}

func resolveCandidateFresh(db *sql.DB, want Candidate) (Candidate, error) {
	cs, err := candidates(db)
	if err != nil {
		return Candidate{}, err
	}
	for _, c := range cs {
		if (want.SubscriptionID == 0 || c.SubscriptionID == want.SubscriptionID) &&
			c.Name == want.Name &&
			c.Protocol == want.Protocol &&
			c.Network == want.Network &&
			c.Security == want.Security {
			return c, nil
		}
	}
	return Candidate{}, fmt.Errorf("candidate disappeared after subscription refresh: %s (%s)", want.Name, want.Protocol)
}

func currentCandidate(db *sql.DB) (Candidate, bool, error) {
	id, sub, ok := current(db)
	if !ok {
		return Candidate{}, false, nil
	}
	cs, err := candidates(db)
	if err != nil {
		return Candidate{}, false, err
	}
	for _, c := range cs {
		if c.TouchID == id && c.Sub == sub {
			return c, true, nil
		}
	}
	return Candidate{}, false, nil
}

func apiSetOne(want Candidate) error {
	db, err := openDB()
	if err != nil {
		return err
	}
	fresh, err := resolveCandidateFresh(db, want)
	if err != nil {
		db.Close()
		return err
	}
	token, err := signLocalJWT(db)
	db.Close()
	if err != nil {
		return err
	}

	body := map[string]any{
		"outbound": "proxy",
		"touches": []any{
			map[string]any{
				"_type":    "subscriptionServer",
				"id":       fresh.TouchID,
				"sub":      fresh.Sub,
				"outbound": "proxy",
			},
		},
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPut, "http://127.0.0.1:2017/api/outboundConnections", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("v2rayA API switch: %w", err)
	}
	defer resp.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var envelope map[string]any
	if err := json.Unmarshal(responseBody, &envelope); err != nil {
		return fmt.Errorf("v2rayA API switch returned invalid JSON: HTTP %d", resp.StatusCode)
	}
	code := fmt.Sprint(envelope["code"])
	if resp.StatusCode >= 400 || code != "SUCCESS" {
		return fmt.Errorf("v2rayA API switch failed: HTTP %d code=%s error=%v message=%v",
			resp.StatusCode, code, envelope["errorCode"], envelope["message"])
	}
	if err := waitReady(6 * time.Second); err != nil {
		return err
	}

	db, err = openDB()
	if err != nil {
		return err
	}
	actual, ok, checkErr := currentCandidate(db)
	db.Close()
	if checkErr != nil {
		return checkErr
	}
	if !ok {
		return fmt.Errorf("v2rayA API switch completed but no active proxy node is recorded")
	}
	if actual.Name != fresh.Name || actual.Protocol != fresh.Protocol {
		return fmt.Errorf("v2rayA selected %s (%s), expected %s (%s)",
			actual.Name, actual.Protocol, fresh.Name, fresh.Protocol)
	}
	return nil
}

func transparent(db *sql.DB) (string, error) {
	raw, err := getRaw(db, "system:setting")
	if err != nil {
		return "", err
	}
	var m map[string]any
	if err = json.Unmarshal([]byte(raw), &m); err != nil {
		return "", err
	}
	return fmt.Sprint(m["transparent"]), nil
}
func setTransparent(db *sql.DB, mode string) error {
	raw, err := getRaw(db, "system:setting")
	if err != nil {
		return err
	}
	var m map[string]any
	if err = json.Unmarshal([]byte(raw), &m); err != nil {
		return err
	}
	m["transparent"] = mode
	b, _ := json.Marshal(m)
	return putRaw(db, "system:setting", string(b))
}

func enforceTproxy(db *sql.DB) error {
	raw, err := getRaw(db, "system:setting")
	if err != nil {
		return err
	}
	var m map[string]any
	if err = json.Unmarshal([]byte(raw), &m); err != nil {
		return err
	}
	m["transparentType"] = "tproxy"
	b, _ := json.Marshal(m)
	return putRaw(db, "system:setting", string(b))
}

func tproxyReady() bool {
	rules, _ := exec.Command("ip", "rule", "show").CombinedOutput()
	rt := string(rules)
	return strings.Contains(rt, "fwmark 0x40/0xc0") &&
		strings.Contains(rt, "lookup 100")
}
func preferredTransportConfigured() bool {
	db, err := openDB()
	if err != nil {
		return false
	}
	defer db.Close()
	raw, err := getRaw(db, "system:setting")
	if err != nil {
		return false
	}
	var m map[string]any
	if json.Unmarshal([]byte(raw), &m) != nil {
		return false
	}
	return fmt.Sprint(m["transparentType"]) == "tproxy"
}
func service(action string) error {
	cmd := exec.Command("/etc/init.d/v2raya", action)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", action, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func processAlive(name string) bool {
	return exec.Command("pidof", name).Run() == nil
}

func waitStopped(max time.Duration) error {
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if !processAlive("v2raya") && !processAlive("v2raya_core") {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("v2rayA/core did not stop within %s", max)
}

func waitReady(max time.Duration) error {
	deadline := time.Now().Add(max)
	var last string
	for time.Now().Before(deadline) {
		if !processAlive("v2raya_core") {
			last = "core process not running"
			time.Sleep(250 * time.Millisecond)
			continue
		}

		db, err := openDB()
		if err != nil {
			last = "database unavailable: " + err.Error()
			time.Sleep(250 * time.Millisecond)
			continue
		}

		var pending int
		err = db.QueryRow("SELECT COUNT(*) FROM system_config WHERE key='system:hostState'").Scan(&pending)
		mode, modeErr := transparent(db)
		var rawSetting string
		settingErr := db.QueryRow("SELECT value FROM system_config WHERE key='system:setting'").Scan(&rawSetting)
		db.Close()
		if err != nil || modeErr != nil || settingErr != nil {
			last = "database startup state incomplete"
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if pending != 0 {
			last = "transparent host setup still pending"
			time.Sleep(250 * time.Millisecond)
			continue
		}

		var setting map[string]any
		if json.Unmarshal([]byte(rawSetting), &setting) != nil {
			last = "cannot parse system setting"
			time.Sleep(250 * time.Millisecond)
			continue
		}
		typeName := fmt.Sprint(setting["transparentType"])

		conn, err := net.DialTimeout("tcp", "127.0.0.1:20173", 350*time.Millisecond)
		if err != nil {
			last = "local proxy not listening"
			time.Sleep(250 * time.Millisecond)
			continue
		}
		_ = conn.Close()

		if mode == "close" {
			return nil
		}

		if typeName != "tproxy" {
			last = "unexpected transparent implementation: " + typeName
			time.Sleep(250 * time.Millisecond)
			continue
		}
		out, _ := exec.Command("ip", "rule", "show").CombinedOutput()
		text := string(out)
		if !strings.Contains(text, "fwmark 0x40/0xc0") || !strings.Contains(text, "lookup 100") {
			last = "TPROXY policy rule not installed"
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if exec.Command("nft", "list", "table", "inet", "v2raya").Run() != nil {
			last = "TPROXY nft table not installed"
			time.Sleep(250 * time.Millisecond)
			continue
		}
		out, _ = exec.Command("ip", "route", "show", "table", "100").CombinedOutput()
		if !strings.Contains(string(out), "local default dev lo") {
			last = "TPROXY route table 100 not installed"
			time.Sleep(250 * time.Millisecond)
			continue
		}
		return nil
	}
	if last == "" {
		last = "unknown startup state"
	}
	return fmt.Errorf("v2rayA/core did not become ready within %s: %s", max, last)
}

func hostPathReady() bool {
	db, err := openDB()
	if err != nil {
		return false
	}
	mode, modeErr := transparent(db)
	var raw string
	settingErr := db.QueryRow("SELECT value FROM system_config WHERE key='system:setting'").Scan(&raw)
	db.Close()
	if modeErr != nil || settingErr != nil {
		return false
	}
	if mode == "close" {
		return true
	}
	var setting map[string]any
	if json.Unmarshal([]byte(raw), &setting) != nil {
		return false
	}
	if fmt.Sprint(setting["transparentType"]) != "tproxy" {
		return false
	}
	if !tproxyReady() {
		return false
	}
	if exec.Command("nft", "list", "table", "inet", "v2raya").Run() != nil {
		return false
	}
	out, _ := exec.Command("ip", "route", "show", "table", "100").CombinedOutput()
	return strings.Contains(string(out), "local default dev lo")
}
func repairHostPath() error {
	if hostPathReady() {
		return nil
	}
	note("transparent host path missing; rebuilding TPROXY through v2rayA lifecycle")
	return mutate(func(db *sql.DB) error { return enforceTproxy(db) })
}
func health(timeout time.Duration, viaProxy bool) bool {
	if !viaProxy && !hostPathReady() {
		return false
	}
	d := &net.Dialer{Timeout: 3 * time.Second}
	tr := &http.Transport{
		DialContext:         d.DialContext,
		TLSHandshakeTimeout: 4 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	if viaProxy {
		p, _ := url.Parse(proxyURL)
		tr.Proxy = http.ProxyURL(p)
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Timeout: timeout, Transport: tr}
	urls := []string{
		"https://connectivitycheck.gstatic.com/generate_204",
		"https://github.com/",
		"https://www.youtube.com/generate_204",
		"https://web.telegram.org/",
		"https://api.openai.com/v1/models",
	}
	results := make(chan bool, len(urls))
	for _, u := range urls {
		go func(u string) {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			resp, err := client.Do(req)
			if err != nil {
				results <- false
				return
			}
			_, _ = io.CopyN(io.Discard, resp.Body, 1024)
			_ = resp.Body.Close()
			results <- resp.StatusCode > 0 && resp.StatusCode < 500
		}(u)
	}
	ok := 0
	for range urls {
		if <-results {
			ok++
		}
	}
	return ok >= 4
}

func waitHealthy(max time.Duration, viaProxy bool) bool {
	end := time.Now().Add(max)
	for time.Now().Before(end) {
		if health(1500*time.Millisecond, viaProxy) {
			return true
		}
		if time.Until(end) < 200*time.Millisecond {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}
func loadState() State {
	var s State
	if b, err := os.ReadFile(statePath); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	if s.DesiredTransparent == "" {
		s.DesiredTransparent = "pac"
	}
	return s
}
func saveState(s State) { b, _ := json.Marshal(s); _ = os.WriteFile(statePath, b, 0600) }
func note(f string, a ...any) {
	msg := fmt.Sprintf(f, a...)
	log.Print(msg)
	_ = exec.Command("logger", "-t", "vpn-guardian-control", msg).Run()
}

func syncTproxyHostRules() error {
	db, err := openDB()
	if err != nil {
		return err
	}
	mode, modeErr := transparent(db)
	db.Close()
	if modeErr != nil {
		return modeErr
	}

	cleanup := func() {
		for i := 0; i < 4; i++ {
			_ = exec.Command("ip", "rule", "del", "fwmark", "0x40/0xc0", "table", "100").Run()
			_ = exec.Command("ip", "-6", "rule", "del", "fwmark", "0x40/0xc0", "table", "100").Run()
		}
		_ = exec.Command("ip", "route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", "100").Run()
		_ = exec.Command("ip", "-6", "route", "del", "local", "::/0", "dev", "lo", "table", "100").Run()
		_ = exec.Command("nft", "delete", "table", "inet", "v2raya").Run()
	}

	if mode == "close" {
		cleanup()
		return nil
	}

	deadline := time.Now().Add(6 * time.Second)
	for {
		if processAlive("v2raya_core") {
			if _, err := os.Stat("/etc/v2raya/v2raya.nft"); err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("v2raya core/nft config did not become ready")
		}
		time.Sleep(200 * time.Millisecond)
	}

	cleanup()

	if out, err := exec.Command("ip", "rule", "add", "fwmark", "0x40/0xc0", "table", "100").CombinedOutput(); err != nil {
		cleanup()
		return fmt.Errorf("add IPv4 TPROXY rule: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "100").CombinedOutput(); err != nil {
		cleanup()
		return fmt.Errorf("add IPv4 TPROXY route: %w: %s", err, strings.TrimSpace(string(out)))
	}

	// IPv6 is optional: configure it when the kernel accepts the commands.
	if exec.Command("ip", "-6", "rule", "add", "fwmark", "0x40/0xc0", "table", "100").Run() == nil {
		_ = exec.Command("ip", "-6", "route", "add", "local", "::/0", "dev", "lo", "table", "100").Run()
	}

	out, err := exec.Command("nft", "-f", "/etc/v2raya/v2raya.nft").CombinedOutput()
	if err != nil {
		cleanup()
		return fmt.Errorf("load /etc/v2raya/v2raya.nft: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func mutate(fn func(*sql.DB) error) error {
	if err := service("stop"); err != nil {
		return err
	}
	if err := waitStopped(20 * time.Second); err != nil {
		_ = service("start")
		return err
	}
	db, err := openDB()
	if err != nil {
		_ = service("start")
		return err
	}
	err = fn(db)
	if err == nil {
		err = enforceTproxy(db)
	}
	if err == nil {
		err = putRaw(db, "system:running", "true")
	}
	db.Close()
	if err != nil {
		_ = service("start")
		return err
	}
	if err = service("start"); err != nil {
		return err
	}
	if err = syncTproxyHostRules(); err != nil {
		return err
	}
	return waitReady(20 * time.Second)
}
func setOne(c Candidate) error { return apiSetOne(c) }
func changeTransparent(mode string) error {
	return mutate(func(db *sql.DB) error { return setTransparent(db, mode) })
}

func run() error {
	s := loadState()
	ctrl := loadControl()
	if ctrl.Mode != "direct" && killSwitch(ctrl) && hostPathReady() {
		hardKillSwitchOff()
	}
	if ctrl.Mode == "direct" {
		hardKillSwitchOff()
		db, err := openDB()
		if err != nil {
			return err
		}
		mode, _ := transparent(db)
		db.Close()
		if mode != "close" {
			return changeTransparent("close")
		}
		s.FallbackDirect = false
		s.Failures = 0
		s.DesiredTransparent = "pac"
		saveState(s)
		return nil
	}
	if ctrl.Mode == "pinned" {
		return runPinned(ctrl, s)
	}

	// State lives in /tmp and is lost on reboot. Reconstruct fail-open state
	// from v2rayA itself so a reboot while transparent=close cannot leave
	// the router permanently bypassing LIBERTY.
	if db, err := openDB(); err == nil {
		if mode, modeErr := transparent(db); modeErr == nil {
			if mode == "close" && !s.FallbackDirect {
				s.FallbackDirect = true
				s.DesiredTransparent = "pac"
				s.Failures = 0
				note("detected transparent=close without failover state; treating it as fail-open")
				saveState(s)
			} else if mode != "" && mode != "close" && !s.FallbackDirect {
				s.DesiredTransparent = mode
			}
		}
		db.Close()
	}

	if !s.FallbackDirect {
		if err := repairHostPath(); err != nil {
			note("transparent host path repair failed: %v", err)
			s.Failures++
			saveState(s)
			if s.Failures < 2 {
				return nil
			}
			if db, e := openDB(); e == nil {
				if mode, e2 := transparent(db); e2 == nil && mode != "" && mode != "close" {
					s.DesiredTransparent = mode
				}
				db.Close()
			}
			if killSwitch(ctrl) {
				note("transparent host path unrecoverable; hard kill switch enabled")
				_ = hardKillSwitchOn()
				s.FallbackDirect = false
				s.Failures = 0
				saveState(s)
				return nil
			}
			note("transparent host path unrecoverable; fail-open to direct internet")
			if err := changeTransparent("close"); err != nil {
				return err
			}
			s.FallbackDirect = true
			s.Failures = 0
			saveState(s)
			return nil
		}
	}
	if health(6*time.Second, s.FallbackDirect) {
		if killSwitch(ctrl) {
			hardKillSwitchOff()
		}
		if s.FallbackDirect {
			note("LIBERTY recovered; restoring transparent mode %s", s.DesiredTransparent)
			if err := changeTransparent(s.DesiredTransparent); err != nil {
				return err
			}
			if !waitHealthy(10*time.Second, false) {
				return errors.New("proxy unhealthy after restoring transparent mode")
			}
			s.FallbackDirect = false
			s.LastSwitch = time.Now().Unix()
		}
		s.Failures = 0
		s.ScanOffset = 0
		saveState(s)
		return nil
	}
	s.Failures++
	note("proxy health check failed (%d/2)", s.Failures)
	saveState(s)

	// In normal mode confirm the first failure quickly instead of waiting for
	// the next one-minute cron tick. This preserves the two-failure rule while
	// reducing detection latency from about a minute to several seconds.
	if !s.FallbackDirect && s.Failures < 2 {
		time.Sleep(8 * time.Second)
		if health(4*time.Second, false) {
			s.Failures = 0
			s.ScanOffset = 0
			saveState(s)
			return nil
		}
		s.Failures++
		note("proxy health confirmation failed (%d/2)", s.Failures)
		saveState(s)
	}

	// While already in fail-open there is no reason to wait for a second cron
	// tick: the user's traffic is direct, so immediately continue scanning.

	db, err := openDB()
	if err != nil {
		return err
	}
	cs, err := candidates(db)
	if err != nil {
		db.Close()
		return err
	}
	curID, curSub, hasCur := current(db)
	db.Close()
	if len(cs) == 0 {
		return errors.New("no candidate nodes")
	}
	if hasCur {
		for _, c := range cs {
			if c.TouchID == curID && c.Sub == curSub {
				s.LastFailedNode = c.Name
				s.LastFailedAt = time.Now().Unix()
				break
			}
		}
	}
	saveState(s)
	start := 0
	if s.FallbackDirect && s.ScanOffset >= 0 && s.ScanOffset < len(cs) {
		start = s.ScanOffset
	}
	const failOpenAfterAttempts = 6
	attempts := 0
	for n := 0; n < len(cs); n++ {
		idx := (start + n) % len(cs)
		c := cs[idx]
		if hasCur && c.TouchID == curID && c.Sub == curSub {
			continue
		}
		if s.LastFailedNode != "" &&
			c.Name == s.LastFailedNode &&
			time.Now().Unix()-s.LastFailedAt < 5*60 {
			continue
		}
		attempts++
		note("trying %s (%s)", c.Name, c.Protocol)
		if err := setOne(c); err != nil {
			note("switch failed: %v", err)
			s.ScanOffset = (idx + 1) % len(cs)
			continue
		}
		s.ScanOffset = (idx + 1) % len(cs)
		if waitHealthy(2500*time.Millisecond, s.FallbackDirect) {
			note("switched successfully to %s (%s)", c.Name, c.Protocol)
			if killSwitch(ctrl) && hostPathReady() {
				hardKillSwitchOff()
			}
			if s.FallbackDirect {
				note("working LIBERTY node found during fail-open; restoring transparent mode %s", s.DesiredTransparent)
				if err := changeTransparent(s.DesiredTransparent); err != nil {
					return err
				}
				if !waitHealthy(4*time.Second, false) {
					return errors.New("proxy unhealthy after restoring transparent mode")
				}
				s.FallbackDirect = false
			}
			s.Failures = 0
			s.ScanOffset = 0
			s.LastSwitch = time.Now().Unix()
			s.LastNode = c.Name
			saveState(s)
			return nil
		}
		note("node %s did not pass HTTPS probe", c.Name)

		// Do not make the user wait for a full subscription scan. After several
		// failed candidates, fail open to direct internet but keep scanning the
		// remaining candidates in this same run through the internal SOCKS path.
		if attempts == failOpenAfterAttempts && !s.FallbackDirect && !killSwitch(ctrl) {
			if db, err := openDB(); err == nil {
				if mode, e := transparent(db); e == nil && mode != "" && mode != "close" {
					s.DesiredTransparent = mode
				}
				db.Close()
			}
			note("%d candidates failed; fail-open to direct internet while continuing scan", attempts)
			if err := changeTransparent("close"); err != nil {
				return err
			}
			s.FallbackDirect = true
			s.Failures = 0
			saveState(s)
		} else if attempts == failOpenAfterAttempts && killSwitch(ctrl) {
			note("%d candidates failed; kill switch active, protected traffic remains blocked while scan continues", attempts)
		}
	}
	if !s.FallbackDirect {
		if killSwitch(ctrl) {
			// The scan is over. If TPROXY is stable, drop the temporary hard guard:
			// direct RoutingA traffic works again while proxy-marked traffic still
			// goes only to the unavailable proxy outbound and therefore stays blocked.
			if hostPathReady() {
				hardKillSwitchOff()
				note("no LIBERTY node healthy; selective kill switch remains active")
			} else {
				_ = hardKillSwitchOn()
				note("no LIBERTY node healthy and TPROXY unavailable; hard kill switch remains active")
			}
			s.FallbackDirect = false
		} else {
			if db, err := openDB(); err == nil {
				if mode, e := transparent(db); e == nil && mode != "" && mode != "close" {
					s.DesiredTransparent = mode
				}
				db.Close()
			}
			note("no LIBERTY node healthy; fail-open to direct internet")
			if err := changeTransparent("close"); err != nil {
				return err
			}
			s.FallbackDirect = true
		}
	}
	s.Failures = 0
	saveState(s)
	return nil
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
	id, sub, ok := current(db)
	mode, _ := transparent(db)
	fmt.Printf("transparent=%s health=%v candidates=%d\n", mode, health(6*time.Second, mode == "close"), len(cs))
	for _, c := range cs {
		mark := " "
		if ok && c.TouchID == id && c.Sub == sub {
			mark = "*"
		}
		fmt.Printf("%s id=%d sub=%d p=%d %-12s %s\n", mark, c.TouchID, c.Sub, c.Priority, c.Protocol, c.Name)
	}
	return nil
}

func setByName(q string) error {
	db, err := openDB()
	if err != nil {
		return err
	}
	cs, err := candidates(db)
	db.Close()
	if err != nil {
		return err
	}
	q = strings.ToLower(q)
	for _, c := range cs {
		if strings.Contains(strings.ToLower(c.Name), q) {
			if err := setOne(c); err != nil {
				return err
			}
			fmt.Println("selected", c.Name)
			return nil
		}
	}
	return fmt.Errorf("no node matching %q", q)
}

// Run executes the vpn-guardian control command.
func Run(args []string) {
	oldArgs := os.Args
	oldFlags := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet("vpn-guardian control", flag.ExitOnError)
	os.Args = append([]string{"vpn-guardian control"}, args...)
	defer func() {
		os.Args = oldArgs
		flag.CommandLine = oldFlags
	}()
	main()
}

// NodeInfo is the dashboard-safe representation of a v2rayA node.
type NodeInfo struct {
	ID             int    `json:"id"`
	Sub            int    `json:"sub"`
	SubscriptionID int    `json:"subscriptionId"`
	Name           string `json:"name"`
	Net            string `json:"net"`
	Address        string `json:"address"`
	PingLatency    string `json:"pingLatency"`
	Active         bool   `json:"active"`
	Pinned         bool   `json:"pinned"`
}

// SubscriptionInfo is the dashboard representation of a v2rayA subscription.
type SubscriptionInfo struct {
	ID         int    `json:"id"`
	Address    string `json:"address"`
	Host       string `json:"host"`
	Info       string `json:"info"`
	Remarks    string `json:"remarks"`
	AutoSelect bool   `json:"autoSelect"`
	NodeCount  int    `json:"nodeCount"`
}

type ActiveNode struct {
	ID  int `json:"id"`
	Sub int `json:"sub"`
}

type FrontSnapshot struct {
	Control        Control            `json:"control"`
	Active         ActiveNode         `json:"active"`
	Nodes          []NodeInfo         `json:"nodes"`
	Subscriptions  []SubscriptionInfo `json:"subscriptions"`
	FrontEnabled   bool               `json:"frontEnabled"`
	HardKillSwitch bool               `json:"hardKillSwitch"`
	PolicyMode     string             `json:"policyMode"`
}

func Snapshot(includeSecrets bool) (FrontSnapshot, error) {
	var out FrontSnapshot
	out.Control = loadControl()
	out.FrontEnabled = fileExists("/etc/vpn-front-enabled")
	out.HardKillSwitch = false
	out.PolicyMode = strings.TrimSpace(readSmallFile("/etc/vpn-policy-mode"))

	db, err := openDB()
	if err != nil {
		return out, err
	}
	cs, err := candidates(db)
	if err != nil {
		db.Close()
		return out, err
	}
	activeID, activeSub, _ := current(db)
	db.Close()
	out.Active = ActiveNode{ID: activeID, Sub: activeSub}

	ping := map[string]string{}
	touch, touchErr := touchData()
	if touchErr == nil {
		if t, ok := touch["touch"].(map[string]any); ok {
			if subs, ok := t["subscriptions"].([]any); ok {
				for si, rawSub := range subs {
					sm, ok := rawSub.(map[string]any)
					if !ok {
						continue
					}
					sub := SubscriptionInfo{
						ID:         intValue(sm["id"]),
						Host:       fmt.Sprint(sm["host"]),
						Info:       fmt.Sprint(sm["info"]),
						Remarks:    fmt.Sprint(sm["remarks"]),
						AutoSelect: boolValue(sm["autoSelect"]),
					}
					if includeSecrets {
						sub.Address = fmt.Sprint(sm["address"])
					}
					if servers, ok := sm["servers"].([]any); ok {
						sub.NodeCount = len(servers)
						for _, rawServer := range servers {
							vm, ok := rawServer.(map[string]any)
							if !ok {
								continue
							}
							id := intValue(vm["id"])
							ping[fmt.Sprintf("%d:%d", si, id)] = fmt.Sprint(vm["pingLatency"])
						}
					}
					out.Subscriptions = append(out.Subscriptions, sub)
				}
			}
		}
	}

	for _, c := range cs {
		netLabel := c.Protocol
		if c.Network != "" || c.Security != "" {
			netLabel = fmt.Sprintf("%s(%s+%s)", c.Protocol, c.Network, c.Security)
		}
		out.Nodes = append(out.Nodes, NodeInfo{
			ID:             c.TouchID,
			Sub:            c.Sub,
			SubscriptionID: c.SubscriptionID,
			Name:           c.Name,
			Net:            netLabel,
			Address:        c.Address,
			PingLatency:    ping[fmt.Sprintf("%d:%d", c.Sub, c.TouchID)],
			Active:         c.TouchID == activeID && c.Sub == activeSub,
			Pinned:         isPinned(out.Control, c),
		})
	}
	return out, nil
}

const frontControlLockPath = "/tmp/vpn-guardian-control.lock"

func withFrontControlLock(fn func() error) error {
	f, err := os.OpenFile(frontControlLockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)
	return fn()
}

func clearPin(c *Control) {
	c.PinName = ""
	c.PinProtocol = ""
	c.PinNetwork = ""
	c.PinSecurity = ""
	c.PinSubscriptionID = 0
}

func applyFrontPolicy(c Control) error {
	mode := c.FailurePolicy
	if c.Mode == "direct" {
		mode = "direct"
	}
	if mode != "killswitch" && mode != "failopen" && mode != "direct" {
		return fmt.Errorf("invalid front policy %q", mode)
	}
	return policy.Apply(mode)
}

func SetAutoFront() error {
	return withFrontControlLock(func() error {
		c := loadControl()
		c.Mode = "auto"
		clearPin(&c)
		if err := saveControl(c); err != nil {
			return err
		}
		return applyFrontPolicy(c)
	})
}

func SetDirectFront() error {
	return withFrontControlLock(func() error {
		c := loadControl()
		c.Mode = "direct"
		clearPin(&c)
		if err := saveControl(c); err != nil {
			return err
		}
		return applyFrontPolicy(c)
	})
}

func PinFront(id, sub int) error {
	return withFrontControlLock(func() error {
		candidate, err := candidateByTouch(id, sub)
		if err != nil {
			return err
		}
		if err := setTouchRaw(id, sub); err != nil {
			return err
		}
		c := loadControl()
		c.Mode = "pinned"
		c.PinName = candidate.Name
		c.PinProtocol = candidate.Protocol
		c.PinNetwork = candidate.Network
		c.PinSecurity = candidate.Security
		c.PinSubscriptionID = candidate.SubscriptionID
		if err := saveControl(c); err != nil {
			return err
		}
		return applyFrontPolicy(c)
	})
}

func SwitchFront(id, sub int) error {
	return withFrontControlLock(func() error {
		if _, err := candidateByTouch(id, sub); err != nil {
			return err
		}
		if err := setTouchRaw(id, sub); err != nil {
			return err
		}
		c := loadControl()
		c.Mode = "auto"
		clearPin(&c)
		if err := saveControl(c); err != nil {
			return err
		}
		return applyFrontPolicy(c)
	})
}

func SetFailurePolicyFront(policy string) error {
	if policy != "killswitch" && policy != "failopen" {
		return fmt.Errorf("invalid failure policy %q", policy)
	}
	return withFrontControlLock(func() error {
		c := loadControl()
		c.FailurePolicy = policy
		if err := saveControl(c); err != nil {
			return err
		}
		return applyFrontPolicy(c)
	})
}

func AddSubscription(address string) error {
	if strings.TrimSpace(address) == "" {
		return errors.New("subscription URL required")
	}
	return withFrontControlLock(func() error {
		_, err := apiCall(http.MethodPost, "import", map[string]any{
			"url":  strings.TrimSpace(address),
			"kind": "subscription",
		}, 120*time.Second)
		return err
	})
}

func UpdateSubscription(id int) error {
	if id <= 0 {
		return errors.New("subscription id required")
	}
	return withFrontControlLock(func() error {
		_, err := apiCall(http.MethodPut, "subscription", map[string]any{
			"_type": "subscription",
			"id":    id,
		}, 120*time.Second)
		return err
	})
}

func EditSubscription(id int, address, remarks string, autoSelect bool) error {
	if id <= 0 || strings.TrimSpace(address) == "" {
		return errors.New("subscription id and URL required")
	}
	return withFrontControlLock(func() error {
		return editSubscription(id, strings.TrimSpace(address), remarks, autoSelect)
	})
}

func DeleteSubscription(id int) error {
	if id <= 0 {
		return errors.New("subscription id required")
	}
	return withFrontControlLock(func() error {
		_, err := apiCall(http.MethodDelete, "touch", map[string]any{
			"touches": []any{map[string]any{"_type": "subscription", "id": id}},
		}, 30*time.Second)
		return err
	})
}

func TestLatency() (any, error) {
	var result any
	err := withFrontControlLock(func() error {
		var err error
		result, err = latencyAll()
		return err
	})
	return result, err
}

func isPinned(c Control, node Candidate) bool {
	return c.Mode == "pinned" &&
		(c.PinSubscriptionID == 0 || c.PinSubscriptionID == node.SubscriptionID) &&
		c.PinName == node.Name &&
		c.PinProtocol == node.Protocol &&
		c.PinNetwork == node.Network &&
		c.PinSecurity == node.Security
}

func intValue(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case json.Number:
		n, _ := strconv.Atoi(string(x))
		return n
	case string:
		n, _ := strconv.Atoi(x)
		return n
	default:
		return 0
	}
}

func boolValue(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true" || x == "1"
	case float64:
		return x != 0
	default:
		return false
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readSmallFile(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}
