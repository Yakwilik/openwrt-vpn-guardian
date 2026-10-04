package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/control"
)

const (
	authPath         = "/etc/vpn-dashboard-auth.json"
	sessionDir       = "/tmp/vpn-dashboard-sessions"
	sessionCookie    = "vpnctl"
	legacyControlCGI = "/www/cgi-bin/vpn-control.legacy"
	sessionTTL       = time.Hour
	pinRounds        = 150000
)

type authConfig struct {
	Version    int    `json:"Version,omitempty"`
	Salt       string `json:"Salt"`
	Hash       string `json:"Hash"`
	Iterations int    `json:"Iterations,omitempty"`
}

type session struct {
	CSRF    string `json:"csrf"`
	Expires int64  `json:"expires"`
}

type controlRequest struct {
	Action     string `json:"action"`
	PIN        string `json:"pin,omitempty"`
	Enabled    bool   `json:"enabled,omitempty"`
	ID         int    `json:"id,omitempty"`
	Sub        int    `json:"sub,omitempty"`
	URL        string `json:"url,omitempty"`
	Remarks    string `json:"remarks,omitempty"`
	AutoSelect bool   `json:"autoSelect,omitempty"`
	Confirm    string `json:"confirm,omitempty"`
	Service    string `json:"service,omitempty"`
}

type controlResponse struct {
	OK             bool                       `json:"ok"`
	Authenticated  bool                       `json:"authenticated"`
	AuthConfigured bool                       `json:"authConfigured"`
	AuthMode       string                     `json:"authMode"`
	CSRF           string                     `json:"csrf,omitempty"`
	Control        control.Control            `json:"control"`
	Active         control.ActiveNode         `json:"active"`
	Nodes          []control.NodeInfo         `json:"nodes"`
	Subscriptions  []control.SubscriptionInfo `json:"subscriptions"`
	FrontEnabled   bool                       `json:"frontEnabled"`
	HardKillSwitch bool                       `json:"hardKillSwitch"`
	PolicyMode     string                     `json:"policyMode"`
	Result         string                     `json:"result,omitempty"`
	Message        string                     `json:"message,omitempty"`
	Error          string                     `json:"error,omitempty"`
}

func ControlCGI() {
	method := os.Getenv("REQUEST_METHOD")
	if method == "" {
		method = http.MethodGet
	}

	switch method {
	case http.MethodGet:
		handleControlGET()
	case http.MethodPost:
		handleControlPOST()
	default:
		writeControlError(405, "method not allowed")
	}
}

func handleControlGET() {
	token, sess, authenticated := currentSession()
	configured, legacy := authConfigured()
	resp, err := makeControlResponse(authenticated, configured, legacy, sess)
	if err != nil {
		writeControlError(500, err.Error())
		return
	}
	if authenticated {
		refreshSession(token, &sess)
		resp.CSRF = sess.CSRF
	}
	writeControlJSON(200, resp, "")
}

func handleControlPOST() {
	body, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		writeControlError(400, err.Error())
		return
	}
	var req controlRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeControlError(400, "invalid JSON")
		return
	}

	configured, legacy := authConfigured()
	if req.Action == "login" {
		if legacy {
			if fileExistsAPI(legacyHelperPath()) {
				delegateLegacyLogin(body)
				return
			}
			writeControlError(409, "legacy PIN requires migration helper")
			return
		}
		if configured {
			if !verifyPIN(req.PIN) {
				writeControlError(401, "invalid PIN")
				return
			}
		} else {
			if !isLANRequest() || os.Getenv("HTTP_X_VPN_UNLOCK") != "1" {
				writeControlError(403, "initial unlock is allowed only from LAN")
				return
			}
		}
		token, sess, err := createSession()
		if err != nil {
			writeControlError(500, err.Error())
			return
		}
		resp, err := makeControlResponse(true, configured, false, sess)
		if err != nil {
			writeControlError(500, err.Error())
			return
		}
		resp.CSRF = sess.CSRF
		writeControlJSON(200, resp, sessionSetCookie(token))
		return
	}

	token, sess, authenticated := currentSession()
	if !authenticated {
		writeControlError(401, "management session required")
		return
	}
	if req.Action == "logout" {
		_ = os.Remove(sessionFile(token))
		resp, err := makeControlResponse(false, configured, legacy, session{})
		if err != nil {
			writeControlError(500, err.Error())
			return
		}
		writeControlJSON(200, resp, sessionClearCookie())
		return
	}
	if subtle.ConstantTimeCompare([]byte(os.Getenv("HTTP_X_VPN_CSRF")), []byte(sess.CSRF)) != 1 {
		writeControlError(403, "invalid CSRF token")
		return
	}

	result, err := executeControlAction(req)
	if err != nil {
		writeControlError(400, err.Error())
		return
	}

	if req.Action == "change_pin" {
		configured, legacy = authConfigured()
	}
	refreshSession(token, &sess)
	resp, err := makeControlResponse(true, configured, legacy, sess)
	if err != nil {
		writeControlError(500, err.Error())
		return
	}
	resp.CSRF = sess.CSRF
	resp.Result = result
	writeControlJSON(200, resp, "")
}

func executeControlAction(req controlRequest) (string, error) {
	switch req.Action {
	case "change_pin":
		if len(req.PIN) < 6 {
			return "", errors.New("PIN must be at least 6 characters")
		}
		return "", savePIN(req.PIN)
	case "auto":
		return "", control.SetAutoFront()
	case "direct":
		return "", control.SetDirectFront()
	case "killswitch":
		policy := "failopen"
		if req.Enabled {
			policy = "killswitch"
		}
		return "", control.SetFailurePolicyFront(policy)
	case "switch":
		if req.ID <= 0 {
			return "", errors.New("node id required")
		}
		return "", control.SwitchFront(req.ID, req.Sub)
	case "pin":
		if req.ID <= 0 {
			return "", errors.New("node id required")
		}
		return "", control.PinFront(req.ID, req.Sub)
	case "latency":
		x, err := control.TestLatency()
		if err != nil {
			return "", err
		}
		b, _ := json.Marshal(x)
		return string(b), nil
	case "sub_add":
		return "", control.AddSubscription(req.URL)
	case "sub_update":
		return "", control.UpdateSubscription(req.ID)
	case "sub_edit":
		return "", control.EditSubscription(req.ID, req.URL, req.Remarks, req.AutoSelect)
	case "sub_delete":
		if req.Confirm != "DELETE" {
			return "", errors.New("subscription deletion requires DELETE confirmation")
		}
		if activeSubscriptionMatches(req.ID) {
			if err := control.SetDirectFront(); err != nil {
				return "", fmt.Errorf("protect active subscription before deletion: %w", err)
			}
		}
		return "", control.DeleteSubscription(req.ID)
	case "repair":
		return "", restartServiceAPI("vpn-backend-watchdog")
	case "restart":
		return "", restartAllowedService(req.Service)
	default:
		return "", fmt.Errorf("unknown action %q", req.Action)
	}
}

func activeSubscriptionMatches(id int) bool {
	snap, err := control.Snapshot(false)
	if err != nil || snap.Active.Sub < 0 || snap.Active.Sub >= len(snap.Subscriptions) {
		return false
	}
	return snap.Subscriptions[snap.Active.Sub].ID == id
}

func restartAllowedService(name string) error {
	switch name {
	case "v2raya", "xray", "zapret2":
		return restartServiceAPI(name)
	default:
		return fmt.Errorf("service %q is not allowed", name)
	}
}

func restartServiceAPI(name string) error {
	out, err := exec.Command("/etc/init.d/"+name, "restart").CombinedOutput()
	if err != nil {
		return fmt.Errorf("restart %s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func makeControlResponse(authenticated, configured, legacy bool, sess session) (controlResponse, error) {
	snap, err := control.Snapshot(authenticated)
	if err != nil {
		return controlResponse{}, err
	}
	mode := "setup"
	if configured {
		mode = "pin"
	}
	if legacy {
		mode = "legacy"
	}
	return controlResponse{
		OK:             true,
		Authenticated:  authenticated,
		AuthConfigured: configured,
		AuthMode:       mode,
		Control:        snap.Control,
		Active:         snap.Active,
		Nodes:          snap.Nodes,
		Subscriptions:  snap.Subscriptions,
		FrontEnabled:   snap.FrontEnabled,
		HardKillSwitch: snap.HardKillSwitch,
		PolicyMode:     snap.PolicyMode,
	}, nil
}

func authConfigured() (configured, legacy bool) {
	var cfg authConfig
	if err := readJSONFile(authConfigPath(), &cfg); err != nil {
		return false, false
	}
	if cfg.Salt == "" || cfg.Hash == "" {
		return false, false
	}
	return true, cfg.Version < 2
}

func savePIN(pin string) error {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	cfg := authConfig{
		Version:    2,
		Salt:       hex.EncodeToString(salt),
		Iterations: pinRounds,
	}
	cfg.Hash = hex.EncodeToString(pinDigest(pin, salt, cfg.Iterations))
	return writeJSONFileAtomic(authConfigPath(), cfg, 0600)
}

func verifyPIN(pin string) bool {
	var cfg authConfig
	if readJSONFile(authConfigPath(), &cfg) != nil || cfg.Version < 2 {
		return false
	}
	salt, err := hex.DecodeString(cfg.Salt)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(cfg.Hash)
	if err != nil {
		return false
	}
	rounds := cfg.Iterations
	if rounds <= 0 {
		rounds = pinRounds
	}
	got := pinDigest(pin, salt, rounds)
	return len(got) == len(want) && subtle.ConstantTimeCompare(got, want) == 1
}

func pinDigest(pin string, salt []byte, rounds int) []byte {
	first := make([]byte, 0, len(salt)+len(pin))
	first = append(first, salt...)
	first = append(first, pin...)
	sum := sha256.Sum256(first)
	for i := 1; i < rounds; i++ {
		h := sha256.New()
		_, _ = h.Write(sum[:])
		_, _ = h.Write(salt)
		_, _ = h.Write([]byte(pin))
		copy(sum[:], h.Sum(nil))
	}
	out := make([]byte, len(sum))
	copy(out, sum[:])
	return out
}

func createSession() (string, session, error) {
	if err := os.MkdirAll(sessionDirectory(), 0700); err != nil {
		return "", session{}, err
	}
	token, err := randomHex(24)
	if err != nil {
		return "", session{}, err
	}
	csrf, err := randomHex(24)
	if err != nil {
		return "", session{}, err
	}
	sess := session{CSRF: csrf, Expires: time.Now().Add(sessionTTL).Unix()}
	if err := writeJSONFileAtomic(sessionFile(token), sess, 0600); err != nil {
		return "", session{}, err
	}
	return token, sess, nil
}

func currentSession() (string, session, bool) {
	token := cookieValue(os.Getenv("HTTP_COOKIE"), sessionCookie)
	if !validSessionToken(token) {
		return "", session{}, false
	}
	var sess session
	if err := readJSONFile(sessionFile(token), &sess); err != nil {
		return "", session{}, false
	}
	if sess.CSRF == "" || sess.Expires <= time.Now().Unix() {
		_ = os.Remove(sessionFile(token))
		return "", session{}, false
	}
	return token, sess, true
}

func refreshSession(token string, sess *session) {
	if !validSessionToken(token) || sess == nil {
		return
	}
	sess.Expires = time.Now().Add(sessionTTL).Unix()
	_ = writeJSONFileAtomic(sessionFile(token), *sess, 0600)
}

func sessionFile(token string) string {
	return filepath.Join(sessionDirectory(), token+".json")
}

func validSessionToken(token string) bool {
	if len(token) != 48 {
		return false
	}
	_, err := hex.DecodeString(token)
	return err == nil
}

func cookieValue(header, name string) string {
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		if key, value, ok := strings.Cut(part, "="); ok && key == name {
			return value
		}
	}
	return ""
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func sessionSetCookie(token string) string {
	return fmt.Sprintf("%s=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d", sessionCookie, token, int(sessionTTL.Seconds()))
}

func sessionClearCookie() string {
	return sessionCookie + "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
}

func isLANRequest() bool {
	ip := net.ParseIP(strings.TrimSpace(os.Getenv("REMOTE_ADDR")))
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
}

func readJSONFile(path string, dst any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

func writeJSONFileAtomic(path string, v any, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := path + ".new"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func fileExistsAPI(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func writeControlJSON(status int, v controlResponse, setCookie string) {
	fmt.Printf("Status: %d\r\n", status)
	fmt.Print("Content-Type: application/json\r\n")
	fmt.Print("Cache-Control: no-store\r\n")
	if setCookie != "" {
		fmt.Printf("Set-Cookie: %s\r\n", setCookie)
	}
	fmt.Print("\r\n")
	_ = json.NewEncoder(os.Stdout).Encode(v)
}

func writeControlError(status int, message string) {
	resp := controlResponse{OK: false, Error: message, Message: message}
	writeControlJSON(status, resp, "")
}

func delegateLegacyLogin(body []byte) {
	helper := legacyHelperPath()
	cmd := exec.Command(helper)
	env := make([]string, 0, len(os.Environ())+3)
	for _, item := range os.Environ() {
		if strings.HasPrefix(item, "SCRIPT_FILENAME=") ||
			strings.HasPrefix(item, "SCRIPT_NAME=") ||
			strings.HasPrefix(item, "CONTENT_LENGTH=") {
			continue
		}
		env = append(env, item)
	}
	env = append(env,
		"SCRIPT_FILENAME="+helper,
		"SCRIPT_NAME=/cgi-bin/vpn-control.legacy",
		"CONTENT_LENGTH="+strconv.Itoa(len(body)),
	)
	cmd.Env = env
	cmd.Stdin = strings.NewReader(string(body))
	out, err := cmd.CombinedOutput()
	if len(out) > 0 && strings.Contains(string(out), "Content-Type:") {
		_, _ = os.Stdout.Write(out)
		return
	}
	if err != nil {
		writeControlError(401, "legacy PIN verification failed")
		return
	}
	writeControlError(500, "legacy control helper returned invalid CGI response")
}

func authConfigPath() string {
	if v := strings.TrimSpace(os.Getenv("VPN_GUARDIAN_AUTH_PATH")); v != "" {
		return v
	}
	return authPath
}

func sessionDirectory() string {
	if v := strings.TrimSpace(os.Getenv("VPN_GUARDIAN_SESSION_DIR")); v != "" {
		return v
	}
	return sessionDir
}

func legacyHelperPath() string {
	if v := strings.TrimSpace(os.Getenv("VPN_GUARDIAN_LEGACY_CONTROL_CGI")); v != "" {
		return v
	}
	return legacyControlCGI
}
