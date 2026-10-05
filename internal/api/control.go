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
	"strings"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/control"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
	v2rayautil "github.com/Yakwilik/openwrt-vpn-guardian/internal/v2raya"
)

const (
	authPath      = paths.AuthConfig
	sessionDir    = paths.SessionsDir
	sessionCookie = "vpnctl"
	sessionTTL    = time.Hour
	pinRounds     = 150000
)

type authConfig struct {
	Salt       string `json:"salt"`
	Hash       string `json:"hash"`
	Iterations int    `json:"iterations"`
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

func HandleControlHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleControlGET(w, r)
	case http.MethodPost:
		handleControlPOST(w, r)
	default:
		writeControlError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func handleControlGET(w http.ResponseWriter, r *http.Request) {
	token, sess, authenticated := currentSession(r)
	configured := authConfigured()

	resp, err := makeControlResponse(authenticated, configured)
	if err != nil {
		writeControlError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if authenticated {
		refreshSession(token, &sess)
		resp.CSRF = sess.CSRF
	}
	writeControlJSON(w, http.StatusOK, resp)
}

func handleControlPOST(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeControlError(w, http.StatusBadRequest, "cannot read request")
		return
	}

	var req controlRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeControlError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	configured := authConfigured()
	if req.Action == "login" {
		if configured {
			if !verifyPIN(req.PIN) {
				writeControlError(w, http.StatusUnauthorized, "invalid PIN")
				return
			}
		} else if r.Header.Get("X-VPN-Unlock") != "1" || !isLANRequest(r) {
			writeControlError(w, http.StatusForbidden, "initial unlock is allowed only from router LAN")
			return
		}

		token, sess, err := createSession()
		if err != nil {
			writeControlError(w, http.StatusInternalServerError, err.Error())
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookie,
			Value:    token,
			Path:     "/",
			MaxAge:   int(sessionTTL.Seconds()),
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		resp, err := makeControlResponse(true, configured)
		if err != nil {
			writeControlError(w, http.StatusInternalServerError, err.Error())
			return
		}
		resp.CSRF = sess.CSRF
		writeControlJSON(w, http.StatusOK, resp)
		return
	}

	token, sess, authenticated := currentSession(r)
	if !authenticated {
		writeControlError(w, http.StatusUnauthorized, "management session required")
		return
	}

	if req.Action == "logout" {
		_ = os.Remove(sessionFile(token))
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookie,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		resp, err := makeControlResponse(false, configured)
		if err != nil {
			writeControlError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeControlJSON(w, http.StatusOK, resp)
		return
	}

	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-VPN-CSRF")), []byte(sess.CSRF)) != 1 {
		writeControlError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}

	result, err := executeControlAction(req)
	if err != nil {
		writeControlError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Action == "change_pin" {
		configured = authConfigured()
	}
	refreshSession(token, &sess)

	resp, err := makeControlResponse(true, configured)
	if err != nil {
		writeControlError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp.CSRF = sess.CSRF
	resp.Result = result
	writeControlJSON(w, http.StatusOK, resp)
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
		ready, err := v2rayautil.RepairBackendListener(true)
		if err != nil {
			return "", err
		}
		if !ready {
			return "", errors.New("backend listener is still unavailable")
		}
		return "", nil
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

func makeControlResponse(authenticated, configured bool) (controlResponse, error) {
	snap, err := control.Snapshot(authenticated)
	if err != nil {
		return controlResponse{}, err
	}
	mode := "setup"
	if configured {
		mode = "pin"
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

func authConfigured() bool {
	var cfg authConfig
	if err := readJSONFile(authConfigPath(), &cfg); err != nil {
		return false
	}
	return cfg.Salt != "" && cfg.Hash != "" && cfg.Iterations > 0
}

func savePIN(pin string) error {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	cfg := authConfig{
		Salt:       hex.EncodeToString(salt),
		Iterations: pinRounds,
	}
	cfg.Hash = hex.EncodeToString(pinDigest(pin, salt, cfg.Iterations))
	return writeJSONFileAtomic(authConfigPath(), cfg, 0600)
}

func verifyPIN(pin string) bool {
	var cfg authConfig
	if readJSONFile(authConfigPath(), &cfg) != nil || cfg.Iterations <= 0 {
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
	got := pinDigest(pin, salt, cfg.Iterations)
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

func currentSession(r *http.Request) (string, session, bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || !validSessionToken(cookie.Value) {
		return "", session{}, false
	}
	token := cookie.Value
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

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func dashboardPeerAllowed(r *http.Request) bool {
	peerIP := requestPeerIP(r)
	if peerIP == nil {
		return false
	}
	if peerIP.IsLoopback() {
		return true
	}
	return ipInCIDR(peerIP, configuredLANCIDR())
}

func isLANRequest(r *http.Request) bool {
	clientIP := requestClientIP(r)
	if clientIP == nil {
		return false
	}
	return ipInCIDR(clientIP, configuredLANCIDR())
}

func requestPeerIP(r *http.Request) net.IP {
	if r == nil {
		return nil
	}
	peer := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(peer); err == nil {
		peer = host
	}
	return net.ParseIP(peer)
}

func requestClientIP(r *http.Request) net.IP {
	peerIP := requestPeerIP(r)
	if peerIP == nil {
		return nil
	}
	if !peerIP.IsLoopback() {
		return peerIP
	}
	if forwarded := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); forwarded != nil {
		return forwarded
	}
	return peerIP
}

func configuredLANCIDR() string {
	cfg, err := config.LoadStack()
	if err != nil {
		return ""
	}
	return cfg.LANCIDR
}

func ipInCIDR(ip net.IP, cidr string) bool {
	if ip == nil || cidr == "" {
		return false
	}
	_, subnet, err := net.ParseCIDR(cidr)
	return err == nil && subnet.Contains(ip)
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
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
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

func writeControlJSON(w http.ResponseWriter, status int, v controlResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeControlError(w http.ResponseWriter, status int, message string) {
	writeControlJSON(w, status, controlResponse{OK: false, Error: message, Message: message})
}
