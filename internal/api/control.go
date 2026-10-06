package api

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/control"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
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
	Action     string             `json:"action"`
	PIN        string             `json:"pin,omitempty"`
	Enabled    bool               `json:"enabled,omitempty"`
	ID         int                `json:"id,omitempty"`
	Sub        int                `json:"sub,omitempty"`
	URL        string             `json:"url,omitempty"`
	Remarks    string             `json:"remarks,omitempty"`
	AutoSelect bool               `json:"autoSelect,omitempty"`
	Confirm    string             `json:"confirm,omitempty"`
	Service    string             `json:"service,omitempty"`
	Transports []config.Transport `json:"transports,omitempty"`
}

type transportOptionResponse struct {
	Value config.Transport `json:"value"`
	Label string           `json:"label"`
}

type selectionResponse struct {
	AllowedTransports []config.Transport        `json:"allowedTransports"`
	Options           []transportOptionResponse `json:"options"`
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
	Selection      selectionResponse          `json:"selection"`
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

func makeControlResponse(authenticated, configured bool) (controlResponse, error) {
	snap, err := control.Snapshot(authenticated)
	if err != nil {
		return controlResponse{}, err
	}
	stack, err := config.LoadStack()
	if err != nil {
		return controlResponse{}, err
	}
	selection := makeSelectionResponse(stack)

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
		Selection:      selection,
	}, nil
}

func makeSelectionResponse(stack config.Stack) selectionResponse {
	options := make([]transportOptionResponse, 0, len(config.TransportOptions()))
	for _, option := range config.TransportOptions() {
		options = append(options, transportOptionResponse{
			Value: option.Value,
			Label: option.Label,
		})
	}
	return selectionResponse{
		AllowedTransports: append([]config.Transport(nil), stack.Selection.AllowedTransports...),
		Options:           options,
	}
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
