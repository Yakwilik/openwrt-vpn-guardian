package v2raya

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
)

const (
	setupTimeout          = 2 * time.Minute
	setupCandidateTimeout = 20 * time.Second
	setupRollbackTimeout  = 10 * time.Second
	setupPollInterval     = 250 * time.Millisecond
)

type setupAPI interface {
	Call(context.Context, string, string, any) (map[string]any, error)
}

// HasEligibleNodes checks the existing database without creating one or
// requiring a selected/healthy node. An absent database means setup needs input.
func HasEligibleNodes(ctx context.Context, selection config.Selection) (bool, error) {
	return hasEligibleNodes(ctx, selection, readSetupCandidates)
}

func hasEligibleNodes(ctx context.Context, selection config.Selection, list func(context.Context, CandidatePolicy) ([]Candidate, error)) (bool, error) {
	policy, err := NewCandidatePolicy(selection)
	if err != nil {
		return false, err
	}
	candidates, err := list(ctx, policy)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, setupError(ctx, "read available VPN nodes", err)
	}
	return len(candidates) > 0, nil
}

// ImportSubscriptions imports only addresses that are not already present.
// Subscription addresses stay inside this call and the authenticated transport;
// they are never included in returned errors. The caller holds the control lock.
func ImportSubscriptions(ctx context.Context, addresses []string) error {
	return importSubscriptions(ctx, addresses, NewClient("vpn-guardian-setup"))
}

func importSubscriptions(ctx context.Context, addresses []string, api setupAPI) error {
	if len(addresses) == 0 {
		return nil
	}
	input := make([]string, 0, len(addresses))
	for i, address := range addresses {
		address = strings.TrimSpace(address)
		u, err := url.Parse(address)
		if err != nil || u == nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.Opaque != "" {
			return fmt.Errorf("subscription #%d must be a valid HTTP or HTTPS URL", i+1)
		}
		input = append(input, address)
	}
	ctx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	envelope, err := api.Call(ctx, http.MethodGet, "touch", nil)
	if err != nil {
		return setupError(ctx, "read existing subscriptions", err)
	}
	existing, err := setupSubscriptionAddresses(envelope)
	if err != nil {
		return err
	}
	for i, address := range input {
		if _, exists := existing[address]; exists {
			continue
		}
		_, err := api.Call(ctx, http.MethodPost, "import", map[string]any{"url": address, "kind": "subscription"})
		if err != nil {
			return setupError(ctx, fmt.Sprintf("import subscription #%d", i+1), err)
		}
		existing[address] = struct{}{}
	}
	return nil
}

func setupSubscriptionAddresses(envelope map[string]any) (map[string]struct{}, error) {
	data, ok := envelope["data"].(map[string]any)
	if !ok {
		return nil, errors.New("v2rayA returned an unsupported subscription response")
	}
	touch, ok := data["touch"].(map[string]any)
	if !ok {
		return nil, errors.New("v2rayA returned an unsupported subscription response")
	}
	addresses := make(map[string]struct{})
	raw, exists := touch["subscriptions"]
	if !exists {
		return nil, errors.New("v2rayA subscription response is incomplete")
	}
	if raw == nil {
		return addresses, nil
	}
	subscriptions, ok := raw.([]any)
	if !ok {
		return nil, errors.New("v2rayA returned an unsupported subscription list")
	}
	for _, raw := range subscriptions {
		subscription, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("v2rayA returned an unsupported subscription entry")
		}
		address, ok := subscription["address"].(string)
		if !ok || address == "" {
			return nil, errors.New("v2rayA did not provide subscription addresses for duplicate checks")
		}
		addresses[address] = struct{}{}
	}
	return addresses, nil
}

type setupBackend struct {
	api        setupAPI
	candidates func(context.Context, CandidatePolicy) ([]Candidate, error)
	connected  func(context.Context) (NodeTouch, bool, error)
	listener   func() bool
	running    func() bool
	usable     func(context.Context) bool
	poll       time.Duration
}

// EnsureAllowedBackend preserves an already healthy allowed node, otherwise
// tries allowed candidates in priority order. It only changes the v2rayA proxy
// selection/core; front, policy and router interception remain the caller's
// responsibility. The caller must hold the shared control lock throughout.
// On success, restore compensates the selection/core changes if a later setup
// step fails. Failed selection attempts compensate themselves before returning.
func EnsureAllowedBackend(ctx context.Context, selection config.Selection) (func(context.Context) error, error) {
	return ensureAllowedBackend(ctx, selection, setupBackend{
		api: NewClient("vpn-guardian-setup"), candidates: readSetupCandidates,
		connected: readSetupTouch, listener: BackendSOCKSReady,
		running: func() bool { return processAlive("v2raya_core") },
		usable:  BackendUsableContext, poll: setupPollInterval,
	})
}

func ensureAllowedBackend(ctx context.Context, selection config.Selection, backend setupBackend) (restore func(context.Context) error, result error) {
	policy, err := NewCandidatePolicy(selection)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	if backend.poll <= 0 {
		backend.poll = setupPollInterval
	}
	candidates, err := backend.candidates(ctx, policy)
	if err != nil {
		return nil, setupError(ctx, "read allowed VPN nodes", err)
	}
	if len(candidates) == 0 {
		return nil, errors.New("no VPN nodes match selection.allowedTransports; import a compatible subscription or change the selection")
	}
	original, hadOriginal, err := backend.connected(ctx)
	if err != nil {
		return nil, setupError(ctx, "read the selected VPN node", err)
	}
	wasRunning := backend.running()
	compensate := setupCompensation(backend, original, hadOriginal, wasRunning)

	if active, ok := candidateAtTouch(candidates, original, hadOriginal); ok {
		probeCtx, probeCancel := context.WithTimeout(ctx, 10*time.Second)
		healthy := backend.listener() && backend.usable(probeCtx)
		if healthy {
			healthy, err = verifySetupChoice(probeCtx, backend, policy, active)
		}
		probeCancel()
		if healthy && err == nil {
			return func(context.Context) error { return nil }, nil
		}
		// Try recovering the current allowed backend before changing nodes.
		candidates = preferSetupCandidate(candidates, active)
	}

	changed := false
	defer func() {
		if result == nil || !changed {
			return
		}
		if err := compensate(context.WithoutCancel(ctx)); err != nil {
			result = errors.Join(result, err)
		}
	}()

	tried := 0
	var last error
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			break
		}
		attemptCtx, attemptCancel := context.WithTimeout(ctx, setupCandidateTimeout)
		// Subscription updates can change positional touch IDs. Refresh the
		// identity before issuing a switch and again before accepting success.
		fresh, readErr := backend.candidates(attemptCtx, policy)
		if readErr != nil {
			attemptCancel()
			return nil, setupError(ctx, "refresh allowed VPN nodes", readErr)
		}
		candidate, exists := findSetupIdentity(fresh, candidate)
		if !exists {
			attemptCancel()
			continue
		}
		tried++
		current, found, readErr := backend.connected(attemptCtx)
		if readErr != nil {
			attemptCancel()
			return nil, setupError(ctx, "read the selected VPN node", readErr)
		}
		touch := NodeTouch{ID: candidate.TouchID, Sub: candidate.Sub}
		if !found || current != touch {
			// A failed API response can still follow a completed server write.
			changed = true
			err = setSetupTouch(attemptCtx, backend.api, &touch)
		} else {
			err = nil
		}
		if err == nil && !backend.listener() {
			changed = true
			_, err = backend.api.Call(attemptCtx, http.MethodPost, "v2ray", nil)
		}
		if err == nil {
			err = waitSetupBackend(attemptCtx, backend, policy, candidate)
		}
		if err == nil {
			attemptCancel()
			if !changed {
				return func(context.Context) error { return nil }, nil
			}
			return compensate, nil
		}
		last = setupError(attemptCtx, "check the selected VPN backend", err)
		attemptCancel()
	}
	if ctx.Err() != nil {
		return nil, fmt.Errorf("VPN backend setup timed out or was canceled after %d candidates: %w", tried, ctx.Err())
	}
	if last != nil {
		return nil, fmt.Errorf("no allowed VPN backend passed connectivity checks after %d candidates: %w", tried, last)
	}
	return nil, errors.New("allowed VPN nodes changed during setup; retry bootstrap")
}

func setupCompensation(backend setupBackend, original NodeTouch, hadOriginal, wasRunning bool) func(context.Context) error {
	return func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, setupRollbackTimeout)
		defer cancel()
		var touch *NodeTouch
		if hadOriginal {
			touch = &original
		}
		if err := setSetupTouch(ctx, backend.api, touch); err != nil {
			return setupError(ctx, "restore the previous VPN node", err)
		}
		var method string
		if wasRunning && !backend.running() {
			method = http.MethodPost
		} else if !wasRunning && backend.running() {
			method = http.MethodDelete
		}
		if method != "" {
			if _, err := backend.api.Call(ctx, method, "v2ray", nil); err != nil {
				return setupError(ctx, "restore the previous VPN core state", err)
			}
		}
		return nil
	}
}

func waitSetupBackend(ctx context.Context, backend setupBackend, policy CandidatePolicy, expected Candidate) error {
	for {
		selected, err := verifySetupChoice(ctx, backend, policy, expected)
		if err != nil {
			return err
		}
		if selected && backend.listener() {
			if !backend.usable(ctx) {
				return errors.New("backend SOCKS connectivity check failed")
			}
			selected, err = verifySetupChoice(ctx, backend, policy, expected)
			if err != nil {
				return err
			}
			if selected {
				return nil
			}
		}
		timer := time.NewTimer(backend.poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func verifySetupChoice(ctx context.Context, backend setupBackend, policy CandidatePolicy, expected Candidate) (bool, error) {
	touch, found, err := backend.connected(ctx)
	if err != nil {
		return false, err
	}
	candidates, err := backend.candidates(ctx, policy)
	if err != nil {
		return false, err
	}
	actual, eligible := candidateAtTouch(candidates, touch, found)
	return eligible && sameSetupIdentity(actual, expected), nil
}

func candidateAtTouch(candidates []Candidate, touch NodeTouch, found bool) (Candidate, bool) {
	if found {
		for _, candidate := range candidates {
			if candidate.TouchID == touch.ID && candidate.Sub == touch.Sub {
				return candidate, true
			}
		}
	}
	return Candidate{}, false
}

func findSetupIdentity(candidates []Candidate, expected Candidate) (Candidate, bool) {
	for _, candidate := range candidates {
		if sameSetupIdentity(candidate, expected) {
			return candidate, true
		}
	}
	return Candidate{}, false
}

func sameSetupIdentity(a, b Candidate) bool {
	return a.SubscriptionID == b.SubscriptionID && a.Name == b.Name && a.Protocol == b.Protocol &&
		a.Network == b.Network && a.Security == b.Security && a.Address == b.Address
}

func preferSetupCandidate(candidates []Candidate, preferred Candidate) []Candidate {
	out := make([]Candidate, 0, len(candidates))
	out = append(out, preferred)
	for _, candidate := range candidates {
		if !sameSetupIdentity(candidate, preferred) {
			out = append(out, candidate)
		}
	}
	return out
}

func setSetupTouch(ctx context.Context, api setupAPI, touch *NodeTouch) error {
	touches := make([]any, 0, 1)
	if touch != nil {
		touches = append(touches, map[string]any{"_type": "subscriptionServer", "id": touch.ID, "sub": touch.Sub, "outbound": "proxy"})
	}
	_, err := api.Call(ctx, http.MethodPut, "outboundConnections", map[string]any{"outbound": "proxy", "touches": touches})
	return err
}

func readSetupCandidates(ctx context.Context, policy CandidatePolicy) ([]Candidate, error) {
	db, err := openSetupDB(paths.V2rayADB)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return ListCandidates(ctx, db, policy)
}

func readSetupTouch(ctx context.Context) (NodeTouch, bool, error) {
	db, err := openSetupDB(paths.V2rayADB)
	if err != nil {
		return NodeTouch{}, false, err
	}
	defer db.Close()
	return ConnectedTouch(ctx, db)
}

func openSetupDB(path string) (*sql.DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	uri := url.URL{Scheme: "file", Path: path}
	uri.RawQuery = url.Values{"mode": {"ro"}, "_pragma": {"busy_timeout(1000)"}}.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

func setupError(ctx context.Context, action string, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%s: %w", action, ctx.Err())
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return fmt.Errorf("%s: local v2rayA API rejected the request (HTTP %d)", action, apiErr.StatusCode)
	}
	// Upstream/API/SQL errors can contain private addresses or credentials.
	// Keep the actionable boundary and omit their untrusted details.
	return fmt.Errorf("%s failed; check the local v2rayA manager and its configured subscriptions", action)
}
