package v2raya

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"time"
)

const (
	accountCheckTimeout  = 10 * time.Second
	backendAccessTimeout = 30 * time.Second
)

// NeedsAccount reports whether the local manager needs its first account.
// It does not open the database, generate a JWT, or change the manager.
func NeedsAccount(ctx context.Context) (bool, error) {
	return needsAccount(ctx, NewClient("vpn-guardian-setup"))
}

func needsAccount(ctx context.Context, client *Client) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, accountCheckTimeout)
	defer cancel()

	envelope, err := client.call(ctx, http.MethodGet, "account", nil, false)
	if err != nil {
		return false, bootstrapError(ctx, "check the initial v2rayA account", err)
	}
	data, ok := envelope["data"].(map[string]any)
	if !ok {
		return false, errors.New("v2rayA account response is missing its data object")
	}
	hasAccounts, ok := data["hasAnyAccounts"].(bool)
	if !ok {
		return false, errors.New("v2rayA account response is missing a boolean hasAnyAccounts")
	}
	return !hasAccounts, nil
}

// ConfigureBackendAccess creates the first account when necessary and ensures
// the ordinary backend SOCKS port matches the Guardian configuration. Existing
// accounts and all other ports are preserved. Credentials are used only for
// initial registration and are never persisted by Guardian or included in errors.
//
// The caller holds the shared control lock and must ensure transparent=close
// before calling this function: updating ports can reload a running v2rayA core.
// This function neither starts a core nor configures transparent routing itself.
func ConfigureBackendAccess(ctx context.Context, username, password string, socksPort int) error {
	return configureBackendAccess(ctx, username, password, socksPort, NewClient("vpn-guardian-setup"))
}

func configureBackendAccess(ctx context.Context, username, password string, socksPort int, client *Client) error {
	if socksPort < 1 || socksPort > 65535 {
		return errors.New("backend SOCKS port must be between 1 and 65535")
	}
	ctx, cancel := context.WithTimeout(ctx, backendAccessTimeout)
	defer cancel()

	required, err := needsAccount(ctx, client)
	if err != nil {
		return err
	}
	if required {
		if err := createInitialAccount(ctx, client, username, password); err != nil {
			return err
		}
	}

	ports, err := readBootstrapPorts(ctx, client)
	if err != nil {
		return err
	}
	if ports["socks5"] != float64(socksPort) {
		for _, field := range []string{"http", "socks5WithPac", "httpWithPac", "vmess"} {
			if ports[field] == float64(socksPort) {
				return fmt.Errorf("backend SOCKS port conflicts with the v2rayA %s port", field)
			}
		}
		if ports["api"].(map[string]any)["port"] == float64(socksPort) {
			return errors.New("backend SOCKS port conflicts with the v2rayA core API port")
		}

		// PUT /ports replaces the complete configuration. Preserve even unknown
		// fields returned by the manager rather than resetting its other ports.
		updated := maps.Clone(ports)
		updated["socks5"] = socksPort
		if _, err := client.Call(ctx, http.MethodPut, "ports", updated); err != nil {
			return bootstrapError(ctx, "configure the backend SOCKS port", err)
		}
	}
	confirmed, err := readBootstrapPorts(ctx, client)
	if err != nil {
		return err
	}
	if confirmed["socks5"] != float64(socksPort) {
		return errors.New("v2rayA did not retain the configured backend SOCKS port")
	}
	return nil
}

func createInitialAccount(ctx context.Context, client *Client, username, password string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("initial v2rayA setup requires an account username")
	}
	// v2rayA measures password length in bytes, not Unicode code points.
	if len(password) < 6 || len(password) > 32 {
		return errors.New("initial v2rayA account password must contain 6 to 32 bytes")
	}
	envelope, err := client.call(ctx, http.MethodPost, "account", map[string]string{
		"username": username,
		"password": password,
	}, false)
	if err != nil {
		return bootstrapError(ctx, "create the initial v2rayA account", err)
	}
	data, ok := envelope["data"].(map[string]any)
	if !ok {
		return errors.New("v2rayA account registration response is missing its data object")
	}
	token, ok := data["token"].(string)
	if !ok || strings.TrimSpace(token) == "" {
		return errors.New("v2rayA account registration did not return a session token")
	}
	// Successful registration persists the signing secret. Subsequent requests
	// use the usual local JWT source; the returned login token is not retained.
	return nil
}

func readBootstrapPorts(ctx context.Context, client *Client) (map[string]any, error) {
	envelope, err := client.Call(ctx, http.MethodGet, "ports", nil)
	if err != nil {
		return nil, bootstrapError(ctx, "read the backend SOCKS port configuration", err)
	}
	data, ok := envelope["data"].(map[string]any)
	if !ok {
		return nil, errors.New("v2rayA ports response is missing its data object")
	}
	for _, field := range []string{"socks5", "http", "socks5WithPac", "httpWithPac", "vmess"} {
		if !validBootstrapPort(data[field]) {
			return nil, fmt.Errorf("v2rayA ports response has a missing or invalid %s port", field)
		}
	}
	api, ok := data["api"].(map[string]any)
	if !ok || !validBootstrapPort(api["port"]) {
		return nil, errors.New("v2rayA ports response has a missing or invalid core API port")
	}
	services, exists := api["services"]
	if !exists {
		return nil, errors.New("v2rayA ports response is missing core API services")
	}
	// A disabled core API has services:null in v2rayA's default configuration.
	if services != nil {
		items, ok := services.([]any)
		if !ok {
			return nil, errors.New("v2rayA ports response has invalid core API services")
		}
		for _, item := range items {
			if _, ok := item.(string); !ok {
				return nil, errors.New("v2rayA ports response has invalid core API services")
			}
		}
	}
	return data, nil
}

func validBootstrapPort(value any) bool {
	port, ok := value.(float64)
	return ok && port >= 0 && port <= 65535 && port == float64(int(port))
}

func bootstrapError(ctx context.Context, action string, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%s: %w", action, ctx.Err())
	}
	// An upstream response, transport failure or local signing error may contain
	// credentials. Keep only trusted context and the numeric HTTP status.
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return fmt.Errorf("%s: local v2rayA API rejected the request (HTTP %d)", action, apiErr.StatusCode)
	}
	return fmt.Errorf("%s failed; check that the local v2rayA manager is available", action)
}
