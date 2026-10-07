package api

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServiceAPIKeyLifecycle(t *testing.T) {
	dir := t.TempDir()
	authPath := filepath.Join(dir, "service-auth.json")
	outputPath := filepath.Join(dir, "assistant.key")
	t.Setenv("VPN_GUARDIAN_SERVICE_AUTH_PATH", authPath)

	if serviceAPIKeyConfigured() {
		t.Fatal("service API key unexpectedly configured")
	}
	if err := createServiceAPIKey(outputPath); err != nil {
		t.Fatalf("create service API key: %v", err)
	}
	if !serviceAPIKeyConfigured() {
		t.Fatal("service API key should be configured")
	}

	raw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(raw))
	if !validServiceAPIKeyToken(token) {
		t.Fatal("generated service API key format is invalid")
	}
	if !verifyServiceAPIKey(token) {
		t.Fatal("generated service API key did not verify")
	}
	if verifyServiceAPIKey(strings.Repeat("0", 64)) {
		t.Fatal("wrong service API key was accepted")
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("plaintext key mode = %o, want 600", info.Mode().Perm())
	}
}

func TestRequestServiceAPIKey(t *testing.T) {
	token := strings.Repeat("a", 64)
	req := httptest.NewRequest("GET", "http://router/api/control", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if got := requestServiceAPIKey(req); got != token {
		t.Fatalf("requestServiceAPIKey = %q, want token", got)
	}

	for _, value := range []string{
		"",
		"Basic " + token,
		"Bearer short",
		"Bearer " + token + " extra",
	} {
		req.Header.Set("Authorization", value)
		if got := requestServiceAPIKey(req); got != "" && !validServiceAPIKeyToken(got) {
			t.Fatalf("invalid authorization produced usable token %q", got)
		}
	}
}

func TestServiceAPIKeyCannotManageBrowserAuthentication(t *testing.T) {
	for _, action := range []string{"login", "logout", "change_pin"} {
		if serviceAPIActionAllowed(action) {
			t.Fatalf("service API key must not allow %q", action)
		}
	}
	for _, action := range []string{"routing", "selection", "switch", "repair"} {
		if !serviceAPIActionAllowed(action) {
			t.Fatalf("service API key should allow %q", action)
		}
	}
}
