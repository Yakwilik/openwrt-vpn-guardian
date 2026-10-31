package api

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestDashboardHandlerServesBundle(t *testing.T) {
	handler, err := newDashboardHandler()
	if err != nil {
		t.Fatalf("newDashboardHandler: %v", err)
	}

	index := requestDashboard(t, handler, http.MethodGet, "/")
	if index.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want %d", index.Code, http.StatusOK)
	}
	if got := index.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("index Cache-Control = %q", got)
	}
	if got := index.Header().Get("Content-Security-Policy"); !strings.Contains(got, "script-src 'self'") {
		t.Fatalf("missing dashboard CSP: %q", got)
	}

	assetPath := regexp.MustCompile("/assets/[^\\\"]+\\.js").FindString(index.Body.String())
	if assetPath == "" {
		t.Fatalf("built index contains no JavaScript asset: %s", index.Body.String())
	}

	asset := requestDashboard(t, handler, http.MethodGet, assetPath)
	if asset.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d, want %d", assetPath, asset.Code, http.StatusOK)
	}
	if got := asset.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("asset Cache-Control = %q", got)
	}
	if asset.Body.Len() == 0 {
		t.Fatal("embedded JavaScript asset is empty")
	}

	if !strings.Contains(index.Body.String(), "href=\"/favicon.svg\"") {
		t.Fatal("dashboard has no favicon link")
	}
	favicon := requestDashboard(t, handler, http.MethodGet, "/favicon.svg")
	if favicon.Code != http.StatusOK {
		t.Fatalf("GET /favicon.svg status = %d, want 200", favicon.Code)
	}
	if got := favicon.Header().Get("Content-Type"); !strings.Contains(got, "image/svg+xml") {
		t.Fatalf("favicon Content-Type = %q", got)
	}
	if !strings.Contains(favicon.Body.String(), "<svg") {
		t.Fatal("favicon is not SVG markup")
	}
	if got := requestDashboard(t, handler, http.MethodHead, "/favicon.svg"); got.Code != http.StatusOK || got.Body.Len() != 0 {
		t.Fatalf("HEAD favicon status = %d, body length = %d", got.Code, got.Body.Len())
	}
}

func TestDashboardHandlerRejectsUnknownPathAndMethod(t *testing.T) {
	handler, err := newDashboardHandler()
	if err != nil {
		t.Fatalf("newDashboardHandler: %v", err)
	}

	if got := requestDashboard(t, handler, http.MethodGet, "/unknown").Code; got != http.StatusNotFound {
		t.Fatalf("GET /unknown status = %d, want %d", got, http.StatusNotFound)
	}
	if got := requestDashboard(t, handler, http.MethodPost, "/").Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("POST / status = %d, want %d", got, http.StatusMethodNotAllowed)
	}
}

func requestDashboard(t *testing.T, handler http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, "http://router"+path, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
