package v2raya

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSignLocalJWT(t *testing.T) {
	db := openTestDB(t)
	secret := []byte("0123456789abcdef0123456789abcdef")
	secretJSON, err := json.Marshal(hex.EncodeToString(secret))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		"INSERT INTO system_config(key, value) VALUES(?, ?)",
		"system:jwtSecret",
		string(secretJSON),
	); err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1_700_000_000, 0)
	token, err := SignLocalJWT(db, "unit-test", now)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts, want 3", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("header is not valid JSON: %v; raw=%q", err, headerBytes)
	}
	if header["alg"] != "HS256" || header["typ"] != "JWT" {
		t.Fatalf("unexpected header: %#v", header)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["uname"] != "unit-test" {
		t.Fatalf("uname = %v, want unit-test", payload["uname"])
	}
	wantExp := now.Add(jwtLifetime).Unix()
	if got := int64(payload["exp"].(float64)); got != wantExp {
		t.Fatalf("exp = %d, want %d", got, wantExp)
	}

	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	wantSignature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if parts[2] != wantSignature {
		t.Fatalf("signature mismatch")
	}
}

func TestClientCall(t *testing.T) {
	var gotAuthorization string
	var gotContentType string
	var gotBody map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/outboundConnections" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.URL.RawQuery != "test=1" {
			t.Errorf("query = %q", r.URL.RawQuery)
		}
		gotAuthorization = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"code":"SUCCESS","data":{"selected":true}}`)
	}))
	defer server.Close()

	client := &Client{
		baseURL:    server.URL + "/api",
		httpClient: server.Client(),
		tokenSource: func() (string, error) {
			return "test-token", nil
		},
	}

	envelope, err := client.Call(
		context.Background(),
		http.MethodPut,
		"outboundConnections?test=1",
		map[string]any{"id": 7},
	)
	if err != nil {
		t.Fatal(err)
	}
	if gotAuthorization != "test-token" {
		t.Fatalf("Authorization = %q", gotAuthorization)
	}
	if gotContentType != "application/json" {
		t.Fatalf("Content-Type = %q", gotContentType)
	}
	if gotBody["id"] != float64(7) {
		t.Fatalf("request body = %#v", gotBody)
	}
	data, ok := envelope["data"].(map[string]any)
	if !ok || data["selected"] != true {
		t.Fatalf("envelope = %#v", envelope)
	}
}

func TestClientCallAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"code":"FAILED","errorCode":"BAD","message":"nope"}`)
	}))
	defer server.Close()

	client := testClient(server)
	_, err := client.Call(context.Background(), http.MethodGet, "touch", nil)
	if err == nil {
		t.Fatal("expected API error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error type = %T, want *APIError: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusBadRequest || apiErr.Code != "FAILED" || apiErr.ErrorCode != "BAD" {
		t.Fatalf("unexpected APIError: %+v", apiErr)
	}
}

func TestClientCallRejectsInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "not-json")
	}))
	defer server.Close()

	client := testClient(server)
	_, err := client.Call(context.Background(), http.MethodGet, "touch", nil)
	if err == nil || !strings.Contains(err.Error(), "invalid JSON") {
		t.Fatalf("error = %v, want invalid JSON", err)
	}
}

func TestClientCallHonorsContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = io.WriteString(w, `{"code":"SUCCESS"}`)
	}))
	defer server.Close()

	client := testClient(server)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := client.Call(ctx, http.MethodGet, "touch", nil)
	if err == nil {
		t.Fatal("expected context timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context deadline exceeded", err)
	}
}

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+t.TempDir()+"/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec("CREATE TABLE system_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	return db
}

func testClient(server *httptest.Server) *Client {
	return &Client{
		baseURL:    server.URL + "/api",
		httpClient: server.Client(),
		tokenSource: func() (string, error) {
			return "test-token", nil
		},
	}
}
