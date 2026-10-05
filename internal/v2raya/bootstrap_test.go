package v2raya

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNeedsAccountUsesPublicEndpointAndStrictBoolean(t *testing.T) {
	tests := []struct {
		name string
		data any
		want bool
		bad  bool
	}{
		{name: "first account", data: map[string]any{"hasAnyAccounts": false}, want: true},
		{name: "existing account", data: map[string]any{"hasAnyAccounts": true}},
		{name: "missing data", bad: true},
		{name: "non-object data", data: "private-response", bad: true},
		{name: "missing flag", data: map[string]any{}, bad: true},
		{name: "null flag", data: map[string]any{"hasAnyAccounts": nil}, bad: true},
		{name: "string flag", data: map[string]any{"hasAnyAccounts": "false"}, bad: true},
		{name: "numeric flag", data: map[string]any{"hasAnyAccounts": 0}, bad: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/api/account" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("Authorization") != "" {
					t.Error("initial account check included authorization")
				}
				writeBootstrapResponse(w, tt.data)
			}))
			defer server.Close()

			// A nil token source must be valid for this public request.
			client := &Client{baseURL: server.URL + "/api", httpClient: server.Client()}
			got, err := needsAccount(context.Background(), client)
			if (err != nil) != tt.bad || got != tt.want {
				t.Fatalf("needsAccount = (%v, %v), want (%v, error=%v)", got, err, tt.want, tt.bad)
			}
			if err != nil && strings.Contains(err.Error(), "private-response") {
				t.Fatal("response contents leaked into error")
			}
		})
	}
}

func TestConfigureBackendAccessRegistersBeforeReadingJWT(t *testing.T) {
	db := openTestDB(t)
	const username = "router-admin"
	const password = "private-password"
	var mu sync.Mutex
	var requests []string
	ports := bootstrapTestPorts(20170)
	expected := maps.Clone(ports)
	expected["socks5"] = float64(20173)
	accountCreated := false
	var tokenCalls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests = append(requests, r.Method+" "+r.URL.Path)
		if r.URL.Path == "/api/account" {
			if r.Header.Get("Authorization") != "" {
				t.Error("public account request included authorization")
			}
			switch r.Method {
			case http.MethodGet:
				writeBootstrapResponse(w, map[string]any{"hasAnyAccounts": accountCreated})
			case http.MethodPost:
				var credentials map[string]string
				if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
					t.Error(err)
				}
				if credentials["username"] != username || credentials["password"] != password {
					t.Error("registration did not preserve the supplied credentials")
				}
				if tokenCalls.Load() != 0 {
					t.Error("JWT source was called before first registration")
				}
				secret, _ := json.Marshal(hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
				if _, err := db.Exec("INSERT INTO system_config(key,value) VALUES(?,?)", "system:jwtSecret", string(secret)); err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				accountCreated = true
				writeBootstrapResponse(w, map[string]any{"token": "initial-login-token"})
			default:
				t.Errorf("unexpected account method: %s", r.Method)
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
			return
		}
		if r.URL.Path != "/api/ports" {
			t.Errorf("unexpected endpoint: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if !accountCreated || len(strings.Split(r.Header.Get("Authorization"), ".")) != 3 {
			t.Error("ports request lacked a local JWT after account creation")
		}
		switch r.Method {
		case http.MethodGet:
			writeBootstrapResponse(w, ports)
		case http.MethodPut:
			var changed map[string]any
			if err := json.NewDecoder(r.Body).Decode(&changed); err != nil {
				t.Error(err)
			}
			if !reflect.DeepEqual(changed, expected) {
				t.Error("port update changed or omitted unrelated configuration")
			}
			ports = changed
			writeBootstrapResponse(w, nil)
		default:
			t.Errorf("unexpected ports method: %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	client := &Client{
		baseURL: server.URL + "/api", httpClient: server.Client(),
		tokenSource: func() (string, error) {
			tokenCalls.Add(1)
			return SignLocalJWT(db, "bootstrap-test", time.Now())
		},
	}
	if err := configureBackendAccess(context.Background(), username, password, 20173, client); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"GET /api/account", "POST /api/account", "GET /api/ports", "PUT /api/ports", "GET /api/ports"}
	if !reflect.DeepEqual(requests, want) {
		t.Fatalf("request order = %v, want %v", requests, want)
	}
	if tokenCalls.Load() != 3 {
		t.Fatalf("JWT source calls = %d, want 3", tokenCalls.Load())
	}
}

func TestConfigureBackendAccessPreservesExistingAccountAndPort(t *testing.T) {
	var puts, registrations, reads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/account":
			if r.Method != http.MethodGet {
				registrations.Add(1)
			}
			writeBootstrapResponse(w, map[string]any{"hasAnyAccounts": true})
		case "/api/ports":
			if r.Method != http.MethodGet {
				puts.Add(1)
			}
			reads.Add(1)
			ports := bootstrapTestPorts(20173)
			ports["api"] = map[string]any{"port": float64(0), "services": nil}
			writeBootstrapResponse(w, ports)
		default:
			t.Errorf("unexpected endpoint: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Invalid supplied credentials are irrelevant once an account exists.
	if err := configureBackendAccess(context.Background(), "", "x", 20173, testClient(server)); err != nil {
		t.Fatal(err)
	}
	if puts.Load() != 0 || registrations.Load() != 0 || reads.Load() != 2 {
		t.Fatalf("writes=%d registrations=%d reads=%d", puts.Load(), registrations.Load(), reads.Load())
	}
}

func TestConfigureBackendAccessRequiresValidInitialCredentials(t *testing.T) {
	for _, tt := range []struct {
		name, username, password string
	}{
		{name: "username absent", password: "123456"},
		{name: "username blank", username: "  ", password: "123456"},
		{name: "password absent", username: "admin"},
		{name: "password too short", username: "admin", password: "12345"},
		{name: "password too long", username: "admin", password: strings.Repeat("x", 33)},
		{name: "multibyte password too long", username: "admin", password: strings.Repeat("я", 17)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var writes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/api/account" {
					writes.Add(1)
				}
				writeBootstrapResponse(w, map[string]any{"hasAnyAccounts": false})
			}))
			defer server.Close()
			client := &Client{baseURL: server.URL + "/api", httpClient: server.Client()}
			err := configureBackendAccess(context.Background(), tt.username, tt.password, 20173, client)
			if err == nil || writes.Load() != 0 {
				t.Fatalf("error=%v writes=%d", err, writes.Load())
			}
			if tt.password != "" && len(tt.password) > 4 && strings.Contains(err.Error(), tt.password) {
				t.Fatal("password leaked into error")
			}
		})
	}
}

func TestConfigureBackendAccessValidatesTargetPortBeforeRequests(t *testing.T) {
	for _, port := range []int{-1, 0, 65536} {
		if err := configureBackendAccess(context.Background(), "", "", port, nil); err == nil || !strings.Contains(err.Error(), "between 1 and 65535") {
			t.Fatalf("port=%d error=%v", port, err)
		}
	}
}

func TestConfigureBackendAccessRejectsIncompletePortsWithoutWriting(t *testing.T) {
	tests := []struct {
		name   string
		change func(map[string]any) any
	}{
		{name: "null data", change: func(map[string]any) any { return nil }},
		{name: "missing socks", change: func(p map[string]any) any { delete(p, "socks5"); return p }},
		{name: "string socks", change: func(p map[string]any) any { p["socks5"] = "20170"; return p }},
		{name: "fractional socks", change: func(p map[string]any) any { p["socks5"] = 20170.5; return p }},
		{name: "out of range http", change: func(p map[string]any) any { p["http"] = 65536; return p }},
		{name: "missing unused port", change: func(p map[string]any) any { delete(p, "vmess"); return p }},
		{name: "missing api", change: func(p map[string]any) any { delete(p, "api"); return p }},
		{name: "missing api port", change: func(p map[string]any) any { p["api"] = map[string]any{"services": nil}; return p }},
		{name: "missing api services", change: func(p map[string]any) any { p["api"] = map[string]any{"port": 0}; return p }},
		{name: "invalid api services", change: func(p map[string]any) any { p["api"] = map[string]any{"port": 0, "services": []any{4}}; return p }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var writes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					writes.Add(1)
				}
				if r.URL.Path == "/api/account" {
					writeBootstrapResponse(w, map[string]any{"hasAnyAccounts": true})
				} else {
					writeBootstrapResponse(w, tt.change(bootstrapTestPorts(20170)))
				}
			}))
			defer server.Close()
			if err := configureBackendAccess(context.Background(), "", "", 20173, testClient(server)); err == nil || writes.Load() != 0 {
				t.Fatalf("error=%v writes=%d", err, writes.Load())
			}
		})
	}
}

func TestConfigureBackendAccessDetectsUnretainedPort(t *testing.T) {
	var puts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/account" {
			writeBootstrapResponse(w, map[string]any{"hasAnyAccounts": true})
		} else if r.Method == http.MethodPut {
			puts.Add(1)
			writeBootstrapResponse(w, nil)
		} else {
			// Simulate an upstream success response without a persisted update.
			writeBootstrapResponse(w, bootstrapTestPorts(20170))
		}
	}))
	defer server.Close()
	err := configureBackendAccess(context.Background(), "", "", 20173, testClient(server))
	if err == nil || !strings.Contains(err.Error(), "did not retain") || puts.Load() != 1 {
		t.Fatalf("error=%v writes=%d", err, puts.Load())
	}
}

func TestBootstrapErrorsOmitUpstreamCredentials(t *testing.T) {
	const private = "private-username private-password private-token subscription-secret"
	for _, failure := range []string{"account read", "account create", "ports read", "ports write", "ports confirm"} {
		t.Run(failure, func(t *testing.T) {
			var gets atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var stage string
				switch {
				case r.URL.Path == "/api/account" && r.Method == http.MethodGet:
					stage = "account read"
				case r.URL.Path == "/api/account":
					stage = "account create"
				case r.Method == http.MethodPut:
					stage = "ports write"
				case gets.Add(1) == 1:
					stage = "ports read"
				default:
					stage = "ports confirm"
				}
				if stage == failure {
					_ = json.NewEncoder(w).Encode(map[string]any{"code": "FAIL", "message": private, "errorCode": private, "data": private})
					return
				}
				switch stage {
				case "account read":
					writeBootstrapResponse(w, map[string]any{"hasAnyAccounts": failure != "account create"})
				case "account create":
					writeBootstrapResponse(w, map[string]any{"token": "initial-token"})
				case "ports write":
					writeBootstrapResponse(w, nil)
				default:
					writeBootstrapResponse(w, bootstrapTestPorts(20170))
				}
			}))
			defer server.Close()
			err := configureBackendAccess(context.Background(), "private-username", "private-password", 20173, testClient(server))
			if err == nil {
				t.Fatal("expected error")
			}
			for _, value := range strings.Fields(private) {
				if strings.Contains(err.Error(), value) {
					t.Fatalf("error leaked %q", value)
				}
			}
		})
	}
}

func TestNeedsAccountHonorsCancellationAndBoundsRequests(t *testing.T) {
	var calls atomic.Int32
	client := &Client{
		baseURL: "http://local.invalid/api",
		httpClient: &http.Client{Transport: bootstrapRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls.Add(1)
			deadline, ok := r.Context().Deadline()
			if !ok || time.Until(deadline) > accountCheckTimeout {
				t.Error("request has no bounded deadline")
			}
			<-r.Context().Done()
			return nil, r.Context().Err()
		})},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := needsAccount(ctx, client)
	if !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 1 {
		t.Fatalf("error=%v calls=%d", err, calls.Load())
	}

	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	_, err = needsAccount(ctx, client)
	if !errors.Is(err, context.Canceled) || calls.Load() != 1 {
		t.Fatalf("canceled error=%v calls=%d", err, calls.Load())
	}
}

func TestNeedsAccountUsesSharedResponseLimit(t *testing.T) {
	client := &Client{
		baseURL: "http://local.invalid/api",
		httpClient: &http.Client{Transport: bootstrapRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxAPIResponseBytes+1))),
			}, nil
		})},
	}
	if _, err := needsAccount(context.Background(), client); err == nil {
		t.Fatal("oversized account response was accepted")
	}
}

func TestBootstrapTransportAndTokenErrorsAreSanitized(t *testing.T) {
	const private = "private-transport-token"
	client := &Client{
		baseURL: "http://local.invalid/api",
		httpClient: &http.Client{Transport: bootstrapRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("transport exposed %s", private)
		})},
	}
	_, err := needsAccount(context.Background(), client)
	if err == nil || strings.Contains(err.Error(), private) {
		t.Fatalf("transport error was not sanitized: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeBootstrapResponse(w, map[string]any{"hasAnyAccounts": true})
	}))
	defer server.Close()
	client = testClient(server)
	client.tokenSource = func() (string, error) { return "", errors.New(private) }
	err = configureBackendAccess(context.Background(), "", "", 20173, client)
	if err == nil || strings.Contains(err.Error(), private) {
		t.Fatalf("token error was not sanitized: %v", err)
	}
}

func bootstrapTestPorts(socks int) map[string]any {
	return map[string]any{
		"socks5": float64(socks), "http": float64(28080),
		"socks5WithPac": float64(0), "httpWithPac": float64(28081), "vmess": float64(0),
		"api":       map[string]any{"port": float64(30000), "services": []any{"LoggerService", "StatsService"}},
		"vmessLink": nil, "futureSetting": "preserve",
	}
}

func writeBootstrapResponse(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"code": "SUCCESS", "message": nil, "data": data})
}

type bootstrapRoundTripFunc func(*http.Request) (*http.Response, error)

func (f bootstrapRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestConfigureBackendAccessRejectsIncompleteRegistration(t *testing.T) {
	for _, tt := range []struct {
		name string
		data any
	}{
		{name: "missing data"},
		{name: "missing token", data: map[string]any{}},
		{name: "null token", data: map[string]any{"token": nil}},
		{name: "non-string token", data: map[string]any{"token": false}},
		{name: "empty token", data: map[string]any{"token": ""}},
		{name: "blank token", data: map[string]any{"token": "  "}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var privateRequests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/account" {
					privateRequests.Add(1)
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if r.Method == http.MethodGet {
					writeBootstrapResponse(w, map[string]any{"hasAnyAccounts": false})
				} else {
					writeBootstrapResponse(w, tt.data)
				}
			}))
			defer server.Close()
			client := &Client{baseURL: server.URL + "/api", httpClient: server.Client()}
			err := configureBackendAccess(context.Background(), "admin", "123456", 20173, client)
			if err == nil || privateRequests.Load() != 0 {
				t.Fatalf("error=%v private requests=%d", err, privateRequests.Load())
			}
		})
	}
}
