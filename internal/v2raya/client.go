package v2raya

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	defaultAPIBaseURL   = "http://127.0.0.1:2017/api"
	maxAPIResponseBytes = 4 << 20
	jwtLifetime         = 10 * time.Minute
)

// Client is the small transport boundary around the local v2rayA HTTP API.
// Runtime code uses NewClient; tests can replace the transport and token source
// without touching router state.
type Client struct {
	baseURL     string
	httpClient  *http.Client
	tokenSource func() (string, error)
}

// NewClient returns a client authenticated as subject against the local v2rayA
// manager.
func NewClient(subject string) *Client {
	return &Client{
		baseURL:    defaultAPIBaseURL,
		httpClient: http.DefaultClient,
		tokenSource: func() (string, error) {
			db, err := OpenDB()
			if err != nil {
				return "", err
			}
			defer db.Close()
			return SignLocalJWT(db, subject, time.Now())
		},
	}
}

// OpenDB opens the v2rayA SQLite database with the same busy timeout used by
// the rest of the integration layer.
func OpenDB() (*sql.DB, error) {
	return openRuntimeDB()
}

// GetRaw reads a raw system_config value.
func GetRaw(db *sql.DB, key string) (string, error) {
	return getRuntimeRaw(db, key)
}

// PutRaw writes a raw system_config value.
func PutRaw(db *sql.DB, key, value string) error {
	return putRuntimeRaw(db, key, value)
}

// SignLocalJWT creates a short-lived token accepted by the local v2rayA API.
func SignLocalJWT(db *sql.DB, subject string, now time.Time) (string, error) {
	raw, err := GetRaw(db, "system:jwtSecret")
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

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadBytes, err := json.Marshal(map[string]any{
		"uname": subject,
		"exp":   now.Add(jwtLifetime).Unix(),
	})
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	unsigned := header + "." + payload

	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(unsigned))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return unsigned + "." + signature, nil
}

// APIError describes a successful HTTP exchange that v2rayA rejected.
type APIError struct {
	Method     string
	Path       string
	StatusCode int
	Code       any
	ErrorCode  any
	Message    any
}

func (e *APIError) Error() string {
	return fmt.Sprintf(
		"v2rayA API %s %s failed: HTTP %d code=%v error=%v message=%v",
		e.Method,
		e.Path,
		e.StatusCode,
		e.Code,
		e.ErrorCode,
		e.Message,
	)
}

// Call performs one authenticated v2rayA request and returns the complete
// response envelope.
func (c *Client) Call(ctx context.Context, method, path string, payload any) (map[string]any, error) {
	if c == nil {
		return nil, fmt.Errorf("nil v2rayA client")
	}
	if c.httpClient == nil {
		return nil, fmt.Errorf("nil v2rayA HTTP client")
	}
	if c.tokenSource == nil {
		return nil, fmt.Errorf("nil v2rayA token source")
	}

	token, err := c.tokenSource()
	if err != nil {
		return nil, fmt.Errorf("create v2rayA API token: %w", err)
	}

	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("encode v2rayA API payload: %w", err)
		}
		body = bytes.NewReader(encoded)
	}

	endpoint := strings.TrimRight(c.baseURL, "/") + "/" + strings.TrimLeft(path, "/")
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("create v2rayA API request: %w", err)
	}
	req.Header.Set("Authorization", token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("v2rayA API %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read v2rayA API %s response: %w", path, err)
	}
	if len(responseBody) > maxAPIResponseBytes {
		return nil, fmt.Errorf("v2rayA API %s response exceeds %d bytes", path, maxAPIResponseBytes)
	}

	var envelope map[string]any
	if err := json.Unmarshal(responseBody, &envelope); err != nil {
		return nil, fmt.Errorf("v2rayA API %s returned invalid JSON: HTTP %d: %w", path, resp.StatusCode, err)
	}
	if resp.StatusCode >= http.StatusBadRequest || fmt.Sprint(envelope["code"]) != "SUCCESS" {
		return nil, &APIError{
			Method:     method,
			Path:       path,
			StatusCode: resp.StatusCode,
			Code:       envelope["code"],
			ErrorCode:  envelope["errorCode"],
			Message:    envelope["message"],
		}
	}
	return envelope, nil
}

// CallData is a convenience wrapper for callers that only need the data field.
func (c *Client) CallData(ctx context.Context, method, path string, payload any) (any, error) {
	envelope, err := c.Call(ctx, method, path, payload)
	if err != nil {
		return nil, err
	}
	return envelope["data"], nil
}

// CallAPI preserves the simple call shape used by the control plane while all
// transport behavior lives in Client.
func CallAPI(subject, method, path string, payload any, timeout time.Duration) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return NewClient(subject).Call(ctx, method, path, payload)
}

// CallAPIData is the data-only counterpart of CallAPI.
func CallAPIData(subject, method, path string, payload any, timeout time.Duration) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return NewClient(subject).CallData(ctx, method, path, payload)
}
