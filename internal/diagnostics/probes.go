package diagnostics

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/proxy"
)

type probeResult struct {
	Name       string `json:"name"`
	Route      string `json:"route"`
	HTTPStatus int    `json:"http_status,omitempty"`
	LatencyMS  int64  `json:"latency_ms"`
	Error      string `json:"error,omitempty"`
}

type probeSummary struct {
	Time   string        `json:"time"`
	Probes []probeResult `json:"probes"`
}

// Named, read-only probes reproduce more than watchdog's generic five URLs:
// direct Yandex, proxy YouTube, and ChatGPT's actual homepage (which can be
// challenged even when the /backend-api/me health endpoint returns 401).
// Never save response bodies, redirects, cookies or the browsing history.
func collectProbes(ctx context.Context, now time.Time) probeSummary {
	out := probeSummary{Time: now.UTC().Format(time.RFC3339Nano)}
	for _, target := range []struct {
		name, route, url string
	}{
		{"yandex", "direct", "https://yandex.ru/"},
		{"youtube", "front-socks", "https://www.youtube.com/"},
		{"chatgpt", "front-socks", "https://chatgpt.com/"},
		{"notebook", "front-socks", "https://notebook.google/"},
	} {
		out.Probes = append(out.Probes, probeHTTP(ctx, target.name, target.route, target.url))
	}
	return out
}

func probeHTTP(ctx context.Context, name, route, url string) (result probeResult) {
	result = probeResult{Name: name, Route: route}
	begin := time.Now()
	defer func() { result.LatencyMS = time.Since(begin).Milliseconds() }()
	// Use a distinct 6-second timeout for each request. Monitoring never
	// changes control mode, network routes or the active backend.
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	base := &net.Dialer{Timeout: 3 * time.Second}
	dial := base.DialContext
	if route == "front-socks" {
		socks, err := proxy.SOCKS5("tcp", "127.0.0.1:20174", nil, base)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		contextDial, ok := socks.(proxy.ContextDialer)
		if !ok {
			result.Error = "SOCKS5 context dialer unavailable"
			return result
		}
		dial = contextDial.DialContext
	}
	transport := &http.Transport{
		DialContext:         dial,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 4 * time.Second,
		ForceAttemptHTTP2:   true,
		DisableKeepAlives:   true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Header.Set("User-Agent", "VPN-Guardian-Diagnostics/1")
	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("%v", err)
		return result
	}
	defer resp.Body.Close()
	result.HTTPStatus = resp.StatusCode
	return result
}
