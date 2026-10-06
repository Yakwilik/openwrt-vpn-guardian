package watchdog

import "testing"

func TestBackendUnavailableHealth(t *testing.T) {
	const reason = "backend listener unavailable after runtime repair"

	got := backendUnavailableHealth(reason)
	if got.Healthy {
		t.Fatal("backend-unavailable health must not be healthy")
	}
	if got.Status != "down" {
		t.Fatalf("status = %q, want down", got.Status)
	}
	if got.Passed != 0 {
		t.Fatalf("passed = %d, want 0", got.Passed)
	}
	if got.Total != len(healthTargets) {
		t.Fatalf("total = %d, want %d", got.Total, len(healthTargets))
	}
	if len(got.Results) != len(healthTargets) {
		t.Fatalf("results = %d, want %d", len(got.Results), len(healthTargets))
	}

	for i, result := range got.Results {
		target := healthTargets[i]
		if result.Name != target.Name {
			t.Fatalf("result %d name = %q, want %q", i, result.Name, target.Name)
		}
		if result.URL != target.URL {
			t.Fatalf("result %d URL = %q, want %q", i, result.URL, target.URL)
		}
		if result.Code != 0 {
			t.Fatalf("result %d code = %d, want 0", i, result.Code)
		}
		if result.Error != reason {
			t.Fatalf("result %d error = %q, want %q", i, result.Error, reason)
		}
	}
}

func TestClassifyFrontRecovery(t *testing.T) {
	tests := []struct {
		name           string
		enabled        bool
		listening      bool
		routingReady   bool
		routingPresent bool
		want           frontRecoveryAction
	}{
		{
			name: "disabled and clean",
			want: frontRecoveryNone,
		},
		{
			name:           "disabled with stale routing",
			routingPresent: true,
			want:           frontRecoveryDisableInterception,
		},
		{
			name:         "healthy",
			enabled:      true,
			listening:    true,
			routingReady: true,
			want:         frontRecoveryNone,
		},
		{
			name:      "listener healthy routing missing",
			enabled:   true,
			listening: true,
			want:      frontRecoveryEnableInterception,
		},
		{
			name:           "listener missing routing active",
			enabled:        true,
			routingReady:   true,
			routingPresent: true,
			want:           frontRecoveryRestartFront,
		},
		{
			name:    "listener missing routing already disabled",
			enabled: true,
			want:    frontRecoveryRestartFront,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyFrontRecovery(tt.enabled, tt.listening, tt.routingReady, tt.routingPresent)
			if got != tt.want {
				t.Fatalf("action = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFrontFailureMayBypass(t *testing.T) {
	tests := []struct {
		name string
		ctrl Control
		want bool
	}{
		{
			name: "vpn only",
			ctrl: Control{Mode: "auto", FailurePolicy: "killswitch"},
			want: false,
		},
		{
			name: "pinned vpn only",
			ctrl: Control{Mode: "pinned", FailurePolicy: "killswitch"},
			want: false,
		},
		{
			name: "fail open",
			ctrl: Control{Mode: "auto", FailurePolicy: "failopen"},
			want: true,
		},
		{
			name: "explicit direct",
			ctrl: Control{Mode: "direct", FailurePolicy: "killswitch"},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := frontFailureMayBypass(tt.ctrl); got != tt.want {
				t.Fatalf("frontFailureMayBypass(%+v) = %v, want %v", tt.ctrl, got, tt.want)
			}
		})
	}
}

func TestDaemonLockIsNotControlLock(t *testing.T) {
	if lockPath == "/tmp/vpn-guardian-control.lock" {
		t.Fatal("daemon must not own the management lock for its entire lifetime")
	}
}

func TestRecoveryEventsAreVisible(t *testing.T) {
	for msg, want := range map[string]string{
		"front listener missing in VPN-only mode; keeping interception active while recovering front": "front",
		"front listener recovered; routing ready":                                                     "front",
		"front invariant recovery failed: timeout":                                                    "front",
		"backend listener recovered after runtime repair":                                             "recovery",
		"backend runtime repair failed: timeout":                                                      "backend",
	} {
		if got := dashboardEventType(msg); got != want {
			t.Errorf("event type for %q = %q, want %q", msg, got, want)
		}
	}
}

func TestForbiddenActiveCandidateSkipsHealthProbe(t *testing.T) {
	called := false
	got := healthForActiveCandidate(false, func() HealthResult {
		called = true
		return HealthResult{Healthy: true, Status: "healthy", Passed: 4, Total: 4}
	})
	if called {
		t.Fatal("forbidden active candidate must not be probed or declared healthy")
	}
	if got.Healthy || got.Status != "down" || got.Passed != 0 {
		t.Fatalf("forbidden active candidate health = %+v", got)
	}
}

func TestAllowedActiveCandidatePreservesHealth(t *testing.T) {
	called := false
	want := HealthResult{Healthy: true, Status: "degraded", Passed: 3, Total: 4}
	got := healthForActiveCandidate(true, func() HealthResult {
		called = true
		return want
	})
	if !called || got.Healthy != want.Healthy || got.Status != want.Status || got.Passed != want.Passed {
		t.Fatalf("allowed active candidate health = %+v, want %+v", got, want)
	}
}

func TestApplicationProbesAreRequired(t *testing.T) {
	tests := []struct {
		name  string
		codes map[string]int
		want  string
	}{
		{
			name: "all probes pass",
			codes: map[string]int{
				"google":     204,
				"cloudflare": 204,
				"telegram":   200,
				"openai":     401,
			},
			want: "healthy",
		},
		{
			name: "openai forbidden rejects otherwise healthy node",
			codes: map[string]int{
				"google":     204,
				"cloudflare": 204,
				"telegram":   200,
				"openai":     403,
			},
			want: "down",
		},
		{
			name: "telegram unavailable rejects otherwise healthy node",
			codes: map[string]int{
				"google":     204,
				"cloudflare": 204,
				"telegram":   503,
				"openai":     401,
			},
			want: "down",
		},
		{
			name: "one generic probe may fail",
			codes: map[string]int{
				"google":     0,
				"cloudflare": 204,
				"telegram":   200,
				"openai":     401,
			},
			want: "healthy",
		},
		{
			name: "both generic probes failing is not switch-safe",
			codes: map[string]int{
				"google":     0,
				"cloudflare": 0,
				"telegram":   200,
				"openai":     401,
			},
			want: "degraded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := healthResultWithCodes(tt.codes)
			if result.Status != tt.want {
				t.Fatalf("status = %q, want %q: %+v", result.Status, tt.want, result)
			}
			if got := result.Healthy; got != (tt.want == "healthy") {
				t.Fatalf("healthy = %v for status %q", got, tt.want)
			}
		})
	}
}

func TestOpenAIProbeRequiresUnauthorizedNotForbidden(t *testing.T) {
	target, ok := healthTargetByName("openai")
	if !ok {
		t.Fatal("openai health target missing")
	}
	if !target.Required {
		t.Fatal("openai health target must be required")
	}
	if !target.accepts(401) {
		t.Fatal("openai 401 must prove that the API is reachable from this egress")
	}
	if target.accepts(403) {
		t.Fatal("openai 403 must reject the node")
	}
}

func TestTelegramProbeIsRequired(t *testing.T) {
	target, ok := healthTargetByName("telegram")
	if !ok {
		t.Fatal("telegram health target missing")
	}
	if !target.Required {
		t.Fatal("telegram health target must be required")
	}
	if !target.accepts(200) {
		t.Fatal("telegram 200 must pass")
	}
}

func healthResultWithCodes(codes map[string]int) HealthResult {
	result := HealthResult{
		Total:   len(healthTargets),
		Results: make([]ProbeResult, 0, len(healthTargets)),
	}
	for _, target := range healthTargets {
		result.Results = append(result.Results, ProbeResult{
			Name: target.Name,
			URL:  target.URL,
			Code: codes[target.Name],
		})
	}
	classifyHealth(&result)
	return result
}
