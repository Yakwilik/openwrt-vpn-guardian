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
