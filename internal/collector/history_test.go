package collector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHistoryAvailabilityUsesHealthStatus(t *testing.T) {
	tests := []struct {
		status string
		want   int
	}{
		{status: "healthy", want: 100},
		{status: "degraded", want: 50},
		{status: "down", want: 0},
		{status: "", want: 0},
	}

	for _, tt := range tests {
		if got := historyAvailability(tt.status); got != tt.want {
			t.Errorf("historyAvailability(%q) = %d, want %d", tt.status, got, tt.want)
		}
	}
}

func TestAppendHistoryStoresProbeTotal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "samples.tsv")
	status := Status{
		Now: 100, HealthCount: 4, HealthTotal: 5,
		HealthStatus: "down", Overall: "degraded", Node: "Netherlands",
	}
	appendHistory(&runtimeState{}, status, path)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.TrimSpace(string(raw)), "\t")
	if len(parts) != 8 || parts[2] != "4" || parts[3] != "1" || parts[7] != "5" {
		t.Fatalf("wrong history format: %q", raw)
	}
}
