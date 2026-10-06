package collector

import "testing"

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
