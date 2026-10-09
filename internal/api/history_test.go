package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseTZOffset(t *testing.T) {
	tests := []struct {
		input string
		want  int
		ok    bool
	}{
		{"+0300", 10800, true},
		{"-0530", -19800, true},
		{"+0000", 0, true},
		{"+1245", 45900, true},
		{"UTC", 0, false},
		{"+2460", 0, false},
		{"+01xx", 0, false},
		{"0300", 0, false},
	}
	for _, tt := range tests {
		got, ok := parseTZOffset(tt.input)
		if got != tt.want || ok != tt.ok {
			t.Errorf("parseTZOffset(%q) = (%d, %v), want (%d, %v)", tt.input, got, ok, tt.want, tt.ok)
		}
	}
}

func TestReadSamplesSupportsOldAndNewHealthCounts(t *testing.T) {
	p := filepath.Join(t.TempDir(), "history.tsv")
	records := []string{
		"1791547197\t0\t3\t1\tdegraded\t1\tNetherlands",
		"1791547834\t0\t4\t1\tdegraded\t0\tNetherlands\t5",
	}
	if err := os.WriteFile(p, []byte(strings.Join(records, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	samples, err := readSamples(p, 10)
	if err != nil || len(samples) != 2 {
		t.Fatalf("readSamples = %+v, %v", samples, err)
	}
	for i, wantTotal := range []int{4, 5} {
		if samples[i].Total != wantTotal || samples[i].Failed != 1 || samples[i].Overall != "degraded" {
			t.Errorf("sample %d = %+v", i, samples[i])
		}
	}
	if samples[0].Switch != 1 || samples[0].Node != "Netherlands" {
		t.Errorf("switch data not preserved: %+v", samples[0])
	}
}

func TestReconstructEventsUsesPersistedHealthState(t *testing.T) {
	samples := []Sample{
		{TS: 100, Availability: 100, Health: 5, Total: 5, Overall: "ok"},
		{TS: 200, Availability: 0, Health: 4, Total: 5, Overall: "degraded"},
	}
	events := reconstructEvents(samples)
	if len(events) != 1 || events[0].Type != "outage" || !strings.Contains(events[0].Message, "4/5") {
		t.Fatalf("required target failure was misclassified: %+v", events)
	}
}

func TestNormalizeEventsKeepsRealRapidSwitches(t *testing.T) {
	events := []Event{
		{TS: 100, Type: "switch", Message: "switched successfully id=1 node-A"},
		{TS: 105, Type: "switch", Message: "Active node -> node-A"},
		{TS: 110, Type: "switch", Message: "switched successfully id=2 node-B"},
		{TS: 115, Type: "health", Message: "health failed (1/2): temporary error"},
		{TS: 120, Type: "health", Message: "health failed (2/2): persistent error"},
	}
	got := normalizeEvents(events, 100)
	if len(got) != 3 || got[0].TS != 100 || got[1].TS != 110 || got[2].TS != 120 {
		t.Fatalf("unexpected event history: %+v", got)
	}
}

func TestHistoryAvailabilityTracksBackendNotDirectMode(t *testing.T) {
	sample := Sample{Availability: 100, Health: 5, Total: 5, Overall: "direct"}
	if got := healthState(sample); got != "healthy" {
		t.Fatalf("backend health was lost in direct mode: %q", got)
	}
	sample = Sample{Availability: 0, Health: 4, Total: 5, Overall: "degraded"}
	if got := healthState(sample); got != "down" {
		t.Fatalf("required-probe outage was hidden by degraded overall: %q", got)
	}
}
