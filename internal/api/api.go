package api

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
)

const (
	cachePath   = paths.StatusCache
	historyPath = paths.History
	eventPath   = paths.Events
)

type Sample struct {
	TS           int64  `json:"ts"`
	Availability int    `json:"availability"`
	Health       int    `json:"health"`
	Total        int    `json:"total"`
	Failed       int    `json:"failed"`
	Overall      string `json:"overall"`
	Switch       int    `json:"switch"`
	Node         string `json:"node"`
}

type Event struct {
	TS      int64  `json:"ts"`
	Type    string `json:"type"`
	Message string `json:"message"`
}
type HistoryResponse struct {
	RouterTZOffset int      `json:"router_tz_offset"`
	Samples        []Sample `json:"samples"`
	Events         []Event  `json:"events"`
}

func readSamples(path string, limit int) ([]Sample, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var rows []Sample
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// Column 8 (number of health targets) was introduced after the
		// original 4-probe format; older history remains readable.
		parts := strings.SplitN(sc.Text(), "\t", 8)
		if len(parts) != 7 && len(parts) != 8 {
			continue
		}
		ts, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil || ts <= 0 {
			continue
		}
		health, _ := strconv.Atoi(parts[2])
		switchFlag, _ := strconv.Atoi(parts[5])
		total := 4
		if len(parts) == 8 {
			if value, err := strconv.Atoi(parts[7]); err == nil && value > 0 {
				total = value
			}
		}
		failed := total - health
		if failed < 0 {
			failed = 0
		}
		availability, _ := strconv.Atoi(parts[1])
		overall := parts[4]
		rows = append(rows, Sample{
			TS: ts, Availability: availability, Health: health, Total: total,
			Failed: failed, Overall: overall, Switch: switchFlag, Node: parts[6],
		})
	}
	if len(rows) > limit {
		rows = rows[len(rows)-limit:]
	}
	return rows, sc.Err()
}

func readEvents(path string, limit int) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var rows []Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), "\t", 3)
		if len(parts) != 3 {
			continue
		}
		ts, _ := strconv.ParseInt(parts[0], 10, 64)
		if ts <= 0 {
			continue
		}
		rows = append(rows, Event{TS: ts, Type: parts[1], Message: parts[2]})
	}
	if len(rows) > limit {
		rows = rows[len(rows)-limit:]
	}
	return rows, sc.Err()
}

func reconstructEvents(samples []Sample) []Event {
	if len(samples) == 0 {
		return nil
	}
	var events []Event
	prevState := healthState(samples[0])
	for i, s := range samples {
		if s.Switch == 1 {
			events = append(events, Event{TS: s.TS, Type: "switch", Message: "Active node -> " + s.Node})
		}
		state := healthState(s)
		if i == 0 {
			if state == "down" {
				events = append(events, Event{TS: s.TS, Type: "outage", Message: fmt.Sprintf("VPN backend unavailable: %d/%d checks", s.Health, s.Total)})
			} else if state == "degraded" {
				events = append(events, Event{TS: s.TS, Type: "health", Message: fmt.Sprintf("VPN backend degraded: %d/%d checks", s.Health, s.Total)})
			}
			continue
		}
		if state == prevState {
			continue
		}
		switch state {
		case "down":
			events = append(events, Event{TS: s.TS, Type: "outage", Message: fmt.Sprintf("VPN backend unavailable: %d/%d checks", s.Health, s.Total)})
		case "degraded":
			events = append(events, Event{TS: s.TS, Type: "health", Message: fmt.Sprintf("VPN backend degraded: %d/%d checks", s.Health, s.Total)})
		case "healthy":
			events = append(events, Event{TS: s.TS, Type: "recovery", Message: fmt.Sprintf("VPN backend recovered: %d/%d checks", s.Health, s.Total)})
		}
		prevState = state
	}
	return events
}
func healthState(sample Sample) string {
	// Historical availability is derived from watchdog health status,
	// unlike Overall which also reflects DNS, routing mode and fail-open.
	switch sample.Availability {
	case 100:
		return "healthy"
	case 50:
		return "degraded"
	default:
		return "down"
	}
}

func normalizeEvents(events []Event, limit int) []Event {
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].TS != events[j].TS {
			return events[i].TS < events[j].TS
		}
		return events[i].Type < events[j].Type
	})

	out := make([]Event, 0, len(events))
	for _, e := range events {
		// One failed probe is not a confirmed outage. Keep it in syslog,
		// but do not bury successful failovers under transient noise.
		if e.Type == "health" && strings.HasPrefix(e.Message, "health failed (1/2)") {
			continue
		}
		if len(out) > 0 {
			prev := out[len(out)-1]
			if e.Type == "switch" && prev.Type == "switch" && e.TS-prev.TS < 120 &&
				strings.HasPrefix(e.Message, "Active node -> ") &&
				strings.HasSuffix(prev.Message, strings.TrimPrefix(e.Message, "Active node -> ")) {
				continue
			}
			if e.TS == prev.TS && e.Type == prev.Type && e.Message == prev.Message {
				continue
			}
		}
		out = append(out, e)
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}
