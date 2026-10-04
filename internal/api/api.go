package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	cachePath   = "/tmp/vpn-status-cache.json"
	historyPath = "/tmp/vpn-dashboard-history.tsv"
	eventPath   = "/tmp/vpn-dashboard-events.tsv"
)

type Sample struct {
	TS           int64  `json:"ts"`
	Availability int    `json:"availability"`
	Health       int    `json:"health"`
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

func Run(args []string) {
	if len(args) == 0 {
		writeError(400, "api command required")
		return
	}
	switch args[0] {
	case "status":
		StatusCGI()
	case "history":
		HistoryCGI()
	case "control":
		ControlCGI()
	default:
		writeError(404, "unknown api command")
	}
}

func StatusCGI() {
	b, err := os.ReadFile(cachePath)
	if err != nil {
		writeError(503, "status cache unavailable")
		return
	}
	writeHeaders(200)
	_, _ = os.Stdout.Write(b)
}

func HistoryCGI() {
	samples, _ := readSamples(historyPath, 1440)
	events, _ := readEvents(eventPath, 500)
	events = append(events, reconstructEvents(samples)...)
	events = normalizeEvents(events, 500)

	_, offset := time.Now().Zone()
	writeJSON(200, HistoryResponse{
		RouterTZOffset: offset,
		Samples:        samples,
		Events:         events,
	})
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
		parts := strings.SplitN(sc.Text(), "\t", 7)
		if len(parts) != 7 {
			continue
		}
		ts, _ := strconv.ParseInt(parts[0], 10, 64)
		health, _ := strconv.Atoi(parts[2])
		switchFlag, _ := strconv.Atoi(parts[5])
		if ts <= 0 {
			continue
		}
		failed := 4 - health
		if failed < 0 {
			failed = 0
		}
		availability := 0
		if health >= 2 {
			availability = 100
		} else if health > 0 {
			availability = health * 25
		}
		overall := "down"
		if health >= 3 {
			overall = "ok"
		} else if health == 2 {
			overall = "degraded"
		}
		rows = append(rows, Sample{TS: ts, Availability: availability, Health: health, Failed: failed, Overall: overall, Switch: switchFlag, Node: parts[6]})
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
	prevState := healthState(samples[0].Health)
	for i, s := range samples {
		if s.Switch == 1 {
			events = append(events, Event{TS: s.TS, Type: "switch", Message: "Active node -> " + s.Node})
		}
		state := healthState(s.Health)
		if i == 0 {
			if state == "down" {
				events = append(events, Event{TS: s.TS, Type: "outage", Message: fmt.Sprintf("VPN backend unavailable: %d/4 checks", s.Health)})
			} else if state == "degraded" {
				events = append(events, Event{TS: s.TS, Type: "health", Message: fmt.Sprintf("VPN backend degraded: %d/4 checks", s.Health)})
			}
			continue
		}
		if state == prevState {
			continue
		}
		switch state {
		case "down":
			events = append(events, Event{TS: s.TS, Type: "outage", Message: fmt.Sprintf("VPN backend unavailable: %d/4 checks", s.Health)})
		case "degraded":
			events = append(events, Event{TS: s.TS, Type: "health", Message: fmt.Sprintf("VPN backend degraded: %d/4 checks", s.Health)})
		case "healthy":
			events = append(events, Event{TS: s.TS, Type: "recovery", Message: fmt.Sprintf("VPN backend recovered: %d/4 checks", s.Health)})
		}
		prevState = state
	}
	return events
}
func healthState(passed int) string {
	if passed <= 1 {
		return "down"
	}
	if passed == 2 {
		return "degraded"
	}
	return "healthy"
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
		if len(out) > 0 {
			prev := out[len(out)-1]
			if e.Type == "switch" && prev.Type == "switch" && e.TS-prev.TS < 120 {
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

func writeHeaders(status int) {
	fmt.Printf("Status: %d\r\n", status)
	fmt.Print("Content-Type: application/json\r\n")
	fmt.Print("Cache-Control: no-store\r\n\r\n")
}

func writeJSON(status int, v any) {
	writeHeaders(status)
	_ = json.NewEncoder(os.Stdout).Encode(v)
}

func writeError(status int, message string) {
	writeJSON(status, map[string]any{"ok": false, "error": message})
}
