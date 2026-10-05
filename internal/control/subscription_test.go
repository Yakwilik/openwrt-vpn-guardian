package control

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSubscriptionInfoFromMap(t *testing.T) {
	tests := []struct {
		name           string
		input          map[string]any
		includeSecrets bool
		want           SubscriptionInfo
	}{
		{
			name: "remarks take precedence and strings are trimmed",
			input: map[string]any{
				"id":         float64(1),
				"remarks":    " Primary ",
				"host":       " sub.example.test ",
				"info":       " Expires tomorrow ",
				"address":    " https://subscription.example.test/secret ",
				"autoSelect": true,
				"servers":    []any{map[string]any{}, map[string]any{}},
			},
			includeSecrets: true,
			want: SubscriptionInfo{
				ID: 1, Name: "Primary", Address: "https://subscription.example.test/secret",
				Host: "sub.example.test", Info: "Expires tomorrow", Remarks: "Primary",
				AutoSelect: true, NodeCount: 2,
			},
		},
		{
			name: "null remarks fall back to host and secrets are excluded",
			input: map[string]any{
				"id":      float64(2),
				"remarks": nil,
				"host":    "your-durev.com",
				"info":    "Expires 2027-04-06",
				"address": "https://subscription.example.test/secret",
				"servers": []any{map[string]any{}},
			},
			want: SubscriptionInfo{
				ID: 2, Name: "your-durev.com", Host: "your-durev.com",
				Info: "Expires 2027-04-06", NodeCount: 1,
			},
		},
		{
			name: "empty remarks fall back to host",
			input: map[string]any{
				"id": float64(3), "remarks": "", "host": "sub.example.test",
			},
			want: SubscriptionInfo{ID: 3, Name: "sub.example.test", Host: "sub.example.test"},
		},
		{
			name: "whitespace remarks fall back to trimmed host",
			input: map[string]any{
				"id": float64(4), "remarks": " \t\n", "host": " sub.example.test ",
				"info": " \t\n", "address": " \t\n",
			},
			includeSecrets: true,
			want:           SubscriptionInfo{ID: 4, Name: "sub.example.test", Host: "sub.example.test"},
		},
		{
			name:           "missing optional fields become empty strings",
			input:          map[string]any{"id": "7"},
			includeSecrets: true,
			want:           SubscriptionInfo{ID: 7, Name: "Subscription #7"},
		},
		{
			name: "null optional fields become empty strings",
			input: map[string]any{
				"id": float64(8), "remarks": nil, "host": nil, "info": nil, "address": nil,
			},
			includeSecrets: true,
			want:           SubscriptionInfo{ID: 8, Name: "Subscription #8"},
		},
		{
			name: "empty display fields fall back to id",
			input: map[string]any{
				"id": float64(9), "remarks": "", "host": " \t", "info": "", "address": "",
			},
			includeSecrets: true,
			want:           SubscriptionInfo{ID: 9, Name: "Subscription #9"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := subscriptionInfoFromMap(tt.input, tt.includeSecrets); got != tt.want {
				t.Fatalf("subscriptionInfoFromMap() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestSubscriptionInfoFromMapRejectsNonStringFields(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{name: "number", value: float64(42)},
		{name: "boolean", value: true},
		{name: "object", value: map[string]any{"token": "fixture-object-secret"}},
		{name: "array", value: []any{"fixture-array-secret"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := map[string]any{
				"id": float64(17), "remarks": tt.value, "host": tt.value,
				"info": tt.value, "address": tt.value,
			}
			want := SubscriptionInfo{ID: 17, Name: "Subscription #17"}
			if got := subscriptionInfoFromMap(input, true); got != want {
				t.Fatalf("subscriptionInfoFromMap() = %#v, want %#v", got, want)
			}
		})
	}
}

func TestSubscriptionSnapshotJSONContract(t *testing.T) {
	// Subscription URLs are synthetic; only display fields mirror the regression.
	const source = `[
		{
			"id": 1, "host": "sub.conn-liberty.net", "remarks": null,
			"info": "Used 0.00 GiB · Expires 2026-11-16",
			"address": "https://subscription.example.test/first?token=fixture-first-secret"
		},
		{
			"id": 2, "host": "your-durev.com", "remarks": null,
			"info": "Expires 2027-04-06",
			"address": "https://subscription.example.test/second?token=fixture-second-secret"
		}
	]`
	var upstream []map[string]any
	if err := json.Unmarshal([]byte(source), &upstream); err != nil {
		t.Fatal(err)
	}

	for _, mode := range []struct {
		name           string
		includeSecrets bool
	}{
		{name: "read only"},
		{name: "authenticated", includeSecrets: true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			var snapshot FrontSnapshot
			for _, input := range upstream {
				snapshot.Subscriptions = append(snapshot.Subscriptions, subscriptionInfoFromMap(input, mode.includeSecrets))
			}
			data, err := json.Marshal(snapshot)
			if err != nil {
				t.Fatal(err)
			}

			// Decode the wire representation: encoding/json escapes "<nil>".
			var decoded struct {
				Subscriptions []map[string]any `json:"subscriptions"`
			}
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			if len(decoded.Subscriptions) != len(upstream) {
				t.Fatalf("subscriptions count = %d, want %d", len(decoded.Subscriptions), len(upstream))
			}
			for i, sub := range decoded.Subscriptions {
				for field, want := range map[string]string{
					"name": upstream[i]["host"].(string), "host": upstream[i]["host"].(string),
					"info": upstream[i]["info"].(string), "remarks": "",
				} {
					if got, ok := sub[field].(string); !ok || got != want {
						t.Errorf("subscriptions[%d].%s = %#v, want %q", i, field, sub[field], want)
					}
				}
				address, present := sub["address"]
				if mode.includeSecrets {
					if !present || address != upstream[i]["address"] {
						t.Errorf("subscriptions[%d].address = %#v, want fixture URL", i, address)
					}
				} else if present {
					t.Errorf("read-only subscriptions[%d] contains address key", i)
				}
			}
			if !mode.includeSecrets {
				for _, secret := range []string{"fixture-first-secret", "fixture-second-secret", "subscription.example.test"} {
					if strings.Contains(string(data), secret) {
						t.Errorf("read-only snapshot contains secret %q", secret)
					}
				}
			}
		})
	}
}
