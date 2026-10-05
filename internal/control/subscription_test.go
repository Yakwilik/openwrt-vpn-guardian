package control

import "testing"

func TestSubscriptionInfoFromMap(t *testing.T) {
	tests := []struct {
		name           string
		input          map[string]any
		includeSecrets bool
		wantName       string
		wantAddress    string
		wantHost       string
		wantInfo       string
		wantRemarks    string
		wantNodes      int
	}{
		{
			name: "remarks wins",
			input: map[string]any{
				"id":         float64(1),
				"remarks":    "Primary",
				"host":       "sub.example.com",
				"info":       "Expires tomorrow",
				"address":    "https://secret.example/sub",
				"autoSelect": true,
				"servers":    []any{map[string]any{}, map[string]any{}},
			},
			includeSecrets: true,
			wantName:       "Primary",
			wantAddress:    "https://secret.example/sub",
			wantHost:       "sub.example.com",
			wantInfo:       "Expires tomorrow",
			wantRemarks:    "Primary",
			wantNodes:      2,
		},
		{
			name: "nil remarks fall back to host",
			input: map[string]any{
				"id":      float64(2),
				"remarks": nil,
				"host":    "your-durev.com",
				"info":    "Expires 2027-04-06",
				"address": "https://secret.example/sub",
				"servers": []any{map[string]any{}},
			},
			wantName:    "your-durev.com",
			wantHost:    "your-durev.com",
			wantInfo:    "Expires 2027-04-06",
			wantRemarks: "",
			wantAddress: "",
			wantNodes:   1,
		},
		{
			name: "missing display fields fall back to id",
			input: map[string]any{
				"id":      "7",
				"remarks": nil,
				"host":    nil,
				"info":    nil,
			},
			wantName: "Subscription #7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := subscriptionInfoFromMap(tt.input, tt.includeSecrets)
			if got.Name != tt.wantName {
				t.Fatalf("Name = %q, want %q", got.Name, tt.wantName)
			}
			if got.Address != tt.wantAddress {
				t.Fatalf("Address = %q, want %q", got.Address, tt.wantAddress)
			}
			if got.Host != tt.wantHost {
				t.Fatalf("Host = %q, want %q", got.Host, tt.wantHost)
			}
			if got.Info != tt.wantInfo {
				t.Fatalf("Info = %q, want %q", got.Info, tt.wantInfo)
			}
			if got.Remarks != tt.wantRemarks {
				t.Fatalf("Remarks = %q, want %q", got.Remarks, tt.wantRemarks)
			}
			if got.NodeCount != tt.wantNodes {
				t.Fatalf("NodeCount = %d, want %d", got.NodeCount, tt.wantNodes)
			}
			for field, value := range map[string]string{
				"name": got.Name, "address": got.Address, "host": got.Host,
				"info": got.Info, "remarks": got.Remarks,
			} {
				if value == "<nil>" {
					t.Fatalf("%s leaked <nil>", field)
				}
			}
		})
	}
}
