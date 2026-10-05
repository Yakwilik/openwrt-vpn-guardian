package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSelectionValidation(t *testing.T) {
	tests := []struct {
		name    string
		allowed []Transport
		wantErr string
	}{
		{"all supported", SupportedTransports(), ""},
		{"single supported", []Transport{TransportVLESSXHTTPReality}, ""},
		{"missing", nil, "at least one"},
		{"empty", []Transport{}, "at least one"},
		{"unknown", []Transport{"vless-grpc-tls"}, "unsupported"},
		{"empty identifier", []Transport{""}, "unsupported"},
		{"noncanonical case", []Transport{"HYSTERIA2"}, "unsupported"},
		{"whitespace", []Transport{" hysteria2 "}, "unsupported"},
		{"duplicate", []Transport{TransportHysteria2, TransportHysteria2}, "duplicate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := (Selection{AllowedTransports: tt.allowed}).Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("valid selection rejected: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadFilesRequiresExplicitSelection(t *testing.T) {
	tests := []struct {
		name  string
		value any
		omit  bool
	}{
		{"missing selection", nil, true},
		{"null selection", nil, false},
		{"missing allowlist", map[string]any{}, false},
		{"null allowlist", map[string]any{"allowedTransports": nil}, false},
		{"empty allowlist", map[string]any{"allowedTransports": []string{}}, false},
		{"unknown transport", map[string]any{"allowedTransports": []string{"vmess"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stack := DefaultStack("br-lan", "192.168.1.0/24", "eth0", "/usr/share/xray")
			data, err := json.Marshal(stack)
			if err != nil {
				t.Fatal(err)
			}
			var manifest map[string]any
			if err := json.Unmarshal(data, &manifest); err != nil {
				t.Fatal(err)
			}
			if tt.omit {
				delete(manifest, "selection")
			} else {
				manifest["selection"] = tt.value
			}
			dir := t.TempDir()
			stackPath := filepath.Join(dir, "stack.json")
			routingPath := filepath.Join(dir, "routing.json")
			writeTestJSON(t, stackPath, manifest)
			writeTestJSON(t, routingPath, DefaultRouting())
			if _, _, err := LoadFiles(stackPath, routingPath); err == nil || !strings.Contains(err.Error(), "selection.allowedTransports") {
				t.Fatalf("LoadFiles error = %v, want explicit selection requirement", err)
			}
		})
	}
}

func TestLoadFilesPreservesRestrictedSelection(t *testing.T) {
	stack := DefaultStack("br-lan", "192.168.1.0/24", "eth0", "/usr/share/xray")
	stack.Selection.AllowedTransports = []Transport{TransportVLESSTCPReality}
	dir := t.TempDir()
	stackPath := filepath.Join(dir, "stack.json")
	routingPath := filepath.Join(dir, "routing.json")
	writeTestJSON(t, stackPath, stack)
	writeTestJSON(t, routingPath, DefaultRouting())
	got, _, err := LoadFiles(stackPath, routingPath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Selection, stack.Selection) {
		t.Fatalf("loaded selection = %+v, want %+v", got.Selection, stack.Selection)
	}
}

func TestTransportCatalogueIsIndependent(t *testing.T) {
	first := TransportOptions()
	if len(first) == 0 {
		t.Fatal("empty transport catalogue")
	}
	original := first[0]
	first[0] = TransportOption{Value: "changed", Label: "changed"}
	if got := TransportOptions()[0]; got != original {
		t.Fatalf("catalogue can be mutated by caller: %+v", got)
	}
	for _, option := range TransportOptions() {
		if option.Label == "" {
			t.Fatalf("transport %q has no wizard label", option.Value)
		}
		if err := (Selection{AllowedTransports: []Transport{option.Value}}).Validate(); err != nil {
			t.Fatalf("catalogue contains invalid option: %v", err)
		}
	}
}

func writeTestJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
