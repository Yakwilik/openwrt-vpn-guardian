package v2raya

import "testing"

func TestClassifyRepair(t *testing.T) {
	tests := []struct {
		name  string
		state RuntimeState
		want  repairAction
	}{
		{
			name: "healthy backend",
			state: RuntimeState{
				Selected: true,
				Manager:  true,
				Core:     true,
				SOCKS:    true,
			},
			want: repairNone,
		},
		{
			name: "no selected node",
			state: RuntimeState{
				Manager:     true,
				Transparent: "close",
				Running:     true,
			},
			want: repairNone,
		},
		{
			name: "manager not running",
			state: RuntimeState{
				Selected:    true,
				Transparent: "close",
				Running:     true,
			},
			want: repairConfigureBackend,
		},
		{
			name: "wrong transparent mode",
			state: RuntimeState{
				Selected:    true,
				Manager:     true,
				Core:        true,
				Transparent: "redirect",
				Running:     true,
			},
			want: repairConfigureBackend,
		},
		{
			name: "backend marked stopped",
			state: RuntimeState{
				Selected:    true,
				Manager:     true,
				Core:        true,
				Transparent: "close",
				Running:     false,
			},
			want: repairConfigureBackend,
		},
		{
			name: "core missing",
			state: RuntimeState{
				Selected:    true,
				Manager:     true,
				Core:        false,
				SOCKS:       false,
				Transparent: "close",
				Running:     true,
			},
			want: repairRestartManager,
		},
		{
			name: "core process alive but listener missing",
			state: RuntimeState{
				Selected:    true,
				Manager:     true,
				Core:        true,
				SOCKS:       false,
				Transparent: "close",
				Running:     true,
			},
			want: repairRestartManager,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyRepair(tt.state); got != tt.want {
				t.Fatalf("classifyRepair(%+v) = %v, want %v", tt.state, got, tt.want)
			}
		})
	}
}

func TestBackendOnlyPreparationDoesNotRequireCore(t *testing.T) {
	tests := []struct {
		name  string
		state RuntimeState
		ready bool
	}{
		{"fresh manager without nodes", RuntimeState{Manager: true, Transparent: "close"}, true},
		{"selected node with stopped core", RuntimeState{Manager: true, Transparent: "close", Selected: true}, true},
		{"healthy backend", RuntimeState{Manager: true, Transparent: "close", Running: true, Selected: true, Core: true, SOCKS: true}, true},
		{"manager missing", RuntimeState{Transparent: "close", Running: true}, false},
		{"transparent interception enabled", RuntimeState{Manager: true, Transparent: "global", Running: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := backendOnlyReady(tt.state); got != tt.ready {
				t.Fatalf("backendOnlyReady(%+v) = %v, want %v", tt.state, got, tt.ready)
			}
		})
	}
	stopped := RuntimeState{Manager: true, Transparent: "close", Selected: true}
	if classifyRepair(stopped) == repairNone {
		t.Fatal("a prepared manager with a stopped selected core still needs backend repair")
	}
}
