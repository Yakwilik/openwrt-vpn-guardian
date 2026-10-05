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
