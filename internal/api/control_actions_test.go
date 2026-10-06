package api

import (
	"slices"
	"testing"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
)

func TestMakeSelectionResponse(t *testing.T) {
	stack := config.DefaultStack("br-lan", "192.168.8.0/24", "eth1", "/usr/share/xray")
	stack.Selection.AllowedTransports = []config.Transport{
		config.TransportHysteria2,
		config.TransportVLESSXHTTPReality,
	}

	got := makeSelectionResponse(stack)
	if !slices.Equal(got.AllowedTransports, stack.Selection.AllowedTransports) {
		t.Fatalf("allowed transports = %v, want %v", got.AllowedTransports, stack.Selection.AllowedTransports)
	}
	if len(got.Options) != len(config.TransportOptions()) {
		t.Fatalf("options = %d, want %d", len(got.Options), len(config.TransportOptions()))
	}
}

func TestZapret2CannotBeRestartedFromDashboard(t *testing.T) {
	if restartServiceAllowed("zapret2") {
		t.Fatal("zapret2 is not part of the VPN Guardian dataplane and must not be restartable")
	}
	if restartServiceAllowed("xray") {
		t.Fatal("the generic xray service is outside the VPN Guardian dataplane")
	}
	if !restartServiceAllowed("v2raya") {
		t.Fatal("v2raya restart must remain available")
	}
}
