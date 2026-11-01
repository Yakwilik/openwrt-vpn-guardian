package api

import (
	"encoding/json"
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

func TestMakeRoutingResponse(t *testing.T) {
	routing, err := config.RoutingFromRules([]config.RoutingRule{
		{Type: config.RoutingRuleDomain, Value: "jetbrains.com", Note: "JetBrains updates"},
		{Type: config.RoutingRuleIP, Value: "203.0.113.0/24", Note: "Test network"},
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := makeRoutingResponse(routing)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(got.Rules))
	}
	if got.Rules[0].Note != "JetBrains updates" || got.Rules[1].Note != "Test network" {
		t.Fatalf("notes were not preserved: %#v", got.Rules)
	}
	if len(got.Options) != len(config.RoutingRuleOptions()) {
		t.Fatalf("options = %d, want %d", len(got.Options), len(config.RoutingRuleOptions()))
	}
}

func TestDNSControlJSONContract(t *testing.T) {
	body := []byte(`{"action":"dns","dnsMode":"custom","dnsResolvers":["1.1.1.1","9.9.9.9"]}`)
	var req controlRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatal(err)
	}
	if req.DNSMode != "custom" || !slices.Equal(req.DNSResolvers, []string{"1.1.1.1", "9.9.9.9"}) {
		t.Fatalf("decoded DNS request = %#v", req)
	}
	encoded, err := json.Marshal(controlResponse{OK: true, DNS: dnsResponse{Mode: "custom", Resolvers: req.DNSResolvers}})
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		DNS dnsResponse `json:"dns"`
	}
	if err := json.Unmarshal(encoded, &response); err != nil {
		t.Fatal(err)
	}
	if response.DNS.Mode != "custom" || !slices.Equal(response.DNS.Resolvers, req.DNSResolvers) {
		t.Fatalf("encoded DNS response = %#v", response.DNS)
	}
}

func TestRoutingGroupedControlPayloadAndReadback(t *testing.T) {
	previous := config.Routing{Version: config.Version,
		ProxyDomains: []string{"geosite:telegram"},
	}
	requestJSON := []byte(`{"action":"routing","rules":[{"type":"geosite","value":"telegram","group":"telegram"},{"type":"ip","value":"91.108.8.0/22","group":"telegram"}],"groups":[{"id":"telegram","name":"Telegram","description":"Домены и IP Telegram"},{"id":"future","name":"Пустая группа"}]}`)
	var req controlRequest
	if err := json.Unmarshal(requestJSON, &req); err != nil {
		t.Fatal(err)
	}
	if req.Groups == nil || len(*req.Groups) != 2 {
		t.Fatalf("grouped payload was not decoded: %#v", req.Groups)
	}
	routing, err := routingFromRequest(req.Rules, req.Groups, previous)
	if err != nil {
		t.Fatal(err)
	}
	response, err := makeRoutingResponse(routing)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Groups) != 2 || len(response.Rules) != 2 ||
		response.Rules[1].Group != "telegram" {
		t.Fatalf("grouped response changed after save/readback: %#v", response)
	}
}

func TestRoutingLegacyControlPayloadRetainsExistingMembership(t *testing.T) {
	previous, err := config.RoutingFromRulesWithGroups(
		[]config.RoutingRule{{Type: "domain", Value: "example.com", Group: "tools"}},
		[]config.RoutingGroup{{ID: "tools", Name: "Tools"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	next, err := routingFromRequest([]config.RoutingRule{
		{Type: "domain", Value: "example.com", Note: "Updated"},
		{Type: "domain", Value: "new.example.com"},
	}, nil, previous)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := next.Rules()
	if err != nil || rules[0].Group != "tools" || rules[1].Group != "" || len(next.Groups) != 1 {
		t.Fatalf("old client dropped group metadata: %#v, %v", next, err)
	}
	noGroups := []config.RoutingGroup{}
	withoutGroups, err := routingFromRequest(
		[]config.RoutingRule{{Type: "domain", Value: "example.com"}}, &noGroups, previous)
	if err != nil || len(withoutGroups.Groups) != 0 {
		t.Fatalf("explicitly clearing groups did not work: %#v, %v", withoutGroups, err)
	}
}

func TestTrafficModeAPIContractAndInvalidRequests(t *testing.T) {
	var req controlRequest
	if err := json.Unmarshal([]byte(`{"action":"traffic_mode","trafficMode":"full-vpn"}`), &req); err != nil {
		t.Fatal(err)
	}
	if req.TrafficMode != config.TrafficFullVPN {
		t.Fatalf("traffic mode was lost: %+v", req)
	}
	raw, err := json.Marshal(controlResponse{TrafficMode: config.TrafficFullVPN})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["trafficMode"] != "full-vpn" {
		t.Fatal("saved traffic mode absent from control response")
	}
	for _, mode := range []string{"", "garbage", "direct"} {
		if _, err := executeControlAction(controlRequest{Action: "traffic_mode", TrafficMode: mode}); err == nil {
			t.Fatal("invalid traffic mode accepted")
		}
	}
}
