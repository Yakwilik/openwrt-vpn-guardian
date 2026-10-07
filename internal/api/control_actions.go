package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/control"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
	stackruntime "github.com/Yakwilik/openwrt-vpn-guardian/internal/stack"
	v2rayautil "github.com/Yakwilik/openwrt-vpn-guardian/internal/v2raya"
)

func executeControlAction(req controlRequest) (string, error) {
	switch req.Action {
	case "change_pin":
		if len(req.PIN) < 6 {
			return "", errors.New("PIN must be at least 6 characters")
		}
		return "", savePIN(req.PIN)
	case "auto":
		return "", control.SetAutoFront()
	case "direct":
		return "", control.SetDirectFront()
	case "killswitch":
		policy := "failopen"
		if req.Enabled {
			policy = "killswitch"
		}
		return "", control.SetFailurePolicyFront(policy)
	case "switch":
		if req.ID <= 0 {
			return "", errors.New("node id required")
		}
		return "", control.SwitchFront(req.ID, req.Sub, req.NodeKey)
	case "pin":
		if req.ID <= 0 {
			return "", errors.New("node id required")
		}
		return "", control.PinFront(req.ID, req.Sub, req.NodeKey)
	case "reselect":
		return control.ReselectFront()
	case "latency":
		x, err := control.TestLatency()
		if err != nil {
			return "", err
		}
		b, _ := json.Marshal(x)
		return string(b), nil
	case "sub_add":
		return "", control.AddSubscription(req.URL)
	case "sub_update":
		return "", control.UpdateSubscription(req.ID)
	case "sub_edit":
		return "", control.EditSubscription(req.ID, req.URL, req.Remarks, req.AutoSelect)
	case "sub_delete":
		if req.Confirm != "DELETE" {
			return "", errors.New("subscription deletion requires DELETE confirmation")
		}
		if activeSubscriptionMatches(req.ID) {
			if err := control.SetDirectFront(); err != nil {
				return "", fmt.Errorf("protect active subscription before deletion: %w", err)
			}
		}
		return "", control.DeleteSubscription(req.ID)
	case "selection":
		if err := control.SetAllowedTransportsFront(req.Transports); err != nil {
			return "", err
		}
		// Re-evaluate the active backend immediately. Failure to restart is not
		// fatal: the existing daemon will pick up stack.json on its next pass.
		_ = exec.Command(paths.WatchdogServiceInit, "restart").Run()
		return "", nil
	case "routing":
		routing, err := config.RoutingFromRules(req.Rules)
		if err != nil {
			return "", err
		}
		return "", stackruntime.ApplyRouting(routing)
	case "dns":
		return "", stackruntime.ApplyDNS(req.DNSMode, req.DNSResolvers, req.DNSOnlyProxyDomains)
	case "repair":
		ready, err := v2rayautil.RepairBackendListener(true)
		if err != nil {
			return "", err
		}
		if !ready {
			return "", errors.New("backend listener is still unavailable")
		}
		return "", nil
	case "restart":
		return "", restartAllowedService(req.Service)
	default:
		return "", fmt.Errorf("unknown action %q", req.Action)
	}
}

func activeSubscriptionMatches(id int) bool {
	snap, err := control.Snapshot(false)
	if err != nil || snap.Active.Sub < 0 || snap.Active.Sub >= len(snap.Subscriptions) {
		return false
	}
	return snap.Subscriptions[snap.Active.Sub].ID == id
}

func restartAllowedService(name string) error {
	if !restartServiceAllowed(name) {
		return fmt.Errorf("service %q is not allowed", name)
	}
	return restartServiceAPI(name)
}

func restartServiceAllowed(name string) bool {
	return name == "v2raya"
}

func restartServiceAPI(name string) error {
	out, err := exec.Command("/etc/init.d/"+name, "restart").CombinedOutput()
	if err != nil {
		return fmt.Errorf("restart %s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}
