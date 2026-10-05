package watchdog

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/netstate"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
)

type frontRecoveryAction uint8

const (
	frontRecoveryNone frontRecoveryAction = iota
	frontRecoveryDisableInterception
	frontRecoveryEnableInterception
	frontRecoveryRestartFront
)

func classifyFrontRecovery(enabled, listening, routingReady, routingPresent bool) frontRecoveryAction {
	switch {
	case !enabled && routingPresent:
		return frontRecoveryDisableInterception
	case !enabled:
		return frontRecoveryNone
	case !listening:
		return frontRecoveryRestartFront
	case !routingReady:
		return frontRecoveryEnableInterception
	default:
		return frontRecoveryNone
	}
}

func frontFailureMayBypass(ctrl Control) bool {
	return ctrl.Mode == "direct" || ctrl.FailurePolicy == "failopen"
}

func frontEnabled() bool {
	_, err := os.Stat(paths.FrontEnabled)
	return err == nil
}

func frontRoutingState(cfg config.Stack) (ready, present bool) {
	_, nftErr := frontCommand("nft", "list", "table", "inet", "vpn_front")
	nftPresent := nftErr == nil

	rules, _ := frontCommand("ip", "rule", "show")
	ruleText := string(rules)
	rulePresent := strings.Contains(ruleText, fmt.Sprintf("lookup %d", cfg.Front.RouteTable))

	route, _ := frontCommand("ip", "route", "show", "table", fmt.Sprint(cfg.Front.RouteTable))
	routePresent := strings.Contains(string(route), "local default dev lo")

	present = nftPresent || rulePresent || routePresent
	ready = nftPresent && rulePresent && routePresent
	return ready, present
}

func disableFrontInterception(cfg config.Stack) {
	_, _ = frontCommand("/etc/init.d/vpn-front-routing", "stop")
	_, _ = frontCommand("nft", "delete", "table", "inet", "vpn_front")
	for i := 0; i < 4; i++ {
		_, _ = frontCommand("ip", "rule", "del", "priority", "5", "fwmark", fmt.Sprintf("0x%x/0x%x", cfg.Front.Mark, cfg.Front.Mark), "table", fmt.Sprint(cfg.Front.RouteTable))
	}
	_, _ = frontCommand("ip", "route", "flush", "table", fmt.Sprint(cfg.Front.RouteTable))
}

func enableFrontInterception() error {
	out, err := frontCommand("/etc/init.d/vpn-front-routing", "reload")
	if err != nil {
		return fmt.Errorf("reload vpn-front-routing: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func restartFront() error {
	out, err := frontCommand("/etc/init.d/vpn-front", "restart")
	if err != nil {
		return fmt.Errorf("restart vpn-front: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func waitFrontListener(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if netstate.TCPListening(port) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func ensureFrontInvariant(ctrl Control) error {
	cfg, err := config.LoadStack()
	if err != nil {
		return fmt.Errorf("load stack config for front invariant: %w", err)
	}

	enabled := frontEnabled()
	listening := netstate.TCPListening(cfg.Front.TProxyPort)
	routingReady, routingPresent := frontRoutingState(cfg)

	switch classifyFrontRecovery(enabled, listening, routingReady, routingPresent) {
	case frontRecoveryNone:
		return nil

	case frontRecoveryDisableInterception:
		logLine("front disabled with stale routing state; removing interception")
		disableFrontInterception(cfg)
		return nil

	case frontRecoveryEnableInterception:
		logLine("front listener healthy but routing inactive; restoring interception")
		if err := enableFrontInterception(); err != nil {
			return err
		}
		return nil

	case frontRecoveryRestartFront:
		failOpen := frontFailureMayBypass(ctrl)
		if !failOpen && !routingReady {
			if err := enableFrontInterception(); err != nil {
				return fmt.Errorf("restore VPN-only guard before recovery: %w", err)
			}
			routingReady, routingPresent = frontRoutingState(cfg)
			if !routingReady {
				return fmt.Errorf("VPN-only routing guard could not be verified")
			}
		}

		if failOpen && routingPresent {
			logLine("front listener missing in fail-open mode; disabling interception before recovery")
			disableFrontInterception(cfg)
			routingPresent = false
		} else if routingPresent {
			logLine("front listener missing in VPN-only mode; keeping interception active while recovering front")
		} else {
			logLine("front listener missing; routing is inactive while front recovers")
		}

		if err := restartFront(); err != nil {
			return err
		}
		if !waitFrontListener(cfg.Front.TProxyPort, 5*time.Second) {
			if failOpen {
				return fmt.Errorf("vpn-front did not restore TCP listener on port %d; fail-open routing remains disabled", cfg.Front.TProxyPort)
			}
			return fmt.Errorf("vpn-front did not restore TCP listener on port %d; VPN-only interception remains active", cfg.Front.TProxyPort)
		}

		routingReady, _ = frontRoutingState(cfg)
		if !routingReady {
			if err := enableFrontInterception(); err != nil {
				return err
			}
		}
		logLine("front listener recovered; routing ready")
		return nil

	default:
		return nil
	}
}

// frontCommand bounds every operating-system operation in the recovery loop.
func frontCommand(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}
