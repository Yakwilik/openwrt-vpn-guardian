package stack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/dnsfront"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/dnsproxy"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/lockfile"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
)

func makeFront(s Stack, r Routing) map[string]any {
	front := makeSelectiveFront(s, r)
	if !s.FullVPN() {
		return front
	}
	// No sniffing or domain match is needed in full mode. Keep the original
	// destination, including when TLS hides SNI or a connection is reused.
	for _, value := range front["inbounds"].([]any) {
		delete(value.(map[string]any), "sniffing")
	}
	outbounds := front["outbounds"].([]any)
	// Bypass the fail-open/Direct policy gateway deliberately: full VPN has
	// no direct Internet fallback, even during watchdog policy transitions.
	outbounds[1] = map[string]any{"tag": "full-vpn", "protocol": "socks", "settings": map[string]any{
		"servers": []any{map[string]any{"address": "127.0.0.1", "port": s.Backend.SocksPort}},
	}}
	private := append(append([]string(nil), s.Bypass4...), "::1/128", "fc00::/7", "fe80::/10", "ff00::/8")
	front["routing"] = map[string]any{"domainStrategy": "AsIs", "rules": []any{
		map[string]any{"type": "field", "inboundTag": []string{"front-tproxy"}, "ip": []string{"127.0.0.0/8", "::1/128"}, "outboundTag": "blocked"},
		map[string]any{"type": "field", "ip": private, "outboundTag": "direct"},
		map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "full-vpn"},
	}}
	return front
}

// The current front intercepts IPv4 TCP/UDP only. Never market an unprotected
// IPv6/ICMP forward path as full VPN: refuse external forwarded traffic that
// was not consumed by TPROXY. Private networks and DNAT replies stay usable.
func writeFullVPNGuard(b *strings.Builder, s Stack) {
	if !s.FullVPN() {
		return
	}
	b.WriteString("  chain full_vpn_forward_guard {\n    type filter hook forward priority filter - 25; policy accept;\n")
	fmt.Fprintf(b, "    iifname %q ct status dnat return\n", s.LANInterface)
	fmt.Fprintf(b, "    iifname %q ip daddr @bypass4 return\n", s.LANInterface)
	fmt.Fprintf(b, "    iifname %q ip6 daddr { ::1/128, fc00::/7, fe80::/10, ff00::/8 } return\n", s.LANInterface)
	fmt.Fprintf(b, "    iifname %q counter reject with icmpx type admin-prohibited\n", s.LANInterface)
	b.WriteString("  }\n")
}

// ConfigureTrafficMode preserves routing.json, saved DNS preferences, the VPN
// node and QUIC mode. Only vpn-front restarts; backend/policy remain running.
// All candidates are validated before activation. DNS uses a protected union
// until both consumers converge, and rollback narrows DNS only on success.
func ConfigureTrafficMode(mode string) error {
	if mode != config.TrafficSelective && mode != config.TrafficFullVPN {
		return errors.New("traffic mode must be selective or full-vpn")
	}
	if os.Geteuid() != 0 {
		return errors.New("traffic-mode must run as root")
	}
	lockCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	lock, err := lockfile.Acquire(lockCtx, paths.ControlLock)
	if err != nil {
		return err
	}
	defer lockfile.Release(lock)
	if _, err := os.Stat(paths.FrontEnabled); err != nil {
		return errors.New("Guardian front must be enabled")
	}
	previous, rules, err := config.Load()
	if err != nil {
		return err
	}
	if mode == config.TrafficFullVPN {
		var ctl struct {
			Mode string `json:"mode"`
		}
		data, err := os.ReadFile(paths.ControlConfig)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &ctl); err != nil {
			return err
		}
		if ctl.Mode != "auto" && ctl.Mode != "pinned" {
			return errors.New("switch to Auto or pin a VPN node before enabling full VPN")
		}
	}
	next := previous
	next.Front.TrafficMode = mode
	if err := next.Validate(); err != nil {
		return err
	}
	if _, err := dnsproxy.BuildRuntime(next, rules, "/"); err != nil {
		return err
	}
	oldSelectors, err := os.ReadFile(dnsfront.SelectorsPath)
	if err != nil {
		return err
	}
	selectors, err := dnsSelectors(next, rules)
	if err != nil {
		return err
	}
	transition, err := transitionDNSSelectors(previous, rules, next, rules)
	if err != nil {
		return err
	}
	if err := dnsfront.ValidateSelectors(next.DNS.ListenPort, selectors); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("/tmp", "guardian-traffic-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	frontFile := filepath.Join(dir, "front.json")
	nftFile := filepath.Join(dir, "front.nft")
	if err := jsonWrite(frontFile, makeFront(next, rules)); err != nil {
		return err
	}
	if err := os.WriteFile(nftFile, []byte(makeNFT(next)+"\n"), 0600); err != nil {
		return err
	}
	ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	xray := exec.CommandContext(ctx, "/usr/bin/xray", "run", "-test", "-config", frontFile)
	xray.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+next.AssetsDir)
	if out, err := xray.CombinedOutput(); err != nil {
		return fmt.Errorf("validate traffic front: %w: %s", err, out)
	}
	if out, err := exec.CommandContext(ctx, "nft", "-c", "-f", nftFile).CombinedOutput(); err != nil {
		return fmt.Errorf("validate traffic firewall: %w: %s", err, out)
	}
	oldStack, err := os.ReadFile(paths.StackConfig)
	if err != nil {
		return err
	}
	oldFront, err := os.ReadFile(paths.FrontConfig)
	if err != nil {
		return err
	}
	oldNFT, err := os.ReadFile(paths.FrontNFT)
	if err != nil {
		return err
	}
	if _, err := backup("pre-traffic-mode"); err != nil {
		return err
	}
	rollback := func(cause error) error {
		restoreErr := errors.Join(writePrivateAtomic(paths.StackConfig, oldStack), writePrivateAtomic(paths.FrontConfig, oldFront), writePrivateAtomic(paths.FrontNFT, oldNFT))
		if restoreErr != nil {
			return errors.Join(cause, restoreErr)
		}
		reloadCtx, finish := context.WithTimeout(context.Background(), 8*time.Second)
		defer finish()
		dnsErr := dnsproxy.Reload(reloadCtx)
		_, frontErr := run(paths.FrontServiceInit, "restart")
		_, nftErr := run("nft", "-f", paths.FrontNFT)
		restoreErr = errors.Join(dnsErr, frontErr, nftErr)
		if restoreErr == nil {
			restoreErr = dnsfront.UpdateSelectors(previous.DNS.ListenPort, oldSelectors)
		}
		return errors.Join(cause, restoreErr)
	}
	if err := dnsfront.UpdateSelectors(next.DNS.ListenPort, transition); err != nil {
		return err
	}
	if err := config.SaveStack(next); err != nil {
		return rollback(err)
	}
	if err := copyAtomic(frontFile, paths.FrontConfig, 0600); err != nil {
		return rollback(err)
	}
	if err := copyAtomic(nftFile, paths.FrontNFT, 0600); err != nil {
		return rollback(err)
	}
	if out, err := run("nft", "-f", paths.FrontNFT); err != nil {
		return rollback(fmt.Errorf("activate traffic firewall: %w: %s", err, out))
	}
	reloadCtx, finish := context.WithTimeout(context.Background(), 8*time.Second)
	defer finish()
	if err := dnsproxy.Reload(reloadCtx); err != nil {
		return rollback(err)
	}
	if out, err := run(paths.FrontServiceInit, "restart"); err != nil {
		return rollback(fmt.Errorf("activate traffic front: %w: %s", err, out))
	}
	ready := false
	for until := time.Now().Add(5 * time.Second); time.Now().Before(until); {
		if tcpReady(fmt.Sprintf("127.0.0.1:%d", next.Front.SocksPort), 250*time.Millisecond) {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		return rollback(errors.New("new traffic front did not start"))
	}
	if err := dnsfront.UpdateSelectors(next.DNS.ListenPort, selectors); err != nil {
		return rollback(err)
	}
	_ = exec.Command("logger", "-t", "vpn-guardian-control", "Traffic mode changed to "+mode).Run()
	return nil
}
