package stack

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/lockfile"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
)

// writeQUICRejectChains implements explicit TCP fallback without silent DROP,
// weakening domain routing, or changing the user's browser settings. Only LAN
// UDP/443 is affected. Router-originated Hysteria/other VPN transports, DNS,
// other UDP ports, private destinations and existing DNAT are unaffected.
// It deliberately rejects *all* public UDP/443, not only sniffable QUIC.
func writeQUICRejectChains(b *strings.Builder, s Stack) {
	if s.Front.QUICMode != "tcp-fallback" {
		return
	}
	for _, hook := range []string{"input", "forward"} {
		fmt.Fprintf(b, "  chain quic_tcp_fallback_%s {\n    type filter hook %s priority filter - 30; policy accept;\n", hook, hook)
		fmt.Fprintf(b, "    iifname %q ct status dnat return\n", s.LANInterface)
		fmt.Fprintf(b, "    iifname %q ip daddr @bypass4 return\n", s.LANInterface)
		fmt.Fprintf(b, "    iifname %q ip6 daddr { ::1/128, fc00::/7, fe80::/10, ff00::/8 } return\n", s.LANInterface)
		fmt.Fprintf(b, "    iifname %q ip saddr %s udp dport 443 counter reject with icmpx type port-unreachable\n", s.LANInterface, s.LANCIDR)
		fmt.Fprintf(b, "    iifname %q meta nfproto ipv6 udp dport 443 counter reject with icmpx type port-unreachable\n", s.LANInterface)
		b.WriteString("  }\n")
	}
}

// ConfigureQUIC exposes the same validated, rollback-safe operation to the
// authenticated management API and the CLI. Both paths hold ControlLock and
// update only the Guardian nft table and its persisted mode.
func ConfigureQUIC(mode string) error {
	return configureQUIC([]string{mode})
}

// configureQUIC changes only our nft table and the persisted manifest. It does
// not restart Xray, DNS, watchdog or v2rayA, nor drop existing TCP connections.
func configureQUIC(args []string) error {
	if len(args) != 1 || (args[0] != "allow" && args[0] != "tcp-fallback") {
		return errors.New("usage: vpn-guardian quic-mode allow|tcp-fallback")
	}
	if os.Geteuid() != 0 {
		return errors.New("quic-mode must run as root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	lock, err := lockfile.Acquire(ctx, paths.ControlLock)
	if err != nil {
		return err
	}
	defer lockfile.Release(lock)
	s, err := config.LoadStack()
	if err != nil {
		return err
	}
	if _, err = os.Stat(paths.FrontEnabled); err != nil {
		return errors.New("Guardian front must be enabled before changing QUIC mode")
	}
	oldStack, err := os.ReadFile(paths.StackConfig)
	if err != nil {
		return err
	}
	oldNFT, err := os.ReadFile(paths.FrontNFT)
	if err != nil {
		return err
	}
	s.Front.QUICMode = args[0]
	if err = s.Validate(); err != nil {
		return err
	}
	nextNFT := []byte(makeNFT(s) + "\n")
	candidate, err := os.CreateTemp("/tmp", "guardian-quic-check-")
	if err != nil {
		return err
	}
	defer os.Remove(candidate.Name())
	if _, err = candidate.Write(nextNFT); err != nil {
		candidate.Close()
		return err
	}
	if err = candidate.Close(); err != nil {
		return err
	}
	if out, e := exec.CommandContext(ctx, "nft", "-c", "-f", candidate.Name()).CombinedOutput(); e != nil {
		return fmt.Errorf("validate QUIC rules: %w: %s", e, out)
	}
	snapshot, err := backup("pre-quic-mode")
	if err != nil {
		return err
	}
	rollback := func(cause error) error {
		a := writePrivateAtomic(paths.StackConfig, oldStack)
		b := writePrivateAtomic(paths.FrontNFT, oldNFT)
		// Independent timeout: the original operation may have expired.
		c, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		out, e := exec.CommandContext(c, "nft", "-f", paths.FrontNFT).CombinedOutput()
		if e != nil {
			e = fmt.Errorf("restore nft rules: %w: %s", e, out)
		}
		return errors.Join(cause, a, b, e)
	}
	if err = config.SaveStack(s); err != nil {
		return err
	}
	if err = writePrivateAtomic(paths.FrontNFT, nextNFT); err != nil {
		return rollback(err)
	}
	if out, e := exec.CommandContext(ctx, "nft", "-f", paths.FrontNFT).CombinedOutput(); e != nil {
		return rollback(fmt.Errorf("activate QUIC mode: %w: %s", e, out))
	}
	fmt.Printf("QUIC mode=%s applied without restarting VPN/DNS; backup=%s\n", args[0], snapshot)
	// Persist the mode change via the existing diagnostics/syslog pipeline;
	// do not log the backup path or any browser/request metadata.
	_ = exec.Command("logger", "-t", "vpn-guardian-control", "QUIC mode changed to "+args[0]).Run()
	return nil
}
