package stack

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/dnsfront"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/dnsproxy"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/lockfile"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/policy"
)

// InstallDNSRuntime upgrades the dnsmasq-first integration, DNS dispatcher,
// DNS-only Xray and the policy variants needed by that architecture. It never
// rewrites/restarts vpn-front or v2rayA and never changes the management
// firewall or IP policy routes. vpn-policy is restarted only when its generated
// policy schema actually changed. Native dnsmasq stays on :53; router bootstrap
// is independently fed by the preserved system/WAN DNS sources.
func InstallDNSRuntime() error {
	if _, err := os.Stat(paths.FrontEnabled); err != nil {
		return errors.New("DNS-only upgrade requires an initialized active stack")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	lock, err := lockfile.Acquire(ctx, paths.ControlLock)
	if err != nil {
		return err
	}
	defer lockfile.Release(lock)
	s, r, err := config.Load()
	if err != nil {
		return err
	}
	frontendBefore, err := dnsfront.Capture()
	if err != nil {
		return err
	}
	if _, err := dnsproxy.BuildRuntime(s, r, "/"); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "guardian-dns-install-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	xr := filepath.Join(dir, "dns-xray.json")
	if err := jsonWrite(xr, makeDNSXray(s)); err != nil {
		return err
	}
	policyConfigs := []struct {
		path string
		mode string
	}{
		{paths.PolicyFailOpen, "failopen"},
		{paths.PolicyFailOpenDirect, "failopen-direct"},
		{paths.PolicyVPNOnly, "killswitch"},
		{paths.PolicyBlocked, "killswitch-blocked"},
		{paths.PolicyDirect, "direct"},
	}
	for _, item := range policyConfigs {
		target := filepath.Join(dir, filepath.Base(item.path))
		if err := jsonWrite(target, makePolicy(s, item.mode)); err != nil {
			return err
		}
	}
	for _, target := range append([]string{xr}, func() []string {
		result := make([]string, 0, len(policyConfigs))
		for _, item := range policyConfigs {
			result = append(result, filepath.Join(dir, filepath.Base(item.path)))
		}
		return result
	}()...) {
		if out, err := run("/usr/bin/xray", "run", "-test", "-config", target); err != nil {
			return fmt.Errorf("Xray config %s: %w: %s", filepath.Base(target), err, out)
		}
	}
	nft := filepath.Join(dir, "front.nft")
	if err := os.WriteFile(nft, []byte(makeNFT(s)), 0600); err != nil {
		return err
	}
	if out, err := run("nft", "-c", "-f", nft); err != nil {
		return fmt.Errorf("DNS interception validation: %w: %s", err, out)
	}
	scripts := map[string]string{"dns.init": makeDNSInit(s), "dns-xray.init": makeXrayInit("vpn-dns-xray", paths.DNSXrayConfig, s.AssetsDir, 97, 8)}
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0755); err != nil {
			return err
		}
	}
	files := []struct {
		src, dst string
		mode     os.FileMode
	}{
		{xr, paths.DNSXrayConfig, 0600},
		{filepath.Join(dir, "dns.init"), paths.DNSServiceInit, 0755},
		{filepath.Join(dir, "dns-xray.init"), paths.DNSXrayServiceInit, 0755},
		{nft, paths.FrontNFT, 0600},
	}
	for _, item := range policyConfigs {
		files = append(files, struct {
			src, dst string
			mode     os.FileMode
		}{filepath.Join(dir, filepath.Base(item.path)), item.path, 0600})
	}
	runtimeMode := policy.Runtime()
	policyChanged := false
	for _, item := range policyConfigs {
		want, readErr := os.ReadFile(filepath.Join(dir, filepath.Base(item.path)))
		have, haveErr := os.ReadFile(item.path)
		if readErr != nil || haveErr != nil || string(want) != string(have) {
			policyChanged = true
			break
		}
	}
	previous := make([]setupFile, 0, len(files))
	for _, file := range files {
		f, err := captureSetupFile(file.dst)
		if err != nil {
			return err
		}
		previous = append(previous, f)
	}
	rollback := func(cause error) error {
		cause = errors.Join(cause, dnsfront.RestoreCheckpoint(frontendBefore))
		for i, p := range previous {
			if p.exists {
				cause = errors.Join(cause, writePrivateAtomic(p.path, p.data))
				_ = os.Chmod(p.path, files[i].mode)
			} else {
				_ = os.Remove(p.path)
			}
		}
		if previous[len(previous)-1].exists {
			_, e := run("nft", "-f", paths.FrontNFT)
			cause = errors.Join(cause, e)
		}
		if policyChanged {
			cause = errors.Join(cause, policy.Apply(runtimeMode))
		}
		_, e := run(paths.DNSServiceInit, "restart")
		return errors.Join(cause, e)
	}
	for _, file := range files {
		if err := copyAtomic(file.src, file.dst, file.mode); err != nil {
			return rollback(err)
		}
	}
	if policyChanged {
		if err := policy.Apply(runtimeMode); err != nil {
			return rollback(fmt.Errorf("activate migrated policy runtime %s: %w", runtimeMode, err))
		}
	}
	if err := syncDNSXrayService(s); err != nil {
		return rollback(err)
	}
	if err := startDNSProxy(s); err != nil {
		return rollback(err)
	}
	if err := dnsfront.Configure(s.DNS.ListenPort); err != nil {
		return rollback(err)
	}
	if out, err := run("nft", "-f", paths.FrontNFT); err != nil {
		return rollback(fmt.Errorf("install DNS interception: %w: %s", err, out))
	}
	if err := dnsproxy.Reload(context.Background()); err != nil {
		return rollback(err)
	}
	if out, err := run(paths.DNSServiceInit, "enable"); err != nil {
		return rollback(fmt.Errorf("enable DNS service: %w: %s", err, out))
	}
	return nil
}
