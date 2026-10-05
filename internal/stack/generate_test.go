package stack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
)

func TestDefaultStackUsesVPNOnlyFailurePolicy(t *testing.T) {
	cfg := defaultStack("br-test", "192.0.2.0/24", "eth-test", "/opt/xray")

	if cfg.Policy.Default != "killswitch" {
		t.Fatalf("default policy = %q, want killswitch", cfg.Policy.Default)
	}
	if cfg.Front.SocksPort <= 0 || cfg.Front.TProxyPort <= 0 || cfg.Front.PolicyPort <= 0 {
		t.Fatalf("front ports must be positive: %+v", cfg.Front)
	}
	if cfg.Backend.SocksPort <= 0 {
		t.Fatalf("backend SOCKS port must be positive: %d", cfg.Backend.SocksPort)
	}
}

func TestGenerateUsesOwnedRuntimePaths(t *testing.T) {
	cfg := defaultStack("br-test", "192.0.2.0/24", "eth-test", "/opt/xray-assets")
	dir := t.TempDir()

	if err := generate(dir, cfg, defaultRouting()); err != nil {
		t.Fatal(err)
	}

	mustContainFile(t, filepath.Join(dir, "vpn-front.init"), paths.FrontConfig)
	mustContainFile(t, filepath.Join(dir, "vpn-front.init"), `ASSETS="/opt/xray-assets"`)
	mustContainFile(t, filepath.Join(dir, "vpn-policy.init"), paths.PolicyConfig)
	mustContainFile(t, filepath.Join(dir, "vpn-front-routing.init"), paths.FrontEnabled)
	mustContainFile(t, filepath.Join(dir, "vpn-front-routing.init"), paths.FrontNFT)

	for _, name := range []string{
		filepath.Base(paths.FrontConfig),
		filepath.Base(paths.PolicyFailOpen),
		filepath.Base(paths.PolicyVPNOnly),
		filepath.Base(paths.PolicyBlocked),
		filepath.Base(paths.PolicyDirect),
		filepath.Base(paths.FrontNFT),
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("generated file %s: %v", name, err)
		}
	}
}

func TestGeneratedRoutingIsScopedToLAN(t *testing.T) {
	cfg := defaultStack("br-test", "192.0.2.0/24", "eth-test", "/opt/xray")
	nft := makeNFT(cfg)

	if !strings.Contains(nft, `iifname "br-test" ip saddr 192.0.2.0/24`) {
		t.Fatalf("nft config is not scoped to configured LAN:\n%s", nft)
	}
	if strings.Contains(nft, "blackhole") {
		t.Fatalf("front nft must not install a global blackhole:\n%s", nft)
	}
}

func mustContainFile(t *testing.T, path, needle string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), needle) {
		t.Fatalf("%s does not contain %q:\n%s", path, needle, string(b))
	}
}
