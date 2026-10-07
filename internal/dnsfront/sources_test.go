package dnsfront

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestEndpointsRejectRecursiveAndNonnumericUpstreams(t *testing.T) {
	own := []netip.Addr{netip.MustParseAddr("192.168.8.1"), netip.MustParseAddr("fd00::1")}
	for _, v := range []string{"127.0.0.1", "127.0.0.2#53", "::1", "::ffff:127.0.0.1", "0.0.0.0", "224.0.0.1", "192.168.8.1#53", "[fd00::1]:20176", "dns.google", "1.1.1.1#0", "1.1.1.1#99999"} {
		if ep, err := Endpoint(v, own); err == nil {
			t.Errorf("accepted %s -> %s", v, ep)
		}
	}
	for in, want := range map[string]string{"192.168.1.254": "192.168.1.254:53", "1.1.1.1#54": "1.1.1.1:54", "fe80::1%eth1": "[fe80::1%eth1]:53", "[2606:4700:4700::1111]:53": "[2606:4700:4700::1111]:53"} {
		ep, e := Endpoint(in, own)
		if e != nil || ep != want {
			t.Errorf("%s = %s %v", in, ep, e)
		}
	}
}

func TestNativeOptionsRestoreDirectSourcesAndMountSelectorDirectory(t *testing.T) {
	s := State{Sources: Sources{Servers: []string{"1.1.1.1", "127.0.0.1#20176", "192.168.8.1", "9.9.9.9#5353"}, ResolvFile: WANResolvFile}, Options: map[string]Option{
		"server": {Present: true, Values: []string{"1.1.1.1", "/corp.home/192.168.1.254", "/lan/"}},
	}}
	current := map[string]Option{
		"extraconftext": {Present: true, Values: []string{"cache-size=1000\nconf-file=" + LocalConfigPath}},
		"addnmount":     {Present: true, Values: []string{"/etc/custom-dns", LocalConfigPath, SelectorsPath}},
	}
	opts, err := nativeOptions(s, current, []netip.Addr{netip.MustParseAddr("192.168.8.1")})
	if err != nil {
		t.Fatal(err)
	}
	servers := strings.Join(opts["server"].Values, ",")
	if servers != "/corp.home/192.168.1.254,/lan/,1.1.1.1,9.9.9.9#5353" {
		t.Fatalf("native sources were changed or still point at Guardian: %s", servers)
	}
	if opts["noresolv"].Present || !opts["resolvfile"].Present || opts["resolvfile"].Values[0] != WANResolvFile {
		t.Fatalf("native WAN polling was not restored: %v", opts)
	}
	if mounts := strings.Join(opts["addnmount"].Values, ","); mounts != "/etc/custom-dns,"+LocalConfigPath+","+SelectorsDir {
		t.Fatalf("atomic selector replacements are not visible in ujail: %s", mounts)
	}
	extra := strings.Join(opts["extraconftext"].Values, "\n")
	if !strings.Contains(extra, "cache-size=1000") || strings.Count(extra, "conf-file="+LocalConfigPath) != 1 || !strings.Contains(extra, "servers-file="+SelectorsPath) {
		t.Fatalf("native includes damaged unrelated settings: %s", extra)
	}
}

func TestNativeOptionsRespectExplicitNoResolv(t *testing.T) {
	s := State{Sources: Sources{Servers: []string{"9.9.9.9"}}, Options: map[string]Option{}}
	opts, err := nativeOptions(s, nil, nil)
	if err != nil || !opts["noresolv"].Present || opts["resolvfile"].Present {
		t.Fatalf("explicit static-only DNS was replaced by WAN DNS: %v %v", opts, err)
	}
	if !strings.Contains(bootstrapScriptFor(s.Sources), "wan='/dev/null'") {
		t.Fatal("router bootstrap re-enabled a deliberately disabled WAN source")
	}
}

func TestNativeCheckRejectsDispatcherAsAnyDefaultUpstream(t *testing.T) {
	base := "conf-file=" + LocalConfigPath + "\nservers-file=" + SelectorsPath + "\n"
	for _, defaults := range []string{"server=127.0.0.1#20176\n", "server=9.9.9.9\nserver=127.0.0.1#20176\n", "server=9.9.9.9\nserver=/#/127.0.0.1#20176\n", "no-resolv\nresolv-file=" + WANResolvFile + "\n", "resolv-file=/etc/resolv.conf\n"} {
		if err := checkNativeConfig([]byte(base+defaults), nil); err == nil {
			t.Errorf("accepted non-native or recursive defaults: %s", defaults)
		}
	}
	for _, defaults := range []string{"no-resolv\nserver=9.9.9.9\n", "resolv-file=" + WANResolvFile + "\n"} {
		if err := checkNativeConfig([]byte(base+defaults), nil); err != nil {
			t.Errorf("rejected native defaults: %s: %v", defaults, err)
		}
	}
}

func TestSelectorsCannotInstallMissingPolicyOrUnmanagedUpstreams(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("server=127.0.0.1#20176\n"), []byte("server=/protected.example/9.9.9.9\n"), []byte("server=/protected.example/127.0.0.1#53\n"), []byte("conf-file=/etc/other.conf\n"), []byte("server=/foo.*.example/127.0.0.1#20176\n")} {
		if _, err := selectorRules(20176, data); err == nil {
			t.Errorf("accepted unsafe selector plan: %q", data)
		}
	}
	for _, data := range [][]byte{[]byte{}, []byte("# explicit System mode\n"), []byte("server=/protected.example/127.0.0.1#20176\nserver=/*.protected.example/#\n"), []byte("server=/#/127.0.0.1#20176\n"), []byte(`server=/regex:^foo[0-9]+\.example$/127.0.0.1#20176`)} {
		if _, err := selectorRules(20176, data); err != nil {
			t.Errorf("rejected explicit selector plan: %q: %v", data, err)
		}
	}
}

func TestSelectorsPreserveLocalZonesAndRejectDirectOverrideHoles(t *testing.T) {
	guards := RenderGuards("domain=corp.home\nlocal=/office.home/\n")
	for _, selector := range []string{"server=/vpn.home.arpa/127.0.0.1#20176\n", "server=/*.corp.home/#\n", "server=/office.home/127.0.0.1#20176\n"} {
		if err := validateSelectorZones(20176, []byte(selector), guards, nil); err == nil {
			t.Errorf("selector displaced native local DNS: %s", selector)
		}
	}
	if err := validateSelectorZones(20176, []byte("server=/example.com/127.0.0.1#20176\n"), guards, []string{"/internal.example.com/192.168.1.254"}); err == nil {
		t.Fatal("preserved private override bypasses a protected suffix")
	}
	if err := validateSelectorZones(20176, []byte("server=/#/127.0.0.1#20176\n"), guards, []string{"/internal.example.com/192.168.1.254"}); err != nil {
		t.Fatalf("explicit all-domain mode must retain more-specific native local zones: %v", err)
	}
}

func TestSelectorCheckpointRestoresDirectoryFileAndPermissions(t *testing.T) {
	root := t.TempDir()
	dir, path := rooted(root, SelectorsDir), rooted(root, SelectorsPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatal(err)
	}
	want := []byte("server=/old.example/127.0.0.1#20176\n")
	if err := os.WriteFile(path, want, 0640); err != nil {
		t.Fatal(err)
	}
	var state State
	if err := captureSelectors(root, &state); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(path, []byte("server=/new.example/127.0.0.1#20176\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := restoreSelectors(root, state); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("selector rollback lost the previous policy: %q %v", got, err)
	}
	file, _ := os.Stat(path)
	directory, _ := os.Stat(dir)
	if file.Mode().Perm() != 0640 || directory.Mode().Perm() != 0750 {
		t.Fatal("selector rollback did not restore permissions")
	}
}

func TestSelectorCheckpointRemovesOnlyItsOwnNewFiles(t *testing.T) {
	for _, unrelated := range []bool{false, true} {
		root := t.TempDir()
		var state State
		if err := captureSelectors(root, &state); err != nil {
			t.Fatal(err)
		}
		if err := atomicWrite(rooted(root, SelectorsPath), []byte("# selectors\n"), 0644); err != nil {
			t.Fatal(err)
		}
		foreign := filepath.Join(rooted(root, SelectorsDir), "operator-file")
		if unrelated {
			if err := os.WriteFile(foreign, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := restoreSelectors(root, state); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(rooted(root, SelectorsPath)); !os.IsNotExist(err) {
			t.Fatal("selector rollback retained a newly installed policy")
		}
		if unrelated {
			if b, err := os.ReadFile(foreign); err != nil || string(b) != "keep" {
				t.Fatal("selector rollback removed an unrelated operator file")
			}
		} else if _, err := os.Stat(rooted(root, SelectorsDir)); !os.IsNotExist(err) {
			t.Fatal("selector rollback retained its empty new directory")
		}
	}
}

func TestNativeSelectorSyntaxUsesInstalledDnsmasq(t *testing.T) {
	if _, err := exec.LookPath("dnsmasq"); err != nil {
		t.Skip("native dnsmasq not installed")
	}
	if err := validateSelectorSyntax(20176, []byte("server=/protected.example/127.0.0.1#20176\nserver=/*.protected.example/#\n")); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("dnsmasq", "--version").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(output), " regex-server") {
		if err := validateSelectorSyntax(20176, []byte(`server=/regex:^foo[0-9]+\.example$/127.0.0.1#20176`)); err == nil {
			t.Fatal("stock dnsmasq silently accepted unsupported regex as a literal domain")
		}
	} else {
		if err := validateSelectorSyntax(20176, []byte(`server=/regex:[unterminated/127.0.0.1#20176`)); err == nil {
			t.Fatal("native syntax validation did not reject a malformed regular expression")
		}
	}
}

func TestNativeSelectorSyntaxReadsStagedFile(t *testing.T) {
	if _, err := exec.LookPath("dnsmasq"); err != nil {
		t.Skip("native dnsmasq not installed")
	}
	// The directive and target pass Guardian's whitelist, while a label longer
	// than 63 bytes must be rejected by the real dnsmasq config parser. Native
	// --test does not read --servers-file at all, so merely passing that option
	// would incorrectly accept this plan without examining the staged bytes.
	invalid := []byte("server=/" + strings.Repeat("x", 64) + ".example/127.0.0.1#20176\n")
	if _, err := selectorRules(20176, invalid); err != nil {
		t.Fatalf("fixture should reach the native config parser: %v", err)
	}
	if err := validateSelectorSyntax(20176, invalid); err == nil {
		t.Fatal("native syntax validation did not read the staged selector file")
	}
}

func TestSourcesUseOriginalUpstreamsAndRefreshWAN(t *testing.T) {
	root := t.TempDir()
	s := State{Version: 1, Section: "main", Sources: Sources{Servers: []string{"1.1.1.1", "127.0.0.1#20176", "192.168.8.1"}, ResolvFile: WANResolvFile}}
	b, _ := json.Marshal(s)
	os.MkdirAll(filepath.Dir(rooted(root, StatePath)), 0700)
	os.WriteFile(rooted(root, StatePath), b, 0600)
	p := rooted(root, WANResolvFile)
	os.MkdirAll(filepath.Dir(p), 0700)
	own := []netip.Addr{netip.MustParseAddr("192.168.8.1")}
	for _, wan := range []string{"192.168.1.254", "192.168.2.1"} {
		os.WriteFile(p, []byte("nameserver "+wan+"\nnameserver 1.1.1.1\n"), 0600)
		result, err := ReadResolvers(root, own)
		if err != nil || strings.Join(result, ",") != "1.1.1.1:53,"+wan+":53" {
			t.Fatalf("sources %v %v", result, err)
		}
	}
}
func TestLocalOverridesCannotBypassExternalPolicy(t *testing.T) {
	got, err := keepLocalServers([]string{"1.1.1.1", "/corp.home/192.168.1.254", "/lan/"})
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
	for _, v := range []string{"/youtube.com/8.8.8.8", "/corp/127.0.0.1#20176", "/corp/#"} {
		if _, e := keepLocalServers([]string{v}); e == nil {
			t.Errorf("accepted unsafe override %s", v)
		}
	}
}
func TestNativeGuardRulesCoverNonAAndUnqualifiedNames(t *testing.T) {
	guards := string(RenderGuards("domain=corp.home\naddress=/a.home/b.home/192.168.8.1\n"))
	for _, v := range []string{"local=//\n", "local=/corp.home/\n", "local=/home.arpa/\n", "local=/a.home/\n", "local=/b.home/\n", "bogus-priv\n"} {
		if !strings.Contains(guards, v) {
			t.Errorf("missing %q", v)
		}
	}
	if strings.Contains(guards, "server=127.0.0.1") {
		t.Fatal("guards must only control native local answers")
	}
}

func TestBootstrapPreservesOriginalStaticServers(t *testing.T) {
	data := string(BootstrapSources(Sources{Servers: []string{"1.1.1.1", "9.9.9.9", "127.0.0.1#20176", "192.168.8.1", "8.8.8.8#5353"}}, []netip.Addr{netip.MustParseAddr("192.168.8.1")}))
	if data != "nameserver 1.1.1.1\nnameserver 9.9.9.9\n" {
		t.Fatalf("bootstrap sources: %q", data)
	}
}
