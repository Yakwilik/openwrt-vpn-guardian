package dnsfront

import (
	"encoding/json"
	"net/netip"
	"os"
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
