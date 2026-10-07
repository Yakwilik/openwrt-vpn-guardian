package dnsfront

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// This test also runs as a cross-compiled Go test binary on OpenWrt. It starts
// an isolated DNS-only dnsmasq on an ephemeral loopback port, not the real service.
func TestNativeDnsmasqOwnsLocalQueriesWhenUpstreamIsDown(t *testing.T) {
	binary, err := exec.LookPath("dnsmasq")
	if err != nil {
		t.Skip("native dnsmasq not installed")
	}
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	upstream := &dns.Server{PacketConn: listener, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		calls.Add(1)
		r := new(dns.Msg)
		r.SetReply(q)
		r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}, A: net.ParseIP("192.0.2.7")}}
		w.WriteMsg(r)
	})}
	go upstream.ActivateAndServe()
	defer upstream.Shutdown()
	_, upPort, _ := net.SplitHostPort(listener.LocalAddr().String())
	probe, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	_, port, _ := net.SplitHostPort(probe.Addr().String())
	probe.Close()
	dir := t.TempDir()
	config := filepath.Join(dir, "dnsmasq.conf")
	data := fmt.Sprintf("no-daemon\nno-hosts\nno-resolv\nbind-interfaces\nlisten-address=127.0.0.1\nport=%s\nserver=127.0.0.1#%s\npid-file=%s\ncache-size=0\nhost-record=printer.lan,192.168.8.9\naddress=/vpn.home.arpa/192.168.8.1\n", port, upPort, filepath.Join(dir, "dns.pid")) + string(RenderGuards(""))
	if os.Geteuid() == 0 {
		data += "user=root\n"
	}
	if err := os.WriteFile(config, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(dir, "dnsmasq.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := exec.Command(binary, "--conf-file="+config)
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	endpoint := net.JoinHostPort("127.0.0.1", port)
	client := &dns.Client{Net: "udp", Timeout: 300 * time.Millisecond}
	until := time.Now().Add(3 * time.Second)
	for {
		_, _, err = client.Exchange(new(dns.Msg).SetQuestion("printer.lan.", dns.TypeA), endpoint)
		if err == nil {
			break
		}
		if time.Now().After(until) {
			b, _ := os.ReadFile(log.Name())
			t.Fatalf("dnsmasq did not start: %v %s", err, b)
		}
		time.Sleep(30 * time.Millisecond)
	}
	for _, tt := range []struct {
		name string
		typ  uint16
	}{{"printer.lan", dns.TypeA}, {"vpn.home.arpa", dns.TypeAAAA}, {"missing.home.arpa", dns.TypeTXT}, {"missing-host", dns.TypeTXT}, {"missing-host", dns.TypeA}} {
		if _, _, e := client.Exchange(new(dns.Msg).SetQuestion(dns.Fqdn(tt.name), tt.typ), endpoint); e != nil {
			t.Fatalf("local %s/%s: %v", tt.name, strconv.Itoa(int(tt.typ)), e)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("native dnsmasq forwarded local DNS to Guardian")
	}
	if r, _, e := client.Exchange(new(dns.Msg).SetQuestion("external.example.", dns.TypeA), endpoint); e != nil || len(r.Answer) != 1 || calls.Load() != 1 {
		t.Fatalf("external did not reach upstream: %v %v", r, e)
	}
	upstream.Shutdown()
	if r, _, e := client.Exchange(new(dns.Msg).SetQuestion("printer.lan.", dns.TypeA), endpoint); e != nil || len(r.Answer) != 1 {
		t.Fatalf("upstream outage broke native local DNS: %v %v", r, e)
	}
}
