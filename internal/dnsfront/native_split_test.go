package dnsfront

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type nativeTestUpstream struct {
	endpoint    string
	ip          string
	calls       atomic.Int64
	unavailable atomic.Bool
	udp, tcp    *dns.Server
}

func startNativeTestUpstream(t *testing.T, ip string) *nativeTestUpstream {
	t.Helper()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}
	upstream := &nativeTestUpstream{endpoint: tcp.Addr().String(), ip: ip}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		upstream.calls.Add(1)
		r := new(dns.Msg)
		r.SetReply(q)
		if upstream.unavailable.Load() {
			r.Rcode = dns.RcodeServerFailure
		} else if q.Question[0].Qtype == dns.TypeA {
			r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP(ip)}}
		}
		_ = w.WriteMsg(r)
	})
	upstream.udp = &dns.Server{PacketConn: udp, Handler: handler}
	upstream.tcp = &dns.Server{Listener: tcp, Handler: handler}
	go upstream.udp.ActivateAndServe()
	go upstream.tcp.ActivateAndServe()
	t.Cleanup(func() { upstream.stop() })
	return upstream
}

func (u *nativeTestUpstream) stop() {
	_ = u.udp.Shutdown()
	_ = u.tcp.Shutdown()
}

func dnsmasqEndpoint(endpoint string) string {
	host, port, _ := net.SplitHostPort(endpoint)
	return host + "#" + port
}

func nativeAnswer(t *testing.T, network, endpoint, name string) (*dns.Msg, error) {
	t.Helper()
	client := &dns.Client{Net: network, Timeout: 400 * time.Millisecond}
	reply, _, err := client.Exchange(new(dns.Msg).SetQuestion(dns.Fqdn(name), dns.TypeA), endpoint)
	return reply, err
}

func nativeAnswerIP(reply *dns.Msg) string {
	if reply != nil {
		for _, record := range reply.Answer {
			if address, ok := record.(*dns.A); ok {
				return address.A.String()
			}
		}
	}
	return ""
}

// This integration test can also be cross-compiled and run on OpenWrt. Every
// listener is an isolated loopback port; no production service is signalled.
func TestNativeSplitDNSDirectAndLocalSurviveProtectedUpstreamOutage(t *testing.T) {
	binary, err := exec.LookPath("dnsmasq")
	if err != nil {
		t.Skip("native dnsmasq not installed")
	}
	direct := startNativeTestUpstream(t, "192.0.2.10")
	protected := startNativeTestUpstream(t, "192.0.2.20")
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := probe.Addr().String()
	_, port, _ := net.SplitHostPort(endpoint)
	probe.Close()
	dir := t.TempDir()
	selectorsPath := filepath.Join(dir, "proxy.servers")
	selector := func(domain string) string {
		return "server=/" + domain + "/" + dnsmasqEndpoint(protected.endpoint) + "\n"
	}
	initial := selector("protected.example") + selector("only.example") + "server=/*.only.example/#\n"
	if err := os.WriteFile(selectorsPath, []byte(initial), 0644); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "dnsmasq.conf")
	configuration := fmt.Sprintf("no-daemon\nno-hosts\nno-resolv\nbind-interfaces\nlisten-address=127.0.0.1\nport=%s\nserver=%s\nservers-file=%s\npid-file=%s\ncache-size=0\nhost-record=printer.lan,192.168.8.9\n", port, dnsmasqEndpoint(direct.endpoint), selectorsPath, filepath.Join(dir, "dns.pid")) + string(RenderGuards(""))
	if os.Geteuid() == 0 {
		configuration += "user=root\n"
	}
	if err := os.WriteFile(configPath, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(filepath.Join(dir, "dnsmasq.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logFile.Close() })
	cmd := exec.Command(binary, "--conf-file="+configPath)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	deadline := time.Now().Add(3 * time.Second)
	for {
		reply, err := nativeAnswer(t, "udp", endpoint, "printer.lan")
		if err == nil && nativeAnswerIP(reply) == "192.168.8.9" {
			break
		}
		if time.Now().After(deadline) {
			output, _ := os.ReadFile(logFile.Name())
			skipNativeRuntimeRestriction(t, output)
			t.Fatalf("native split DNS did not start: %v: %s", err, output)
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, network := range []string{"udp", "tcp"} {
		for _, query := range []struct{ name, want string }{
			{"ordinary.example", direct.ip},
			{"protected.example", protected.ip},
			{"child.protected.example", protected.ip},
			{"only.example", protected.ip},
			{"child.only.example", direct.ip},
			{"printer.lan", "192.168.8.9"},
		} {
			reply, err := nativeAnswer(t, network, endpoint, query.name)
			if err != nil || nativeAnswerIP(reply) != query.want {
				t.Fatalf("%s %s: got %v %v, want %s", network, query.name, reply, err, query.want)
			}
		}
	}
	beforeDirect, beforeProtected := direct.calls.Load(), protected.calls.Load()
	for _, name := range []string{"missing.home.arpa", "missing.lan", "missing-host"} {
		if reply, err := nativeAnswer(t, "udp", endpoint, name); err != nil || reply.Rcode != dns.RcodeNameError {
			t.Fatalf("native local negative %s: %v %v", name, reply, err)
		}
	}
	if direct.calls.Load() != beforeDirect || protected.calls.Load() != beforeProtected {
		t.Fatal("local negative answers escaped native dnsmasq")
	}
	// Atomic replacement of servers-file must add and remove dispatch rules on
	// SIGHUP. An ordinary conf-file include would keep the old policy here.
	next := selector("new.example") + selector("only.example") + "server=/*.only.example/#\n"
	if err := atomicWrite(selectorsPath, []byte(next), 0644); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for {
		reply, err := nativeAnswer(t, "udp", endpoint, "new.example")
		if err == nil && nativeAnswerIP(reply) == protected.ip {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("SIGHUP did not activate new native selectors: %v %v", reply, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if reply, err := nativeAnswer(t, "tcp", endpoint, "protected.example"); err != nil || nativeAnswerIP(reply) != direct.ip {
		t.Fatalf("SIGHUP retained a removed proxy selector: %v %v", reply, err)
	}
	// Both an explicit protected SERVFAIL and an absent protected listener must
	// remain failures; the native default upstream must never receive the name.
	protected.unavailable.Store(true)
	beforeDirect = direct.calls.Load()
	if reply, err := nativeAnswer(t, "udp", endpoint, "only.example"); err == nil && nativeAnswerIP(reply) != "" {
		t.Fatalf("protected failure returned a direct answer: %v", reply)
	}
	if direct.calls.Load() != beforeDirect {
		t.Fatal("protected SERVFAIL leaked into native direct DNS")
	}
	protected.stop()
	for _, network := range []string{"udp", "tcp"} {
		beforeDirect = direct.calls.Load()
		if reply, err := nativeAnswer(t, network, endpoint, "only.example"); err == nil && nativeAnswerIP(reply) != "" {
			t.Fatalf("missing protected listener returned a direct answer: %v", reply)
		}
		if direct.calls.Load() != beforeDirect {
			t.Fatalf("protected %s DNS leaked while Guardian was down", network)
		}
		for _, query := range []struct{ name, want string }{{"ordinary.example", direct.ip}, {"printer.lan", "192.168.8.9"}} {
			reply, err := nativeAnswer(t, network, endpoint, query.name)
			if err != nil || nativeAnswerIP(reply) != query.want {
				t.Fatalf("protected outage broke native %s %s: %v %v", network, query.name, reply, err)
			}
		}
	}
}
