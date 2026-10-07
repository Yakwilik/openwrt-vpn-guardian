package dnsproxy

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"google.golang.org/protobuf/encoding/protowire"
)

func testDNS(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tcp := &dns.Server{Listener: ln, Handler: handler}
	udp := &dns.Server{PacketConn: pc, Handler: handler}
	go tcp.ActivateAndServe()
	go udp.ActivateAndServe()
	t.Cleanup(func() { tcp.Shutdown(); udp.Shutdown(); ln.Close(); pc.Close() })
	return ln.Addr().String()
}
func answer(w dns.ResponseWriter, q *dns.Msg) {
	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 20}, A: net.ParseIP("192.0.2.8")}}
	_ = w.WriteMsg(r)
}
func query(name string) *dns.Msg { return new(dns.Msg).SetQuestion(dns.Fqdn(name), dns.TypeA) }

func testSOCKS(t *testing.T, target string, calls *atomic.Int64) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				var h [4]byte
				if _, err := io.ReadFull(c, h[:2]); err != nil {
					return
				}
				methods := make([]byte, int(h[1]))
				if _, err := io.ReadFull(c, methods); err != nil {
					return
				}
				c.Write([]byte{5, 0})
				if _, err := io.ReadFull(c, h[:]); err != nil {
					return
				}
				var addr []byte
				switch h[3] {
				case 1:
					addr = make([]byte, 4)
				case 4:
					addr = make([]byte, 16)
				case 3:
					var n [1]byte
					io.ReadFull(c, n[:])
					addr = make([]byte, int(n[0]))
				default:
					return
				}
				if _, err := io.ReadFull(c, addr); err != nil {
					return
				}
				var p [2]byte
				if _, err := io.ReadFull(c, p[:]); err != nil {
					return
				}
				calls.Add(1)
				if binary.BigEndian.Uint16(p[:]) == 1 {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				upstream, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer upstream.Close()
				c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				go io.Copy(upstream, c)
				io.Copy(c, upstream)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestModeAndRoutingIsolation(t *testing.T) {
	matcher, err := LoadDomainMatcher([]string{"domain:youtube.com", "full:api.example.com", "regexp:^proxy[0-9]+\\.example\\.com$"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"system", "custom", "xray"} {
		for _, only := range []bool{false, true} {
			rt := &Runtime{Mode: mode, OnlyProxyDomains: only, Matcher: matcher}
			want := "proxy"
			if mode == "system" {
				want = "system"
			}
			if got := rt.route("www.YouTube.COM."); got != want {
				t.Fatalf("matched domain: %s want %s", got, want)
			}
			want = "proxy"
			if mode == "system" || only {
				want = "system"
			}
			if got := rt.route("example.com"); got != want {
				t.Fatalf("unmatched: %s want %s", got, want)
			}
		}
	}
}

func TestProxyFailoverAndNoSystemFallback(t *testing.T) {
	var systemCalls, proxyCalls atomic.Int64
	system := testDNS(t, func(w dns.ResponseWriter, q *dns.Msg) { systemCalls.Add(1); answer(w, q) })
	upstream := testDNS(t, answer)
	socks := testSOCKS(t, upstream, &proxyCalls)
	rt := &Runtime{Mode: "custom", SystemResolvers: []string{system}, SOCKSAddr: socks, Resolvers: []string{"1.1.1.1:1", "9.9.9.9:53"}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, err := rt.exchange(ctx, query("youtube.com"), "proxy")
	if err != nil || len(got.Answer) != 1 {
		t.Fatalf("failover: %v %v", got, err)
	}
	if proxyCalls.Load() != 2 || systemCalls.Load() != 0 {
		t.Fatal("wrong upstream path")
	}
	rt.Resolvers = []string{"1.1.1.1:1"}
	if _, err := rt.exchange(ctx, query("youtube.com"), "proxy"); err == nil {
		t.Fatal("dead proxy unexpectedly succeeded")
	}
	if systemCalls.Load() != 0 {
		t.Fatal("proxy DNS leaked into system")
	}
	if _, err := rt.exchange(ctx, query("example.net"), "system"); err != nil {
		t.Fatal(err)
	}
}

func TestNegativeAnswerNotRewritten(t *testing.T) {
	upstream := testDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetRcode(q, dns.RcodeNameError)
		w.WriteMsg(r)
	})
	var calls atomic.Int64
	rt := &Runtime{Mode: "custom", SOCKSAddr: testSOCKS(t, upstream, &calls), Resolvers: []string{"1.1.1.1:53", "9.9.9.9:53"}}
	r, err := rt.exchange(context.Background(), query("absent.example"), "proxy")
	if err != nil || r.Rcode != dns.RcodeNameError || calls.Load() != 1 {
		t.Fatalf("NXDOMAIN changed: %v %v", r, err)
	}
}

func pbText(n protowire.Number, s string) []byte {
	return protowire.AppendString(protowire.AppendTag(nil, n, protowire.BytesType), s)
}
func TestGeositeAndBoundaryMatching(t *testing.T) {
	domain := append(protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 2), pbText(2, "youtube.com")...)
	entry := append(pbText(1, "YOUTUBE"), protowire.AppendBytes(protowire.AppendTag(nil, 2, protowire.BytesType), domain)...)
	data := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), entry)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "geosite.dat"), data, 0600)
	m, err := LoadDomainMatcher([]string{"geosite:youtube"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Match("WWW.YOUTUBE.COM.") || m.Match("notyoutube.com") || m.Match("youtube.com.evil") {
		t.Fatal("domain boundary mismatch")
	}
	if _, err := LoadDomainMatcher([]string{"geosite:missing"}, dir); err == nil {
		t.Fatal("missing geosite silently accepted")
	}
	os.WriteFile(filepath.Join(dir, "geosite.dat"), []byte{0x0a, 0xff}, 0600)
	if _, err := LoadDomainMatcher([]string{"geosite:youtube"}, dir); err == nil {
		t.Fatal("corrupt geodata accepted")
	}
}

func TestWireUDPTruncationTCPAndMalformed(t *testing.T) {
	upstream := testDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		for i := 0; i < 20; i++ {
			r.Answer = append(r.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 30}, Txt: []string{strings.Repeat("x", 100)}})
		}
		w.WriteMsg(r)
	})
	// Exercise wire handling through an explicitly direct protected-domain
	// policy. Ordinary/system questions are no longer served by Guardian.
	server := newServer(&Runtime{Mode: "custom", SystemResolvers: []string{upstream}, Matcher: newMatcher(), Policy: func() string { return "direct" }})
	addr := testDNS(t, server.ServeDNS)
	q := new(dns.Msg).SetQuestion("example.com.", dns.TypeTXT)
	udp := &dns.Client{Net: "udp"}
	r, _, err := udp.Exchange(q, addr)
	if err != nil || !r.Truncated {
		t.Fatalf("UDP must truncate: %v %v", r, err)
	}
	tcp := &dns.Client{Net: "tcp"}
	r, _, err = tcp.Exchange(q, addr)
	if err != nil || r.Truncated || len(r.Answer) != 20 {
		t.Fatalf("TCP must retain records: %v %v", r, err)
	}
	q.Question = append(q.Question, dns.Question{Name: "vpn.home.arpa.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	r, _, err = udp.Exchange(q, addr)
	if err != nil || r.Rcode != dns.RcodeFormatError {
		t.Fatalf("multi-question leaked: %v %v", r, err)
	}
}
