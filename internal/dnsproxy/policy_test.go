package dnsproxy

import (
	"context"
	"github.com/miekg/dns"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSPolicyMatrix(t *testing.T) {
	for _, dnsMode := range []string{"custom", "xray"} {
		for _, mode := range []string{"killswitch", "failopen", "direct", "killswitch-blocked"} {
			for _, healthy := range []bool{true, false} {
				t.Run(dnsMode+"/"+mode+"/"+map[bool]string{true: "up", false: "down"}[healthy], func(t *testing.T) {
					var systemCalls, vpnCalls atomic.Int64
					system := testDNS(t, func(w dns.ResponseWriter, q *dns.Msg) { systemCalls.Add(1); answer(w, q) })
					vpn := testDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
						vpnCalls.Add(1)
						if healthy {
							answer(w, q)
						} else {
							writeError(w, q, dns.RcodeServerFailure)
						}
					})
					var socksCalls atomic.Int64
					rt := &Runtime{Mode: dnsMode, SystemResolvers: []string{system}, SOCKSAddr: testSOCKS(t, vpn, &socksCalls), XrayResolver: vpn, Resolvers: []string{"1.1.1.1:53"}, Policy: func() string { return mode }}
					r, path, err := rt.resolve(context.Background(), query("youtube.com"), "proxy")
					expectedError := mode == "killswitch-blocked" || (!healthy && mode == "killswitch")
					if (err != nil) != expectedError {
						t.Fatalf("path=%s reply=%v err=%v", path, r, err)
					}
					wantSystem := mode == "direct" || (!healthy && mode == "failopen")
					if (systemCalls.Load() > 0) != wantSystem {
						t.Fatalf("unexpected system calls %d", systemCalls.Load())
					}
					if (mode == "direct" || mode == "killswitch-blocked") && vpnCalls.Load() != 0 {
						t.Fatal("direct/blocked must not use VPN DNS")
					}
					if wantSystem && r.Answer[0].Header().Ttl != 0 {
						t.Fatal("policy-bypass answer can leak into future cached VPN-only lookups")
					}
				})
			}
		}
	}
}
func TestFallbackRechecksTightenedPolicy(t *testing.T) {
	var mode atomic.Value
	mode.Store("failopen")
	var direct atomic.Int64
	system := testDNS(t, func(w dns.ResponseWriter, q *dns.Msg) { direct.Add(1); answer(w, q) })
	vpn := testDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		mode.Store("killswitch")
		writeError(w, q, dns.RcodeServerFailure)
	})
	var calls atomic.Int64
	rt := &Runtime{Mode: "custom", SystemResolvers: []string{system}, SOCKSAddr: testSOCKS(t, vpn, &calls), Resolvers: []string{"1.1.1.1:53"}, Policy: func() string { return mode.Load().(string) }}
	if _, _, err := rt.resolve(context.Background(), query("youtube.com"), "proxy"); err == nil {
		t.Fatal("tightening did not fail closed")
	}
	if direct.Load() != 0 {
		t.Fatal("request used stale fail-open permission")
	}
}
func TestVPNNegativeDoesNotTriggerFallback(t *testing.T) {
	for _, rcode := range []int{dns.RcodeNameError, dns.RcodeSuccess} {
		var systemCalls, calls atomic.Int64
		sys := testDNS(t, func(w dns.ResponseWriter, q *dns.Msg) { systemCalls.Add(1); answer(w, q) })
		vpn := testDNS(t, func(w dns.ResponseWriter, q *dns.Msg) { r := new(dns.Msg); r.SetRcode(q, rcode); w.WriteMsg(r) })
		rt := &Runtime{Mode: "custom", SystemResolvers: []string{sys}, SOCKSAddr: testSOCKS(t, vpn, &calls), Resolvers: []string{"1.1.1.1:53"}, Policy: func() string { return "failopen" }}
		r, path, e := rt.resolve(context.Background(), query("absent.example"), "proxy")
		if e != nil || path != "proxy" || r.Rcode != rcode || systemCalls.Load() != 0 {
			t.Fatalf("negative answer changed: %s %v %v", path, r, e)
		}
	}
}
func TestTransportFailureHasBudgetForFallback(t *testing.T) {
	var direct atomic.Int64
	sys := testDNS(t, func(w dns.ResponseWriter, q *dns.Msg) { direct.Add(1); answer(w, q) })
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); time.Sleep(1500 * time.Millisecond) }()
		}
	}()
	rt := &Runtime{Mode: "custom", SystemResolvers: []string{sys}, SOCKSAddr: ln.Addr().String(), Resolvers: []string{"1.1.1.1:53", "9.9.9.9:53"}, Policy: func() string { return "failopen" }}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	_, path, err := rt.resolve(ctx, query("youtube.com"), "proxy")
	if err != nil || path != "fallback" || direct.Load() != 1 {
		t.Fatalf("fallback lost time budget: %s %v", path, err)
	}
}

func TestSystemResolverDisagreementPrefersPositiveAnswer(t *testing.T) {
	negative := testDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetRcode(q, dns.RcodeNameError)
		_ = w.WriteMsg(r)
	})
	positive := testDNS(t, answer)
	rt := &Runtime{SystemResolvers: []string{negative, positive}}
	r, err := rt.system(context.Background(), query("youtube.com"))
	if err != nil || r.Rcode != dns.RcodeSuccess || len(r.Answer) == 0 {
		t.Fatalf("positive resolver did not override poisoned NXDOMAIN: %v %v", r, err)
	}
}

func TestSystemResolverReturnsNegativeWhenAllAreNegative(t *testing.T) {
	negative1 := testDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetRcode(q, dns.RcodeNameError)
		_ = w.WriteMsg(r)
	})
	negative2 := testDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		_ = w.WriteMsg(r)
	})
	rt := &Runtime{SystemResolvers: []string{negative1, negative2}}
	r, err := rt.system(context.Background(), query("absent.example"))
	if err != nil || r == nil || (r.Rcode != dns.RcodeNameError && r.Rcode != dns.RcodeSuccess) {
		t.Fatalf("negative DNS result was lost: %v %v", r, err)
	}
}
