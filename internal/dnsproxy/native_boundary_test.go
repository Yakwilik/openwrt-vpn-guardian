package dnsproxy

import (
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

func TestProtectedListenerNeverResolvesOrdinaryQuestions(t *testing.T) {
	var directCalls atomic.Int32
	upstream := testDNS(t, func(w dns.ResponseWriter, q *dns.Msg) {
		directCalls.Add(1)
		answer(w, q)
	})
	matcher, err := LoadDomainMatcher([]string{"domain:protected.example"}, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"custom", "xray", "system"} {
		t.Run(mode, func(t *testing.T) {
			server := newServer(&Runtime{Mode: mode, OnlyProxyDomains: true, Matcher: matcher, SystemResolvers: []string{upstream}})
			endpoint := testDNS(t, server.ServeDNS)
			for _, transport := range []string{"udp", "tcp"} {
				client := &dns.Client{Net: transport}
				reply, _, err := client.Exchange(new(dns.Msg).SetQuestion("ordinary.example.", dns.TypeA), endpoint)
				if err != nil || reply.Rcode != dns.RcodeRefused {
					t.Fatalf("%s ordinary DNS must stay in dnsmasq: reply=%v error=%v", transport, reply, err)
				}
			}
			if server.systemCount.Load() != 0 || server.proxyCount.Load() != 0 {
				t.Fatal("excluded question entered a Guardian resolution path")
			}
		})
	}
	if directCalls.Load() != 0 {
		t.Fatal("Guardian resolved an ordinary question directly")
	}
}
