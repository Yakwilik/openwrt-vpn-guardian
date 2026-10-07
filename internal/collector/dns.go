package collector

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	"github.com/miekg/dns"
)

type DNSCheck struct {
	Name  string `json:"name"`
	OK    bool   `json:"ok"`
	RCode string `json:"rcode"`
	MS    int64  `json:"ms"`
	Error string `json:"error,omitempty"`
}

// These probes exercise the dispatcher, not the backend SOCKS health path.
// In particular NXDOMAIN/SERVFAIL cannot pass merely because HTTP still works.
func checkDNS(stack config.Stack) map[string]DNSCheck {
	targets := map[string]string{"local": "vpn.home.arpa", "external": "example.com"}
	if stack.DNS.Mode != config.DNSModeSystem {
		targets["youtube"] = "youtube.com"
	}
	out := map[string]DNSCheck{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for label, name := range targets {
		wg.Add(1)
		go func(label, name string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			q := new(dns.Msg).SetQuestion(dns.Fqdn(name), dns.TypeA)
			r, elapsed, err := (&dns.Client{Net: "udp", Timeout: 3 * time.Second}).ExchangeContext(ctx, q, fmt.Sprintf("127.0.0.1:%d", stack.DNS.ListenPort))
			result := DNSCheck{Name: name, MS: elapsed.Milliseconds()}
			if err != nil {
				result.Error = err.Error()
			} else {
				result.RCode = dns.RcodeToString[r.Rcode]
				for _, rr := range r.Answer {
					if _, ok := rr.(*dns.A); ok {
						result.OK = r.Rcode == dns.RcodeSuccess
					}
				}
				if !result.OK {
					result.Error = "no successful A answer"
				}
			}
			mu.Lock()
			out[label] = result
			mu.Unlock()
		}(label, name)
	}
	wg.Wait()
	return out
}
func dnsChecksHealthy(checks map[string]DNSCheck) bool {
	if len(checks) == 0 {
		return false
	}
	for _, c := range checks {
		if !c.OK {
			return false
		}
	}
	return true
}
func dnsConfigKey(s config.Stack) string {
	return fmt.Sprintf("%s/%t/%d/%s", s.DNS.Mode, s.DNS.ProxyOnly(), s.DNS.ListenPort, strings.Join(s.DNS.Resolvers, ","))
}
