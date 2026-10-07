package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/control"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/stack"
	v "github.com/Yakwilik/openwrt-vpn-guardian/internal/v2raya"
	"github.com/miekg/dns"
)

func main() {
	server := flag.String("dns", "", "DNS endpoint")
	name := flag.String("name", "youtube.com", "name")
	typ := flag.String("type", "A", "record type")
	network := flag.String("net", "udp", "UDP/TCP")
	nodes := flag.Bool("nodes", false, "sanitized indices")
	noRecursion := flag.Bool("norecurse", false, "do not request recursion")
	dnsMode := flag.String("apply-dns", "", "apply system|custom|xray DNS mode")
	dnsOnlyProxy := flag.String("dns-only-proxy", "", "optional true|false selective DNS scope")
	dnsResolvers := flag.String("dns-resolvers", "1.1.1.1,9.9.9.9", "comma-separated custom resolver IPs")
	switchKey := flag.String("switch-key", "", "switch using stable candidate key")
	reselect := flag.Bool("reselect", false, "request another healthy candidate")
	flag.Parse()
	var out any
	var err error
	if *dnsMode != "" {
		var only *bool
		if *dnsOnlyProxy != "" {
			v, parseErr := strconv.ParseBool(*dnsOnlyProxy)
			if parseErr != nil {
				err = parseErr
			} else {
				only = &v
			}
		}
		var resolvers []string
		for _, value := range strings.Split(*dnsResolvers, ",") {
			if value = strings.TrimSpace(value); value != "" {
				resolvers = append(resolvers, value)
			}
		}
		if err == nil {
			err = stack.ApplyDNS(*dnsMode, resolvers, only)
		}
		if err == nil {
			out = map[string]any{"mode": *dnsMode, "onlyProxyDomains": only}
		}
	} else if *switchKey != "" {
		var candidate v.Candidate
		candidate, err = candidateByKey(*switchKey)
		if err == nil {
			err = control.SwitchFront(candidate.TouchID, candidate.Sub, candidate.Key)
		}
		if err == nil {
			out = map[string]any{"name": candidate.Name, "key": candidate.Key}
		}
	} else if *reselect {
		var name string
		name, err = control.ReselectFront()
		if err == nil {
			out = map[string]any{"name": name}
		}
	} else if *server != "" {
		q := new(dns.Msg).SetQuestion(dns.Fqdn(*name), dns.StringToType[*typ])
		q.RecursionDesired = !*noRecursion
		c := &dns.Client{Net: *network, Timeout: 5 * time.Second}
		var r *dns.Msg
		var elapsed time.Duration
		r, elapsed, err = c.Exchange(q, *server)
		if err == nil {
			a := []string{}
			for _, rr := range r.Answer {
				a = append(a, rr.String())
			}
			out = map[string]any{"rcode": dns.RcodeToString[r.Rcode], "answers": a, "ms": elapsed.Milliseconds(), "truncated": r.Truncated}
		}
	} else if *nodes {
		out, err = nodeState()
	} else {
		out, err = v.CallAPIData("guardian-diagnostic", "GET", "touch", nil, 5*time.Second)
		out = sanitize(out)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(out)
}
func nodeState() (any, error) {
	db, err := v.OpenDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	cfg, err := config.LoadStack()
	if err != nil {
		return nil, err
	}
	p, err := v.NewCandidatePolicy(cfg.Selection)
	if err != nil {
		return nil, err
	}
	cs, err := v.ListCandidates(context.Background(), db, p)
	if err != nil {
		return nil, err
	}
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Sub != cs[j].Sub {
			return cs[i].Sub < cs[j].Sub
		}
		return cs[i].TouchID < cs[j].TouchID
	})
	touch, ok, err := v.ConnectedTouch(context.Background(), db)
	if err != nil {
		return nil, err
	}
	return map[string]any{"current": touch, "currentKnown": ok, "nodes": cs}, nil
}
func candidateByKey(key string) (v.Candidate, error) {
	db, err := v.OpenDB()
	if err != nil {
		return v.Candidate{}, err
	}
	defer db.Close()
	cfg, err := config.LoadStack()
	if err != nil {
		return v.Candidate{}, err
	}
	p, err := v.NewCandidatePolicy(cfg.Selection)
	if err != nil {
		return v.Candidate{}, err
	}
	cs, err := v.ListCandidates(context.Background(), db, p)
	if err != nil {
		return v.Candidate{}, err
	}
	for _, candidate := range cs {
		if candidate.Key == key {
			return candidate, nil
		}
	}
	return v.Candidate{}, fmt.Errorf("candidate key not found")
}

func sanitize(value any) any {
	switch x := value.(type) {
	case map[string]any:
		r := map[string]any{}
		for k, v := range x {
			switch k {
			case "Link", "link", "address", "url", "serverObj", "token", "password", "uuid", "settings", "config":
				continue
			}
			r[k] = sanitize(v)
		}
		return r
	case []any:
		r := make([]any, len(x))
		for i, v := range x {
			r[i] = sanitize(v)
		}
		return r
	default:
		return x
	}
}
