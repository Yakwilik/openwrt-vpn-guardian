package dnsproxy

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/dnsfront"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/policy"
	"github.com/miekg/dns"
	"golang.org/x/net/netutil"
	"golang.org/x/net/proxy"
)

const ControlSocket = "/tmp/vpn-guardian-dns.sock"

type Runtime struct {
	Mode             string
	OnlyProxyDomains bool
	Resolvers        []string
	SOCKSAddr        string
	XrayResolver     string
	SystemResolvers  []string
	SystemSource     func() ([]string, error)
	Policy           func() string
	Matcher          *DomainMatcher
}

type Server struct {
	current       atomic.Pointer[Runtime]
	systemGate    chan struct{}
	proxyGate     chan struct{}
	systemCount   atomic.Uint64
	proxyCount    atomic.Uint64
	fallbackCount atomic.Uint64
	errorCount    atomic.Uint64
}

func newServer(rt *Runtime) *Server {
	s := &Server{systemGate: make(chan struct{}, 96), proxyGate: make(chan struct{}, 96)}
	s.current.Store(rt)
	return s
}
func BuildRuntime(s config.Stack, r config.Routing, root string) (*Runtime, error) {
	matcher, err := LoadDomainMatcher(r.ProxyDomains, s.AssetsDir)
	if err != nil {
		return nil, err
	}
	own := dnsfront.OwnAddresses()
	rt := &Runtime{Mode: s.DNS.Mode, OnlyProxyDomains: s.DNS.ProxyOnly(), Matcher: matcher,
		SOCKSAddr: fmt.Sprintf("127.0.0.1:%d", s.Backend.SocksPort), XrayResolver: fmt.Sprintf("127.0.0.1:%d", s.DNS.XrayPort),
		Policy: func() string { return policy.DNSRuntimeAt(root) }, SystemSource: func() ([]string, error) { return dnsfront.ReadResolvers(root, own) }}
	source := s.DNS.Resolvers
	if s.DNS.Mode == config.DNSModeXray {
		source = config.DefaultClientDNS().Resolvers
	}
	for _, v := range source {
		ep, err := config.DNSResolverEndpoint(v)
		if err != nil {
			return nil, err
		}
		rt.Resolvers = append(rt.Resolvers, ep)
	}
	return rt, nil
}
func (rt *Runtime) route(name string) string {
	if rt.Mode == config.DNSModeSystem || (rt.OnlyProxyDomains && !rt.Matcher.Match(name)) {
		return "system"
	}
	return "proxy"
}
func (rt *Runtime) policy() string {
	if rt.Policy == nil {
		return "killswitch"
	}
	return rt.Policy()
}

func (s *Server) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {
	rt := s.current.Load()
	host, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	ip := net.ParseIP(strings.Split(host, "%")[0])
	if !ip.IsLoopback() {
		writeError(w, q, dns.RcodeRefused)
		return
	}
	if q.Response || q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 {
		writeError(w, q, dns.RcodeFormatError)
		return
	}
	route := rt.route(q.Question[0].Name)
	// Native dnsmasq owns system/non-proxy questions. Never turn this protected
	// loopback listener back into a general-purpose direct DNS dispatcher when
	// stale or incorrectly generated selectors send a question here.
	if route == "system" {
		writeError(w, q, dns.RcodeRefused)
		return
	}
	gate := s.systemGate
	if route == "proxy" && rt.policy() != "direct" {
		gate = s.proxyGate
	}
	select {
	case gate <- struct{}{}:
		defer func() { <-gate }()
	default:
		writeError(w, q, dns.RcodeServerFailure)
		s.errorCount.Add(1)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	response, path, err := rt.resolve(ctx, q, route)
	switch path {
	case "proxy":
		s.proxyCount.Add(1)
	case "fallback":
		s.proxyCount.Add(1)
		s.fallbackCount.Add(1)
		s.systemCount.Add(1)
	case "system", "direct":
		s.systemCount.Add(1)
	}
	if err != nil {
		s.errorCount.Add(1)
		writeError(w, q, dns.RcodeServerFailure)
		return
	}
	response.Id = q.Id
	if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		size := uint16(512)
		if opt := q.IsEdns0(); opt != nil {
			size = opt.UDPSize()
			if size < 512 {
				size = 512
			}
			if size > 1232 {
				size = 1232
			}
		}
		response.Truncate(int(size))
	}
	_ = w.WriteMsg(response)
}
func writeError(w dns.ResponseWriter, q *dns.Msg, code int) {
	m := new(dns.Msg)
	m.SetRcode(q, code)
	_ = w.WriteMsg(m)
}

// Terminal negative answers (NXDOMAIN and NOERROR/NODATA) are DNS results,
// not transport failures. They must not trigger a direct fallback.
func usable(reply *dns.Msg, err error) bool {
	return err == nil && reply != nil && reply.Rcode != dns.RcodeServerFailure && reply.Rcode != dns.RcodeRefused
}
func zeroTTL(reply *dns.Msg) {
	for _, section := range [][]dns.RR{reply.Answer, reply.Ns, reply.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			rr.Header().Ttl = 0
			if soa, ok := rr.(*dns.SOA); ok {
				soa.Minttl = 0
			}
		}
	}
}
func (rt *Runtime) system(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	upstreams := rt.SystemResolvers
	if rt.SystemSource != nil {
		var err error
		upstreams, err = rt.SystemSource()
		if err != nil {
			return nil, err
		}
	}
	if len(upstreams) == 0 {
		return nil, errors.New("system DNS has no usable upstream")
	}
	var errs []error
	var negative *dns.Msg
	for _, ep := range upstreams {
		attempt, cancel := context.WithTimeout(ctx, 900*time.Millisecond)
		reply, err := exchangeDirect(attempt, q, ep)
		cancel()
		if usable(reply, err) {
			// Direct resolvers on captive/filtered networks can disagree. A positive
			// answer wins over an earlier NXDOMAIN/NODATA. Preserve a negative only
			// if every usable system upstream agrees by failing to produce data.
			if reply.Rcode == dns.RcodeSuccess && len(reply.Answer) > 0 {
				return reply, nil
			}
			if negative == nil {
				negative = reply
			}
			continue
		}
		if err == nil {
			err = errors.New("system upstream returned DNS failure")
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	if negative != nil {
		return negative, nil
	}
	return nil, errors.Join(errs...)
}
func (rt *Runtime) resolve(ctx context.Context, q *dns.Msg, route string) (*dns.Msg, string, error) {
	if route == "system" {
		r, e := rt.system(ctx, q)
		return r, "system", e
	}
	mode := rt.policy()
	if mode == "killswitch-blocked" {
		return nil, "proxy", errors.New("DNS blocked by runtime policy")
	}
	if mode == "direct" {
		r, e := rt.system(ctx, q)
		if rt.policy() != "direct" {
			return nil, "direct", errors.New("DNS policy changed during direct request")
		}
		if e == nil {
			zeroTTL(r)
		}
		return r, "direct", e
	}
	// Reserve an independent time budget for fail-open. An exhausted VPN attempt
	// must not leave fallback with an already-expired request deadline.
	attempt, cancel := context.WithTimeout(ctx, 2700*time.Millisecond)
	r, err := rt.vpn(attempt, q)
	cancel()
	if usable(r, err) {
		if rt.policy() == "killswitch-blocked" {
			return nil, "proxy", errors.New("DNS policy became blocked")
		}
		return r, "proxy", nil
	}
	if err == nil {
		err = errors.New("VPN resolver returned DNS failure")
	}
	// Recheck at the decision point: never use permissions captured before the
	// operator changed fail-open back to VPN-only.
	current := rt.policy()
	if current != "failopen" && current != "direct" {
		return nil, "proxy", err
	}
	r, e := rt.system(ctx, q)
	current = rt.policy()
	if current != "failopen" && current != "direct" {
		return nil, "fallback", errors.New("DNS policy tightened during fallback")
	}
	if e != nil {
		return nil, "fallback", errors.Join(err, e)
	}
	// Do not retain a direct answer after automatic VPN recovery.
	zeroTTL(r)
	return r, "fallback", nil
}
func (rt *Runtime) exchange(ctx context.Context, q *dns.Msg, route string) (*dns.Msg, error) {
	r, _, e := rt.resolve(ctx, q, route)
	return r, e
}
func (rt *Runtime) vpn(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	if rt.Mode == config.DNSModeXray && (q.Question[0].Qtype == dns.TypeA || q.Question[0].Qtype == dns.TypeAAAA) {
		return exchangeDirect(ctx, q, rt.XrayResolver)
	}
	var errs []error
	for _, endpoint := range rt.Resolvers {
		attempt, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
		dialer, err := proxy.SOCKS5("tcp", rt.SOCKSAddr, nil, &net.Dialer{Timeout: 1200 * time.Millisecond})
		var reply *dns.Msg
		if err == nil {
			var conn net.Conn
			conn, err = dialer.(proxy.ContextDialer).DialContext(attempt, "tcp", endpoint)
			if err == nil {
				reply, err = exchangeConn(attempt, q, conn)
			}
		}
		cancel()
		if usable(reply, err) {
			return reply, nil
		}
		if err == nil {
			err = errors.New("VPN upstream returned DNS failure")
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	if len(errs) == 0 {
		return nil, errors.New("no VPN DNS resolvers configured")
	}
	return nil, errors.Join(errs...)
}

func exchangeDirect(ctx context.Context, q *dns.Msg, endpoint string) (*dns.Msg, error) {
	c := &dns.Client{Net: "udp", Timeout: 1800 * time.Millisecond}
	reply, _, err := c.ExchangeContext(ctx, q, endpoint)
	if err == nil && !reply.Truncated {
		return reply, nil
	}
	c.Net = "tcp"
	reply, _, err = c.ExchangeContext(ctx, q, endpoint)
	return reply, err
}
func exchangeConn(ctx context.Context, q *dns.Msg, conn net.Conn) (*dns.Msg, error) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	c := &dns.Client{Net: "tcp", Timeout: 1800 * time.Millisecond}
	reply, _, err := c.ExchangeWithConnContext(ctx, q, &dns.Conn{Conn: conn})
	if err == nil && (len(reply.Question) != 1 || !strings.EqualFold(reply.Question[0].Name, q.Question[0].Name) || reply.Question[0].Qtype != q.Question[0].Qtype) {
		return nil, errors.New("DNS response question mismatch")
	}
	return reply, err
}

func Run(args []string) error {
	fs := flag.NewFlagSet("dns-proxy", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("dns-proxy accepts no arguments")
	}
	cfg, rules, err := config.Load()
	if err != nil {
		return err
	}
	rt, err := BuildRuntime(cfg, rules, "/")
	if err != nil {
		return err
	}
	server := newServer(rt)
	addr := fmt.Sprintf("127.0.0.1:%d", cfg.DNS.ListenPort)
	udp, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer tcp.Close()
	us := &dns.Server{PacketConn: udp, Handler: server, UDPSize: 1232}
	ts := &dns.Server{Listener: netutil.LimitListener(tcp, 96), Handler: server, ReadTimeout: 3 * time.Second, WriteTimeout: 6 * time.Second, IdleTimeout: func() time.Duration { return 3 * time.Second }, MaxTCPQueries: 32}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := os.Remove(ControlSocket); err != nil && !os.IsNotExist(err) {
		return err
	}
	control, err := net.Listen("unix", ControlSocket)
	if err != nil {
		return err
	}
	defer control.Close()
	defer os.Remove(ControlSocket)
	if err := os.Chmod(ControlSocket, 0600); err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		next, rs, err := config.Load()
		if err == nil && next.DNS.ListenPort != cfg.DNS.ListenPort {
			err = errors.New("DNS port change requires restart")
		}
		var runtime *Runtime
		if err == nil {
			runtime, err = BuildRuntime(next, rs, "/")
		}
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		server.current.Store(runtime)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		rt := server.current.Load()
		_ = json.NewEncoder(w).Encode(map[string]any{"architecture": "native-split-dns", "mode": rt.Mode, "policy": rt.policy(), "onlyProxyDomains": rt.OnlyProxyDomains, "system": server.systemCount.Load(), "proxy": server.proxyCount.Load(), "fallbacks": server.fallbackCount.Load(), "errors": server.errorCount.Load()})
	})
	hs := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second, WriteTimeout: 5 * time.Second}
	errs := make(chan error, 3)
	go func() { errs <- us.ActivateAndServe() }()
	go func() { errs <- ts.ActivateAndServe() }()
	go func() { errs <- hs.Serve(control) }()

	select {
	case <-ctx.Done():
		err = nil
	case err = <-errs:
	}
	shutdown, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	_ = us.ShutdownContext(shutdown)
	_ = ts.ShutdownContext(shutdown)
	_ = hs.Shutdown(shutdown)
	return err
}

func Reload(ctx context.Context) error {
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", ControlSocket)
	}}}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/reload", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("DNS reload failed: %s", strings.TrimSpace(string(b)))
	}
	return nil
}
