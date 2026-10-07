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
	SystemResolver   string
	Matcher          *DomainMatcher
	Local            *DomainMatcher
	LAN              *net.IPNet
	LANv6            []*net.IPNet
}

type Server struct {
	current     atomic.Pointer[Runtime]
	localGate   chan struct{}
	proxyGate   chan struct{}
	localCount  atomic.Uint64
	systemCount atomic.Uint64
	proxyCount  atomic.Uint64
	errorCount  atomic.Uint64
}

func newServer(rt *Runtime) *Server {
	s := &Server{localGate: make(chan struct{}, 96), proxyGate: make(chan struct{}, 96)}
	s.current.Store(rt)
	return s
}

func BuildRuntime(s config.Stack, r config.Routing, root string) (*Runtime, error) {
	matcher, err := LoadDomainMatcher(r.ProxyDomains, s.AssetsDir)
	if err != nil {
		return nil, err
	}
	local, err := LocalNames(root)
	if err != nil {
		return nil, err
	}
	_, lan, err := net.ParseCIDR(s.LANCIDR)
	if err != nil {
		return nil, err
	}
	rt := &Runtime{Mode: s.DNS.Mode, OnlyProxyDomains: s.DNS.ProxyOnly(), Matcher: matcher, Local: local, LAN: lan, SystemResolver: "127.0.0.1:53", SOCKSAddr: fmt.Sprintf("127.0.0.1:%d", s.Backend.SocksPort), XrayResolver: fmt.Sprintf("127.0.0.1:%d", s.DNS.XrayPort)}
	source := s.DNS.Resolvers
	if s.DNS.Mode == config.DNSModeXray {
		source = config.DefaultClientDNS().Resolvers
	}
	for _, resolver := range source {
		ep, err := config.DNSResolverEndpoint(resolver)
		if err != nil {
			return nil, err
		}
		rt.Resolvers = append(rt.Resolvers, ep)
	}
	if iface, err := net.InterfaceByName(s.LANInterface); err == nil {
		addresses, _ := iface.Addrs()
		for _, a := range addresses {
			_, n, err := net.ParseCIDR(a.String())
			if err == nil && n.IP.To4() == nil {
				rt.LANv6 = append(rt.LANv6, n)
			}
		}
	}
	return rt, nil
}

func (rt *Runtime) route(name string) string {
	if isLocalName(rt.Local, name) || localReverse(rt, name) {
		return "local"
	}
	if rt.Mode == config.DNSModeSystem || (rt.OnlyProxyDomains && !rt.Matcher.Match(name)) {
		return "system"
	}
	return "proxy"
}

func (s *Server) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {
	rt := s.current.Load()
	host, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	ip := net.ParseIP(strings.Split(host, "%")[0])
	allowed := ip.IsLoopback() || (rt.LAN != nil && rt.LAN.Contains(ip))
	for _, n := range rt.LANv6 {
		allowed = allowed || n.Contains(ip)
	}
	if !allowed {
		writeError(w, q, dns.RcodeRefused)
		return
	}
	if q.Response || q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 {
		writeError(w, q, dns.RcodeFormatError)
		return
	}
	route := rt.route(q.Question[0].Name)
	gate := s.localGate
	if route == "proxy" {
		gate = s.proxyGate
		s.proxyCount.Add(1)
	} else if route == "local" {
		s.localCount.Add(1)
	} else {
		s.systemCount.Add(1)
	}
	select {
	case gate <- struct{}{}:
		defer func() { <-gate }()
	default:
		writeError(w, q, dns.RcodeServerFailure)
		s.errorCount.Add(1)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4500*time.Millisecond)
	defer cancel()
	response, err := rt.exchange(ctx, q, route)
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

func (rt *Runtime) exchange(ctx context.Context, q *dns.Msg, route string) (*dns.Msg, error) {
	if route != "proxy" {
		return exchangeDirect(ctx, q, rt.SystemResolver)
	}
	if rt.Mode == config.DNSModeXray && (q.Question[0].Qtype == dns.TypeA || q.Question[0].Qtype == dns.TypeAAAA) {
		return exchangeDirect(ctx, q, rt.XrayResolver)
	}
	// A proxy failure must never fall back to system/WAN DNS. Retry only the
	// configured VPN resolvers; preserve legitimate NXDOMAIN and empty answers.
	var errs []error
	for _, endpoint := range rt.Resolvers {
		attempt, cancel := context.WithTimeout(ctx, 1800*time.Millisecond)
		dialer, err := proxy.SOCKS5("tcp", rt.SOCKSAddr, nil, &net.Dialer{Timeout: 1800 * time.Millisecond})
		var response *dns.Msg
		if err == nil {
			var conn net.Conn
			conn, err = dialer.(proxy.ContextDialer).DialContext(attempt, "tcp", endpoint)
			if err == nil {
				response, err = exchangeConn(attempt, q, conn)
			}
		}
		cancel()
		if err == nil && response.Rcode != dns.RcodeServerFailure && response.Rcode != dns.RcodeRefused {
			return response, nil
		}
		if err == nil {
			err = fmt.Errorf("upstream returned %s", dns.RcodeToString[response.Rcode])
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
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
	if err := EnsureLocalGuards(); err != nil {
		return err
	}
	rt, err := BuildRuntime(cfg, rules, "/")
	if err != nil {
		return err
	}
	server := newServer(rt)
	addr := fmt.Sprintf(":%d", cfg.DNS.ListenPort)
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
		_ = json.NewEncoder(w).Encode(map[string]any{"mode": rt.Mode, "onlyProxyDomains": rt.OnlyProxyDomains, "local": server.localCount.Load(), "system": server.systemCount.Load(), "proxy": server.proxyCount.Load(), "errors": server.errorCount.Load()})
	})
	hs := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second, WriteTimeout: 5 * time.Second}
	errs := make(chan error, 3)
	go func() { errs <- us.ActivateAndServe() }()
	go func() { errs <- ts.ActivateAndServe() }()
	go func() { errs <- hs.Serve(control) }()
	// DHCP changes do not require a DNS restart. Replace an immutable local map
	// while retaining any concurrently reloaded external/routing configuration.
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				local, err := LocalNames("/")
				if err != nil {
					continue
				}
				for {
					old := server.current.Load()
					next := *old
					next.Local = local
					if server.current.CompareAndSwap(old, &next) {
						break
					}
				}
			}
		}
	}()
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
