package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
)

const Version = 1

type Stack struct {
	Version      int       `json:"version"`
	LANInterface string    `json:"lanInterface"`
	LANCIDR      string    `json:"lanCidr"`
	WANInterface string    `json:"wanInterface"`
	AssetsDir    string    `json:"assetsDir"`
	Front        Front     `json:"front"`
	Backend      Backend   `json:"backend"`
	DNS          ClientDNS `json:"dns"`
	Dashboard    Dashboard `json:"dashboard"`
	Policy       Policy    `json:"policy"`
	Selection    Selection `json:"selection"`
	Bypass4      []string  `json:"bypass4"`
}

type Front struct {
	SocksPort        int `json:"socksPort"`
	TProxyPort       int `json:"tproxyPort"`
	PolicyPort       int `json:"policyPort"`
	Mark             int `json:"mark"`
	RouteTable       int `json:"routeTable"`
	DirectSocketMark int `json:"directSocketMark"`
}

type Backend struct {
	SocksPort        int    `json:"socksPort"`
	WatchdogInterval string `json:"watchdogInterval"`
}

const (
	DNSModeSystem    = "system"
	DNSModeCustom    = "custom"
	DNSModeXray      = "xray"
	legacyDNSModeVPN = "vpn"
)

type ClientDNS struct {
	OnlyProxyDomains *bool    `json:"onlyProxyDomains,omitempty"`
	Mode             string   `json:"mode"`
	ListenPort       int      `json:"listenPort"`
	XrayPort         int      `json:"xrayPort"`
	Resolvers        []string `json:"resolvers"`
}

func (d ClientDNS) ProxyOnly() bool { return d.OnlyProxyDomains == nil || *d.OnlyProxyDomains }

func DefaultClientDNS() ClientDNS {
	onlyProxy := true
	return ClientDNS{
		OnlyProxyDomains: &onlyProxy,
		Mode:             DNSModeCustom,
		ListenPort:       20176,
		XrayPort:         20178,
		Resolvers:        []string{"1.1.1.1", "9.9.9.9"},
	}
}

func XrayDNSServers() []string {
	return []string{"tcp://1.1.1.1:53", "tcp://9.9.9.9:53"}
}

// NormalizeStack fills fields added to the v1 manifest after its initial
// release. Existing manifests stay valid without weakening validation of
// fields that have always been required.
func NormalizeStack(s Stack) Stack {
	defaults := DefaultClientDNS()
	if strings.TrimSpace(s.DNS.Mode) == "" {
		s.DNS.Mode = defaults.Mode
	}
	if s.DNS.Mode == legacyDNSModeVPN {
		s.DNS.Mode = DNSModeCustom
	}
	if s.DNS.ListenPort == 0 {
		s.DNS.ListenPort = defaults.ListenPort
	}
	if s.DNS.XrayPort == 0 {
		s.DNS.XrayPort = defaults.XrayPort
	}
	if s.DNS.Resolvers == nil {
		s.DNS.Resolvers = append([]string(nil), defaults.Resolvers...)
	}
	return s
}

// DNSResolverEndpoint validates a resolver without performing DNS itself.
// Hostnames are deliberately rejected so the client-DNS path can never create
// a recursive dependency on router/system DNS.
func DNSResolverEndpoint(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("DNS resolver must not be empty")
	}
	port := 53
	if addr, err := netip.ParseAddr(value); err == nil {
		if !addr.Is4() {
			return "", fmt.Errorf("DNS resolver %q must be an IPv4 address", value)
		}
		return net.JoinHostPort(addr.String(), strconv.Itoa(port)), nil
	}

	parsedHost, parsedPort, err := net.SplitHostPort(value)
	if err != nil {
		return "", fmt.Errorf("DNS resolver %q must be a numeric IPv4 address with optional port", value)
	}
	addr, err := netip.ParseAddr(parsedHost)
	if err != nil || !addr.Is4() {
		return "", fmt.Errorf("DNS resolver %q must use a numeric IPv4 address", value)
	}
	port64, err := strconv.ParseUint(parsedPort, 10, 16)
	if err != nil || port64 == 0 {
		return "", fmt.Errorf("DNS resolver %q has an invalid port", value)
	}
	return net.JoinHostPort(addr.String(), strconv.Itoa(int(port64))), nil
}

type Dashboard struct {
	CollectorInterval string `json:"collectorInterval"`
}

type Policy struct {
	Default       string `json:"default"`
	ProbeURL      string `json:"probeUrl"`
	ProbeInterval string `json:"probeInterval"`
}

type Routing struct {
	Version      int               `json:"version"`
	ProxyDomains []string          `json:"proxyDomains"`
	ProxyIPs     []string          `json:"proxyIps"`
	Notes        map[string]string `json:"notes,omitempty"`
}

func DefaultStack(lanInterface, lanCIDR, wanInterface, assetsDir string) Stack {
	return Stack{
		Version:      Version,
		LANInterface: lanInterface,
		LANCIDR:      lanCIDR,
		WANInterface: wanInterface,
		AssetsDir:    assetsDir,
		Front: Front{
			SocksPort:        20174,
			TProxyPort:       52346,
			PolicyPort:       20177,
			Mark:             192,
			RouteTable:       101,
			DirectSocketMark: 128,
		},
		Backend: Backend{
			SocksPort:        20173,
			WatchdogInterval: "10s",
		},
		DNS: DefaultClientDNS(),
		Dashboard: Dashboard{
			CollectorInterval: "3s",
		},
		Policy: Policy{
			Default:       "killswitch",
			ProbeURL:      "https://connectivitycheck.gstatic.com/generate_204",
			ProbeInterval: "5s",
		},
		Selection: Selection{AllowedTransports: SupportedTransports()},
		Bypass4: []string{
			"0.0.0.0/8",
			"10.0.0.0/8",
			"100.64.0.0/10",
			"127.0.0.0/8",
			"169.254.0.0/16",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"224.0.0.0/3",
		},
	}
}

func DefaultRouting() Routing {
	return Routing{
		Version: Version,
		ProxyDomains: []string{
			"geosite:openai",
			"geosite:anthropic",
			"geosite:google-gemini",
			"geosite:github",
			"geosite:youtube",
			"geosite:telegram",
			"geosite:whatsapp",
			"geosite:soundcloud",
			"geosite:linkedin",
			"domain:jetbrains.com",
			"domain:descript.com",
			"domain:descriptusercontent.com",
			"domain:heygen.com",
			"domain:heygen.ai",
			"domain:buf.build",
		},
		Notes: map[string]string{
			"geosite:openai":                 "OpenAI / ChatGPT",
			"geosite:anthropic":              "Anthropic / Claude",
			"geosite:google-gemini":          "Google Gemini",
			"geosite:github":                 "GitHub",
			"geosite:youtube":                "YouTube",
			"geosite:telegram":               "Домены Telegram",
			"geosite:whatsapp":               "WhatsApp",
			"geosite:soundcloud":             "SoundCloud",
			"geosite:linkedin":               "LinkedIn",
			"domain:jetbrains.com":           "Обновления JetBrains IDE и Toolbox",
			"domain:descript.com":            "Descript: веб-приложение, API, авторизация, транскрипция и first-party CDN",
			"domain:descriptusercontent.com": "Descript: пользовательские медиа, файлы и assets",
			"domain:heygen.com":              "HeyGen: веб-приложение, API и first-party сервисы",
			"domain:heygen.ai":               "HeyGen: сгенерированные видео и media/CDN (files2, resource2)",
			"domain:buf.build":               "Buf Schema Registry",
		},
	}
}

func Load() (Stack, Routing, error) {
	return LoadFiles(paths.StackConfig, paths.RoutingConfig)
}

func LoadStack() (Stack, error) {
	var cfg Stack
	if err := readJSON(paths.StackConfig, &cfg); err != nil {
		return cfg, err
	}
	cfg = NormalizeStack(cfg)
	if err := cfg.Validate(); err != nil {
		return Stack{}, err
	}
	return cfg, nil
}

func SaveStack(cfg Stack) error {
	return saveStackFile(paths.StackConfig, NormalizeStack(cfg))
}

func SaveRouting(cfg Routing) error {
	return saveRoutingFile(paths.RoutingConfig, cfg)
}

func saveStackFile(path string, cfg Stack) error {
	cfg = NormalizeStack(cfg)
	if err := cfg.Validate(); err != nil {
		return err
	}
	return saveJSONFile(path, cfg)
}

func saveRoutingFile(path string, cfg Routing) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	return saveJSONFile(path, cfg)
}

func saveJSONFile(path string, value any) (err error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".vpn-guardian-stack-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()

	if err := file.Chmod(0600); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func LoadFiles(stackPath, routingPath string) (Stack, Routing, error) {
	var stack Stack
	var routing Routing

	if err := readJSON(stackPath, &stack); err != nil {
		return stack, routing, err
	}
	if err := readJSON(routingPath, &routing); err != nil {
		return stack, routing, err
	}
	stack = NormalizeStack(stack)
	if err := stack.Validate(); err != nil {
		return stack, routing, err
	}
	if err := routing.Validate(); err != nil {
		return stack, routing, err
	}
	return stack, routing, nil
}

func (s Stack) Validate() error {
	if s.Version != Version {
		return fmt.Errorf("unsupported stack manifest version %d", s.Version)
	}
	if err := ValidateInterfaceName(s.LANInterface); err != nil {
		return fmt.Errorf("lanInterface: %w", err)
	}
	if err := ValidateLANCIDR(s.LANCIDR); err != nil {
		return fmt.Errorf("lanCidr: %w", err)
	}
	if err := ValidateInterfaceName(s.WANInterface); err != nil {
		return fmt.Errorf("wanInterface: %w", err)
	}
	if !filepath.IsAbs(s.AssetsDir) {
		return errors.New("assetsDir must be an absolute path to Xray assets")
	}
	if err := s.Selection.Validate(); err != nil {
		return err
	}

	if err := validatePort("front.socksPort", s.Front.SocksPort); err != nil {
		return err
	}
	if err := validatePort("front.tproxyPort", s.Front.TProxyPort); err != nil {
		return err
	}
	if err := validatePort("front.policyPort", s.Front.PolicyPort); err != nil {
		return err
	}
	if err := validatePort("backend.socksPort", s.Backend.SocksPort); err != nil {
		return err
	}
	if err := validatePort("dns.listenPort", s.DNS.ListenPort); err != nil {
		return err
	}
	for _, p := range []int{53, 20175, s.Front.SocksPort, s.Front.TProxyPort, s.Front.PolicyPort, s.Backend.SocksPort} {
		if s.DNS.ListenPort == p || s.DNS.XrayPort == p {
			return fmt.Errorf("DNS listener conflicts with existing port %d", p)
		}
	}
	if len(s.DNS.Resolvers) > 8 {
		return errors.New("dns.resolvers must contain at most 8 resolvers")
	}
	if err := validatePort("dns.xrayPort", s.DNS.XrayPort); err != nil {
		return err
	}
	if s.DNS.ListenPort == s.DNS.XrayPort || s.DNS.XrayPort == s.Front.PolicyPort || s.DNS.XrayPort == s.Backend.SocksPort {
		return errors.New("dns.xrayPort must not conflict with Guardian listener ports")
	}
	switch s.DNS.Mode {
	case DNSModeSystem, DNSModeCustom, DNSModeXray:
	default:
		return fmt.Errorf("invalid dns.mode %q", s.DNS.Mode)
	}
	if s.DNS.Mode == DNSModeCustom && len(s.DNS.Resolvers) == 0 {
		return errors.New("dns.resolvers must not be empty in custom mode")
	}
	seenResolvers := make(map[string]struct{}, len(s.DNS.Resolvers))
	for _, resolver := range s.DNS.Resolvers {
		endpoint, err := DNSResolverEndpoint(resolver)
		if err != nil {
			return err
		}
		if _, exists := seenResolvers[endpoint]; exists {
			return fmt.Errorf("duplicate DNS resolver %q", resolver)
		}
		seenResolvers[endpoint] = struct{}{}
	}
	if s.Front.RouteTable <= 0 {
		return errors.New("front.routeTable must be positive")
	}
	if s.Front.Mark <= 0 {
		return errors.New("front.mark must be positive")
	}
	if s.Front.DirectSocketMark <= 0 {
		return errors.New("front.directSocketMark must be positive")
	}

	switch s.Policy.Default {
	case "killswitch", "failopen", "direct":
	default:
		return fmt.Errorf("invalid policy.default %q", s.Policy.Default)
	}

	if _, err := parsePositiveDuration("backend.watchdogInterval", s.Backend.WatchdogInterval); err != nil {
		return err
	}
	if _, err := parsePositiveDuration("dashboard.collectorInterval", s.Dashboard.CollectorInterval); err != nil {
		return err
	}
	if _, err := parsePositiveDuration("policy.probeInterval", s.Policy.ProbeInterval); err != nil {
		return err
	}
	if s.Policy.ProbeURL == "" {
		return errors.New("policy.probeUrl is required")
	}
	if len(s.Bypass4) == 0 {
		return errors.New("bypass4 must not be empty")
	}
	return nil
}

func (r Routing) Validate() error {
	if r.Version != Version {
		return fmt.Errorf("unsupported routing manifest version %d", r.Version)
	}
	_, err := r.RulesUnchecked()
	return err
}

func (r Routing) RulesUnchecked() ([]RoutingRule, error) {
	rules := make([]RoutingRule, 0, len(r.ProxyDomains)+len(r.ProxyIPs))
	seen := make(map[string]struct{}, cap(rules))
	stored := make(map[string]struct{}, cap(rules))

	for _, raw := range r.ProxyDomains {
		rule, err := parseStoredRoutingRule(raw, true)
		if err != nil {
			return nil, err
		}
		key := "domain:" + raw
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate routing entry %q", raw)
		}
		seen[key] = struct{}{}
		stored[raw] = struct{}{}
		rule.Note = strings.TrimSpace(r.Notes[raw])
		if _, err := normalizeRoutingNote(rule.Note); err != nil {
			return nil, fmt.Errorf("routing note for %q: %w", raw, err)
		}
		rules = append(rules, rule)
	}
	for _, raw := range r.ProxyIPs {
		rule, err := parseStoredRoutingRule(raw, false)
		if err != nil {
			return nil, err
		}
		key := "ip:" + raw
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate routing entry %q", raw)
		}
		seen[key] = struct{}{}
		stored[raw] = struct{}{}
		rule.Note = strings.TrimSpace(r.Notes[raw])
		if _, err := normalizeRoutingNote(rule.Note); err != nil {
			return nil, fmt.Errorf("routing note for %q: %w", raw, err)
		}
		rules = append(rules, rule)
	}
	for raw, note := range r.Notes {
		if _, exists := stored[raw]; !exists {
			return nil, fmt.Errorf("routing note refers to unknown entry %q", raw)
		}
		if _, err := normalizeRoutingNote(note); err != nil {
			return nil, fmt.Errorf("routing note for %q: %w", raw, err)
		}
	}
	return rules, nil
}

func validatePort(name string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("%s must be between 1 and 65535", name)
	}
	return nil
}

func parsePositiveDuration(name, value string) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	if duration <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}
	return duration, nil
}

func readJSON(path string, dst any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}
