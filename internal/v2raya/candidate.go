package v2raya

import (
	"strings"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
)

// CandidatePolicy applies the configured transport allowlist consistently to
// automatic selection, manual controls and the dashboard's eligible node count.
// Its zero value rejects all candidates.
type CandidatePolicy struct {
	allowed map[config.Transport]struct{}
}

func NewCandidatePolicy(selection config.Selection) (CandidatePolicy, error) {
	if err := selection.Validate(); err != nil {
		return CandidatePolicy{}, err
	}

	policy := CandidatePolicy{
		allowed: make(map[config.Transport]struct{}, len(selection.AllowedTransports)),
	}
	for _, transport := range selection.AllowedTransports {
		policy.allowed[transport] = struct{}{}
	}
	return policy, nil
}

// Priority returns the effective selection priority. Lower values are preferred;
// the configured allowlist controls eligibility without changing established ranks.
func (p CandidatePolicy) Priority(protocol, network, security string, sort int) (int, bool) {
	transport, base, supported := candidateTransport(protocol, network, security)
	if !supported {
		return 0, false
	}
	if _, allowed := p.allowed[transport]; !allowed {
		return 0, false
	}
	return base + sort, true
}

func (p CandidatePolicy) Eligible(protocol, network, security string) bool {
	_, eligible := p.Priority(protocol, network, security, 0)
	return eligible
}

func candidateTransport(protocol, network, security string) (config.Transport, int, bool) {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	network = strings.ToLower(strings.TrimSpace(network))
	security = strings.ToLower(strings.TrimSpace(security))

	switch {
	case protocol == "hysteria2":
		return config.TransportHysteria2, 20, true
	case protocol == "vless" && network == "xhttp" && security == "reality":
		return config.TransportVLESSXHTTPReality, 40, true
	case protocol == "shadowsocks":
		return config.TransportShadowsocks, 60, true
	case protocol == "vless" && network == "ws" && security == "tls":
		return config.TransportVLESSWSTLS, 80, true
	case protocol == "vless" && network == "tcp" && security == "reality":
		return config.TransportVLESSTCPReality, 100, true
	default:
		return "", 0, false
	}
}
