package config

const (
	TrafficSelective = "selective"
	TrafficFullVPN   = "full-vpn"
)

func (s Stack) TrafficMode() string {
	if s.Front.TrafficMode == "" {
		return TrafficSelective
	}
	return s.Front.TrafficMode
}

func (s Stack) FullVPN() bool { return s.TrafficMode() == TrafficFullVPN }

// EffectiveClientDNS overlays full-VPN policy without destroying the saved
// selective DNS configuration. Router bootstrap and private zones stay native.
func (s Stack) EffectiveClientDNS() ClientDNS {
	d := s.DNS
	if !s.FullVPN() {
		return d
	}
	all := false
	d.OnlyProxyDomains = &all
	if d.Mode == DNSModeSystem || d.Mode == "" {
		d.Mode = DNSModeCustom
	}
	if len(d.Resolvers) == 0 {
		d.Resolvers = append([]string(nil), DefaultClientDNS().Resolvers...)
	}
	return d
}
