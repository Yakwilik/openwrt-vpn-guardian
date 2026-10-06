package api

import (
	"net"
	"net/http"
	"strings"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
)

func dashboardPeerAllowed(r *http.Request) bool {
	peerIP := requestPeerIP(r)
	if peerIP == nil {
		return false
	}
	if peerIP.IsLoopback() {
		return true
	}
	return ipInCIDR(peerIP, configuredLANCIDR())
}

func isLANRequest(r *http.Request) bool {
	clientIP := requestClientIP(r)
	if clientIP == nil {
		return false
	}
	return ipInCIDR(clientIP, configuredLANCIDR())
}

func requestPeerIP(r *http.Request) net.IP {
	if r == nil {
		return nil
	}
	peer := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(peer); err == nil {
		peer = host
	}
	return net.ParseIP(peer)
}

func requestClientIP(r *http.Request) net.IP {
	peerIP := requestPeerIP(r)
	if peerIP == nil {
		return nil
	}
	if !peerIP.IsLoopback() {
		return peerIP
	}
	if forwarded := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); forwarded != nil {
		return forwarded
	}
	return peerIP
}

func configuredLANCIDR() string {
	cfg, err := config.LoadStack()
	if err != nil {
		return ""
	}
	return cfg.LANCIDR
}

func ipInCIDR(ip net.IP, cidr string) bool {
	if ip == nil || cidr == "" {
		return false
	}
	_, subnet, err := net.ParseCIDR(cidr)
	return err == nil && subnet.Contains(ip)
}
