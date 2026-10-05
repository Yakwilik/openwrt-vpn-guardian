package config

import (
	"fmt"
	"strings"
)

// Transport identifies a supported protocol, transport and security combination.
type Transport string

const (
	TransportHysteria2         Transport = "hysteria2"
	TransportVLESSXHTTPReality Transport = "vless-xhttp-reality"
	TransportShadowsocks       Transport = "shadowsocks"
	TransportVLESSWSTLS        Transport = "vless-ws-tls"
	TransportVLESSTCPReality   Transport = "vless-tcp-reality"
)

type TransportOption struct {
	Value Transport
	Label string
}

// TransportOptions is the shared catalogue for setup and manifest validation.
// The returned slice can be changed by the caller without affecting the catalogue.
func TransportOptions() []TransportOption {
	return []TransportOption{
		{Value: TransportHysteria2, Label: "Hysteria2"},
		{Value: TransportVLESSXHTTPReality, Label: "VLESS XHTTP + Reality"},
		{Value: TransportShadowsocks, Label: "Shadowsocks"},
		{Value: TransportVLESSWSTLS, Label: "VLESS WebSocket + TLS"},
		{Value: TransportVLESSTCPReality, Label: "VLESS TCP + Reality"},
	}
}

func SupportedTransports() []Transport {
	options := TransportOptions()
	out := make([]Transport, 0, len(options))
	for _, option := range options {
		out = append(out, option.Value)
	}
	return out
}

// Selection is an explicit allowlist. Missing, empty and invalid allowlists
// must be completed during setup, never silently replaced while loading config.
type Selection struct {
	AllowedTransports []Transport `json:"allowedTransports"`
}

func (s Selection) Validate() error {
	if len(s.AllowedTransports) == 0 {
		return fmt.Errorf("selection.allowedTransports must contain at least one transport")
	}

	supported := make(map[Transport]struct{})
	labels := make([]string, 0)
	for _, option := range TransportOptions() {
		supported[option.Value] = struct{}{}
		labels = append(labels, string(option.Value))
	}

	seen := make(map[Transport]struct{}, len(s.AllowedTransports))
	for i, transport := range s.AllowedTransports {
		if _, ok := supported[transport]; !ok {
			return fmt.Errorf("selection.allowedTransports[%d]: unsupported transport %q (supported: %s)", i, transport, strings.Join(labels, ", "))
		}
		if _, ok := seen[transport]; ok {
			return fmt.Errorf("selection.allowedTransports contains duplicate %q", transport)
		}
		seen[transport] = struct{}{}
	}
	return nil
}
