package api

import (
	"net"
	"net/http/httptest"
	"testing"
)

func TestRequestClientIPTrustsForwardedOnlyFromLoopback(t *testing.T) {
	t.Run("direct peer cannot spoof forwarded IP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://router/", nil)
		req.RemoteAddr = "192.0.2.10:12345"
		req.Header.Set("X-Real-IP", "192.168.8.20")

		got := requestClientIP(req)
		if got == nil || !got.Equal(net.ParseIP("192.0.2.10")) {
			t.Fatalf("client IP = %v, want direct peer", got)
		}
	})

	t.Run("loopback proxy may forward client IP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://router/", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("X-Real-IP", "192.168.8.20")

		got := requestClientIP(req)
		if got == nil || !got.Equal(net.ParseIP("192.168.8.20")) {
			t.Fatalf("client IP = %v, want forwarded LAN client", got)
		}
	})
}

func TestIPInCIDR(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		cidr string
		want bool
	}{
		{name: "inside", ip: "192.168.8.20", cidr: "192.168.8.0/24", want: true},
		{name: "outside", ip: "192.168.1.20", cidr: "192.168.8.0/24", want: false},
		{name: "ipv6 inside", ip: "fd00::10", cidr: "fd00::/64", want: true},
		{name: "invalid cidr", ip: "192.168.8.20", cidr: "not-a-cidr", want: false},
		{name: "empty", ip: "192.168.8.20", cidr: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ipInCIDR(net.ParseIP(tt.ip), tt.cidr); got != tt.want {
				t.Fatalf("ipInCIDR(%q, %q) = %v, want %v", tt.ip, tt.cidr, got, tt.want)
			}
		})
	}
}

func TestValidSessionToken(t *testing.T) {
	valid := "0123456789abcdef0123456789abcdef0123456789abcdef"
	if !validSessionToken(valid) {
		t.Fatal("valid token rejected")
	}
	for _, token := range []string{"", "abc", valid + "00", "zz23456789abcdef0123456789abcdef0123456789abcdef"} {
		if validSessionToken(token) {
			t.Fatalf("invalid token accepted: %q", token)
		}
	}
}
