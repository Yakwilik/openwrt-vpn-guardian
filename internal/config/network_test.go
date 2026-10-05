package config

import "testing"

func TestValidateInterfaceName(t *testing.T) {
	tests := []struct {
		value string
		valid bool
	}{
		{"br-lan", true},
		{"eth0.2", true},
		{"123456789012345", true},
		{"", false},
		{"1234567890123456", false},
		{".", false},
		{"..", false},
		{"br/lan", false},
		{"eth0:1", false},
		{" br-lan", false},
		{"br-lan ", false},
		{"br lan", false},
		{"br\tlan", false},
		{"br\nlan", false},
		{"br\x00lan", false},
		{"br\u00a0lan", false},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			if err := ValidateInterfaceName(tt.value); (err == nil) != tt.valid {
				t.Fatalf("ValidateInterfaceName(%q) = %v, valid=%v", tt.value, err, tt.valid)
			}
		})
	}
}

func TestValidateLANCIDR(t *testing.T) {
	tests := []struct {
		value string
		valid bool
	}{
		{"192.168.1.0/24", true},
		{"192.168.1.1/24", true},
		{"10.0.0.1/32", true},
		{"0.0.0.0/0", true},
		{"", false},
		{"192.168.1.1", false},
		{"192.168.1.0/33", false},
		{"192.168.256.0/24", false},
		{" 192.168.1.0/24", false},
		{"2001:db8::/64", false},
		{"::ffff:192.168.1.0/120", false},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			if err := ValidateLANCIDR(tt.value); (err == nil) != tt.valid {
				t.Fatalf("ValidateLANCIDR(%q) = %v, valid=%v", tt.value, err, tt.valid)
			}
		})
	}
}

func TestStackRejectsIncompleteSetup(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Stack)
	}{
		{"invalid lan interface", func(s *Stack) { s.LANInterface = "br lan" }},
		{"invalid wan interface", func(s *Stack) { s.WANInterface = "wan/0" }},
		{"invalid lan prefix", func(s *Stack) { s.LANCIDR = "192.168.1.1" }},
		{"IPv6 lan prefix", func(s *Stack) { s.LANCIDR = "2001:db8::/64" }},
		{"relative assets path", func(s *Stack) { s.AssetsDir = "usr/share/xray" }},
		{"missing assets path", func(s *Stack) { s.AssetsDir = "" }},
		{"missing selection", func(s *Stack) { s.Selection = Selection{} }},
		{"invalid selection", func(s *Stack) { s.Selection.AllowedTransports = []Transport{"vless"} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stack := DefaultStack("br-lan", "192.168.1.0/24", "eth0", "/usr/share/xray")
			tt.mutate(&stack)
			if err := stack.Validate(); err == nil {
				t.Fatal("incomplete stack unexpectedly validated")
			}
		})
	}
}
