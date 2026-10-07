package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDNSRuntimeIsConservativeDuringTransitions(t *testing.T) {
	for _, tt := range []struct{ name, control, runtime, want string }{
		{"healthy VPN", `{"mode":"auto","failurePolicy":"killswitch"}`, "killswitch", "killswitch"},
		{"failopen", `{"mode":"auto","failurePolicy":"failopen"}`, "failopen", "failopen"},
		{"failopen stabilized direct", `{"mode":"auto","failurePolicy":"failopen"}`, "failopen-direct", "direct"},
		{"pinned failopen", `{"mode":"pinned","failurePolicy":"failopen"}`, "failopen", "failopen"},
		{"direct", `{"mode":"direct","failurePolicy":"killswitch"}`, "direct", "direct"},
		{"tightening", `{"mode":"auto","failurePolicy":"killswitch"}`, "failopen", "killswitch"},
		{"loosening not applied", `{"mode":"auto","failurePolicy":"failopen"}`, "killswitch", "killswitch"},
		{"leaving direct", `{"mode":"auto","failurePolicy":"killswitch"}`, "direct", "killswitch"},
		{"blocked overrides direct", `{"mode":"direct","failurePolicy":"failopen"}`, "killswitch-blocked", "killswitch-blocked"},
		{"invalid control", "{", "failopen", "killswitch"},
		{"invalid runtime", `{"mode":"auto","failurePolicy":"failopen"}`, "garbage", "killswitch"},
		{"missing control", "", "direct", "killswitch"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "etc/vpn-guardian")
			os.MkdirAll(dir, 0700)
			if tt.control != "" {
				os.WriteFile(filepath.Join(dir, "control.json"), []byte(tt.control), 0600)
			}
			os.WriteFile(filepath.Join(dir, "policy-runtime"), []byte(tt.runtime), 0600)
			if got := DNSRuntimeAt(root); got != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
	if DNSRuntimeAt(t.TempDir()) != "killswitch" {
		t.Fatal("missing state allowed direct")
	}
}
