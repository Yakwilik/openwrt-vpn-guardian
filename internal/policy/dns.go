package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
)

// DNSRuntimeAt uses the intersection of requested and applied policy. A partial
// transition, missing state, or unreadable state must never grant direct DNS.
// Runtime is reread before a fallback, not cached when the daemon starts.
func DNSRuntimeAt(root string) string {
	read := func(path string) ([]byte, error) {
		return os.ReadFile(filepath.Join(root, strings.TrimPrefix(path, "/")))
	}
	runtime, err := read(paths.PolicyRuntime)
	if err != nil {
		return "killswitch"
	}
	mode := strings.TrimSpace(string(runtime))
	if mode == "killswitch-blocked" {
		return mode
	}
	var control struct {
		Mode          string `json:"mode"`
		FailurePolicy string `json:"failurePolicy"`
	}
	b, err := read(paths.ControlConfig)
	if err != nil || json.Unmarshal(b, &control) != nil {
		return "killswitch"
	}
	if mode == "direct" && control.Mode == "direct" {
		return "direct"
	}
	if (control.Mode == "auto" || control.Mode == "pinned") && control.FailurePolicy == "failopen" {
		if mode == "failopen-direct" {
			return "direct"
		}
		if mode == "failopen" {
			return "failopen"
		}
	}
	return "killswitch"
}
