package policy

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/dnsfront"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
)

func Status() string {
	if b, err := os.ReadFile(paths.PolicyMode); err == nil {
		if mode := strings.TrimSpace(string(b)); validPublicMode(mode) {
			return mode
		}
	}
	return "killswitch"
}

func Runtime() string {
	if b, err := os.ReadFile(paths.PolicyRuntime); err == nil {
		mode := strings.TrimSpace(string(b))
		if validRuntimeMode(mode) {
			return mode
		}
	}
	return Status()
}

func Apply(mode string) error {
	if !validRuntimeMode(mode) {
		return fmt.Errorf("invalid policy mode %q", mode)
	}
	public := mode
	if mode == "killswitch-blocked" {
		public = "killswitch"
	}

	src := filepath.Join(paths.GeneratedDir, "policy-"+mode+".json")
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("policy config %s: %w", src, err)
	}
	if out, err := exec.Command("/usr/bin/xray", "run", "-test", "-config", src).CombinedOutput(); err != nil {
		return fmt.Errorf("validate %s: %w: %s", src, err, strings.TrimSpace(string(out)))
	}

	if err := copyAtomic(src, paths.PolicyConfig, 0600); err != nil {
		return err
	}

	if out, err := exec.Command("/etc/init.d/vpn-policy", "restart").CombinedOutput(); err != nil {
		return fmt.Errorf("restart vpn-policy: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if err := waitPolicyReady(4 * time.Second); err != nil {
		return err
	}

	if mode != "killswitch-blocked" {
		if err := writeAtomic(paths.PolicyMode, []byte(public+"\n"), 0600); err != nil {
			return err
		}
	}
	if err := writeAtomic(paths.PolicyRuntime, []byte(mode+"\n"), 0600); err != nil {
		return err
	}
	return dnsfront.ClearCache()
}

func validPublicMode(mode string) bool {
	return mode == "killswitch" || mode == "failopen" || mode == "direct"
}

func validRuntimeMode(mode string) bool {
	return validPublicMode(mode) || mode == "killswitch-blocked"
}

func waitPolicyReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:20177", 250*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			if out, statusErr := exec.Command("/etc/init.d/vpn-policy", "status").CombinedOutput(); statusErr == nil && strings.Contains(string(out), "running") {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("vpn-policy did not become ready on 127.0.0.1:20177")
}

func copyAtomic(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return writeAtomic(dst, b, mode)
}

func writeAtomic(path string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
