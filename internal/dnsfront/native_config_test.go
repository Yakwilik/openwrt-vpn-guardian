package dnsfront

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeCheckReadsActiveOpenWrtExtraConfig(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "dnsmasq.conf")
	extraDir := filepath.Join(dir, "dnsmasq.d")
	if err := os.Mkdir(extraDir, 0755); err != nil {
		t.Fatal(err)
	}
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	includes := "conf-file=" + LocalConfigPath + "\nservers-file=" + SelectorsPath + "\n"
	extra := filepath.Join(extraDir, "extraconfig.conf")
	write(extra, includes)
	defaults := "server=9.9.9.9\nserver=8.8.8.8\nresolv-file=" + WANResolvFile + "\n"
	// A stale file in an unreferenced directory must not satisfy active wiring.
	write(main, defaults)
	if err := checkNativeConfigFile(main, nil); err == nil || !strings.Contains(err.Error(), "servers-file="+SelectorsPath) || !strings.Contains(err.Error(), "conf-file="+LocalConfigPath) {
		t.Fatalf("inactive includes accepted or missing details omitted: %v", err)
	}
	for _, filters := range []string{"", ",*.conf", ",.bak", ",*", ",*.txt,*.conf"} {
		write(main, defaults+"conf-dir="+extraDir+filters+"\n")
		if err := checkNativeConfigFile(main, nil); err != nil {
			t.Errorf("rejected active OpenWrt include with %q: %v", filters, err)
		}
	}
	for _, filters := range []string{",.conf", ",*.txt", ",*.conf,.conf"} {
		write(main, defaults+"conf-dir="+extraDir+filters+"\n")
		if err := checkNativeConfigFile(main, nil); err == nil {
			t.Errorf("accepted excluded OpenWrt include with %q", filters)
		}
	}
	write(main, defaults+"conf-dir="+extraDir+"\n")
	write(extra, includes+"server=127.0.0.1#20176\n")
	if err := checkNativeConfigFile(main, nil); err == nil || !strings.Contains(err.Error(), extra) || !strings.Contains(err.Error(), "non-recursive") {
		t.Fatalf("recursive default in active extra config accepted or location omitted: %v", err)
	}
	write(extra, includes)
	write(main, "conf-dir="+extraDir+"\nno-resolv\n")
	if err := checkNativeConfigFile(main, nil); err == nil || !strings.Contains(err.Error(), "default upstream") {
		t.Fatalf("missing native default accepted or not explained: %v", err)
	}
	if err := os.Remove(extra); err != nil {
		t.Fatal(err)
	}
	write(main, defaults+includes+"conf-dir="+extraDir+"\n")
	if err := checkNativeConfigFile(main, nil); err != nil {
		t.Fatalf("direct main-config includes should remain supported: %v", err)
	}
}
