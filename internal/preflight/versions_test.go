package preflight

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
)

func TestManagerVersionMinimum(t *testing.T) {
	for _, tc := range []struct {
		version string
		valid   bool
	}{
		{"2.5.8", true},
		{"v2.5.8", true},
		{"2.5.9", true},
		{"2.6.0", true},
		{"3.0.0", true},
		{"2.5.8+build.1", true},
		{"2.6.0-rc.1", true},
		{"2.5.7", false},
		{"2.4.99", false},
		{"1.100.100", false},
		{"2.2.7.3", false},
		{"2.5.8-rc.1", false},
		{"2.6.0-rc.01", false},
		{"02.5.8", false},
		{"2.5", false},
		{"", false},
		{"private-token", false},
	} {
		t.Run(tc.version, func(t *testing.T) {
			_, err := managerVersion(tc.version)
			if (err == nil) != tc.valid {
				t.Fatalf("version accepted=%v, want %v; err=%v", err == nil, tc.valid, err)
			}
			if err != nil && strings.Contains(err.Error(), "private-token") {
				t.Fatal("version diagnostic leaked command output")
			}
		})
	}
}

func TestCoreVersionUsesV2rayAReleaseNotXrayMetadata(t *testing.T) {
	manager, err := managerVersion("2.5.8")
	if err != nil {
		t.Fatal(err)
	}
	core, err := coreVersion("V2RAYA_CORE 2.5.8 (based on xray-core 26.7.28)")
	if err != nil || core != manager {
		t.Fatalf("core release=%+v, error=%v; want manager release", core, err)
	}
	for _, value := range []string{"", "Xray 26.7.28", "V2RAYA_CORE", "V2RAYA_CORE private-token"} {
		if _, err := coreVersion(value); err == nil || strings.Contains(err.Error(), "private-token") {
			t.Fatalf("invalid core banner diagnostic=%v", err)
		}
	}
}

func TestPreflightRequiresUsableMatchingManagerAndCore(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*fakeRunner)
		id     string
	}{
		{"missing manager", func(r *fakeRunner) { r.missing = map[string]error{"v2raya": fs.ErrNotExist} }, "v2raya"},
		{"legacy firmware manager", func(r *fakeRunner) { r.versions["v2raya"] = "2.2.7.3" }, "v2raya"},
		{"unreadable version", func(r *fakeRunner) { r.versions["v2raya"] = "private-token" }, "v2raya"},
		{"missing core", func(r *fakeRunner) { r.missing = map[string]error{"v2raya_core": fs.ErrNotExist} }, "v2raya-core"},
		{"core cannot execute", func(r *fakeRunner) { r.fail = map[string]error{"v2raya_core": errors.New("private-token")} }, "v2raya-core"},
		{"ordinary Xray is not the manager core", func(r *fakeRunner) { r.versions["v2raya_core"] = "Xray 26.7.28" }, "v2raya-core"},
		{"mismatched core", func(r *fakeRunner) { r.versions["v2raya_core"] = "V2RAYA_CORE 2.5.9 (based on xray-core 26.7.28)" }, "v2raya-core"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, env, _, runner := fixture(t)
			tc.change(runner)
			report, err := check(context.Background(), opts, env)
			if err == nil {
				t.Fatal("incompatible manager/core pair passed readiness")
			}
			failed := result(t, report, tc.id)
			if failed.Ready || !strings.Contains(failed.Action, "companion") || !strings.Contains(failed.Action, "2.5.8") {
				t.Fatalf("missing actionable compatibility diagnostic: %+v", failed)
			}
			if strings.Contains(err.Error(), "private-token") {
				t.Fatal("private version output leaked into the report")
			}
		})
	}
}

func TestVersionCheckHonorsDeadline(t *testing.T) {
	opts, env, _, runner := fixture(t)
	opts.CommandTimeout = 10 * time.Millisecond
	runner.wait = "v2raya_core"
	report, err := check(context.Background(), opts, env)
	if !errors.Is(err, context.DeadlineExceeded) || result(t, report, "v2raya-core").Ready {
		t.Fatalf("blocked version probe did not time out: %v", err)
	}
	if !result(t, report, "v2raya").Ready {
		t.Fatal("working manager was incorrectly rejected with blocked core")
	}
}

func TestBackendAssetsAreCheckedSeparatelyFromFrontAssets(t *testing.T) {
	for _, asset := range []string{"geosite", "geoip"} {
		t.Run(asset, func(t *testing.T) {
			opts, env, files, _ := fixture(t)
			delete(files, strings.TrimPrefix(filepath.Join(paths.V2rayAAssetsDir, asset+".dat"), "/"))
			report, err := check(context.Background(), opts, env)
			if err == nil || result(t, report, "v2raya-"+asset).Ready {
				t.Fatal("missing v2rayA asset passed readiness")
			}
			if !result(t, report, "geosite").Ready {
				t.Fatal("backend asset failure incorrectly rejected front assets")
			}
		})
	}
}
