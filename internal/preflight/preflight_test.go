package preflight

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
)

type fakeRunner struct {
	missing  map[string]error
	versions map[string]string
	fail     map[string]error
	wait     string
	calls    []string
}

func (r *fakeRunner) LookPath(name string) (string, error) {
	if err := r.missing[name]; err != nil {
		return "", err
	}
	return "/usr/bin/" + name, nil
}

func (r *fakeRunner) Run(ctx context.Context, name string, args ...string) error {
	name = filepath.Base(name)
	r.calls = append(r.calls, strings.Join(append([]string{name}, args...), " "))
	if r.wait == name {
		<-ctx.Done()
		return ctx.Err()
	}
	return r.fail[name]
}

func (r *fakeRunner) Version(ctx context.Context, name string, args ...string) (string, error) {
	if err := r.Run(ctx, name, args...); err != nil {
		return "", err
	}
	return r.versions[filepath.Base(name)], nil
}

func fixture(t *testing.T) (Options, environment, fstest.MapFS, *fakeRunner) {
	t.Helper()
	files := fstest.MapFS{}
	for _, path := range []string{paths.APIServiceInit, paths.BootstrapServiceInit, paths.FrontRoutingHotplug, paths.V2rayAServiceInit} {
		files[strings.TrimPrefix(path, "/")] = &fstest.MapFile{Data: []byte("#!/bin/sh\n"), Mode: 0755}
	}
	files["usr/share/xray/geosite.dat"] = &fstest.MapFile{Data: []byte("geosite fixture"), Mode: 0644}
	files[strings.TrimPrefix(paths.CACertificateBundle, "/")] = &fstest.MapFile{Data: testCA(t), Mode: 0644}
	for _, asset := range []string{"geosite.dat", "geoip.dat"} {
		files[strings.TrimPrefix(filepath.Join(paths.V2rayAAssetsDir, asset), "/")] = &fstest.MapFile{Data: []byte("backend asset fixture"), Mode: 0644}
	}
	runner := &fakeRunner{versions: map[string]string{
		"v2raya":      "2.5.8",
		"v2raya_core": "V2RAYA_CORE 2.5.8 (based on xray-core 26.7.28)",
	}}
	env := environment{
		files: files,
		euid:  func() int { return 0 },
		database: func(context.Context) error {
			t.Fatal("installed checks must not open a database")
			return nil
		},
		api: func(context.Context) error {
			t.Fatal("installed checks must not contact v2rayA")
			return nil
		},
	}
	return Options{Runner: runner}, env, files, runner
}

func testCA(t *testing.T) []byte {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(2000000000, 0),
		KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func result(t *testing.T, report Report, name string) Result {
	t.Helper()
	for _, check := range report.Checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("missing result %q in %+v", name, report)
	return Result{}
}

func TestInstalledChecksAreReadOnlyAndAllowUninitializedManager(t *testing.T) {
	opts, env, _, runner := fixture(t)
	report, err := check(context.Background(), opts, env)
	if err != nil {
		t.Fatal(err)
	}
	if report.Stage != Installed {
		t.Fatalf("default stage = %q", report.Stage)
	}
	for _, call := range runner.calls {
		for _, forbidden := range []string{" add ", " del ", " delete ", " flush ", " start", " restart", " stop", "52346", "connect"} {
			if strings.Contains(" "+call+" ", forbidden) {
				t.Errorf("readiness ran an unsafe command: %q", call)
			}
		}
	}
	if len(runner.calls) == 0 {
		t.Fatal("dependency presence without usability checks is insufficient")
	}
	if report.Err() != nil {
		t.Fatal(report.Err())
	}
}

func TestCheckAggregatesMissingAndUnusableDependencies(t *testing.T) {
	opts, env, files, runner := fixture(t)
	runner.missing = map[string]error{"xray": fs.ErrNotExist}
	runner.fail = map[string]error{"nft": errors.New("operation not permitted")}
	delete(files, strings.TrimPrefix(paths.FrontRoutingHotplug, "/"))
	env.euid = func() int { return 1000 }
	report, err := check(context.Background(), opts, env)
	if err == nil {
		t.Fatal("incomplete installation passed")
	}
	for _, name := range []string{"privileges", "xray", "nft", "routing-hotplug"} {
		got := result(t, report, name)
		if got.Ready || got.Problem == "" || got.Action == "" {
			t.Errorf("failure does not explain the remedy: %+v", got)
		}
		if !strings.Contains(err.Error(), name) {
			t.Errorf("aggregate error omits %s", name)
		}
	}
	if !result(t, report, "v2raya").Ready {
		t.Fatal("unrelated working dependency was reported as failing")
	}
}

func TestCheckTimesOutBlockedCommandAndContinues(t *testing.T) {
	opts, env, _, runner := fixture(t)
	opts.CommandTimeout = 10 * time.Millisecond
	runner.wait = "xray"
	report, err := check(context.Background(), opts, env)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline error was lost: %v", err)
	}
	if result(t, report, "xray").Ready || !result(t, report, "network-manager").Ready {
		t.Fatal("one blocked command should fail without suppressing other diagnostics")
	}
}

func TestCancelledCheckDoesNotExecuteCommands(t *testing.T) {
	opts, env, _, runner := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := check(ctx, opts, env)
	if !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatalf("canceled preflight continued: err=%v calls=%v", err, runner.calls)
	}
}

func TestSelectedAssetsAndInterfacesAreChecked(t *testing.T) {
	opts, env, files, runner := fixture(t)
	opts.Stack = &config.Stack{LANInterface: "br-lan", WANInterface: "pppoe-wan", AssetsDir: "/custom/assets"}
	// A valid default directory must not hide a broken explicit configuration.
	report, err := check(context.Background(), opts, env)
	if err == nil || result(t, report, "geosite").Ready {
		t.Fatal("missing configured assets were silently replaced with defaults")
	}
	files["custom/assets/geosite.dat"] = &fstest.MapFile{Data: []byte("geosite fixture"), Mode: 0644}
	_, err = check(context.Background(), opts, env)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"ip link show dev br-lan", "ip link show dev pppoe-wan"} {
		if !strings.Contains(strings.Join(runner.calls, "\n"), required) {
			t.Errorf("missing device usability check %q", required)
		}
	}
}

func TestRuntimeRequiresInitializedDatabaseBeforeAPI(t *testing.T) {
	opts, env, _, _ := fixture(t)
	opts.Stage = Runtime
	report, err := check(context.Background(), opts, env)
	if err == nil || result(t, report, "v2raya-database").Ready {
		t.Fatal("runtime accepted an uninitialized manager")
	}
	// fixture callbacks fail the test if invoked. A missing database must
	// never reach the normal API token source, which can create databases.
}

func TestRuntimeChecksDatabaseAndAuthenticatedAPIWithoutVPN(t *testing.T) {
	opts, env, files, _ := fixture(t)
	opts.Stage = Runtime
	files[strings.TrimPrefix(paths.V2rayADB, "/")] = &fstest.MapFile{Data: []byte("SQLite format 3\x00fixture"), Mode: 0600}
	var order []string
	env.database = func(ctx context.Context) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("database check has no deadline")
		}
		order = append(order, "database")
		return nil
	}
	env.api = func(ctx context.Context) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("API check has no deadline")
		}
		order = append(order, "api")
		return nil
	}
	report, err := check(context.Background(), opts, env)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "database,api" || !result(t, report, "v2raya-api").Ready {
		t.Fatalf("incorrect readiness ordering: %v", order)
	}
	encoded, err := json.Marshal(report)
	if err != nil || !strings.Contains(string(encoded), `"stage":"runtime"`) {
		t.Fatalf("report cannot be consumed by CLI/API: %s, %v", encoded, err)
	}
}

func TestStaticServicesAndTrustMustBeUsable(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		data []byte
		mode fs.FileMode
		id   string
	}{
		{"non-executable service", paths.APIServiceInit, []byte("#!/bin/sh"), 0644, "api-service"},
		{"empty service", paths.BootstrapServiceInit, nil, 0755, "bootstrap-service"},
		{"invalid CA certificates", paths.CACertificateBundle, []byte("broken PEM"), 0644, "ca-bundle"},
		{"empty geosite", "/usr/share/xray/geosite.dat", nil, 0644, "geosite"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, env, files, _ := fixture(t)
			files[strings.TrimPrefix(tc.path, "/")] = &fstest.MapFile{Data: tc.data, Mode: tc.mode}
			report, err := check(context.Background(), opts, env)
			if err == nil || result(t, report, tc.id).Ready {
				t.Fatalf("unusable file passed: %+v", report)
			}
		})
	}
}
