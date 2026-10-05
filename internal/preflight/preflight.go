// Package preflight checks whether the installed runtime can be used before
// bootstrap changes services or activates transparent routing. Checks are
// read-only: they never start a service, change routing, or probe a TPROXY port.
package preflight

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
)

// Stage separates install-time checks from checks that need an initialized
// v2rayA manager. Neither stage requires a working VPN node.
type Stage string

const (
	Installed Stage = "installed"
	Runtime   Stage = "runtime"

	defaultCommandTimeout = 5 * time.Second
)

// Runner is the command boundary. Run must honor cancellation, discard command
// output, and return only execution errors; command output may contain secrets.
// Version captures a bounded first line only for explicit version commands.
type Runner interface {
	LookPath(name string) (string, error)
	Run(ctx context.Context, name string, args ...string) error
	Version(ctx context.Context, name string, args ...string) (string, error)
}

type Options struct {
	Stage          Stage
	AssetsDir      string
	CommandTimeout time.Duration
	// Stack, when supplied, selects assets and checks that its LAN/WAN devices
	// exist. The caller validates manifest completeness before this check.
	Stack  *config.Stack
	Runner Runner
}

type Result struct {
	Name    string `json:"name"`
	Ready   bool   `json:"ready"`
	Problem string `json:"problem,omitempty"`
	Action  string `json:"action,omitempty"`
	cause   error
}

type Report struct {
	Stage  Stage    `json:"stage"`
	Checks []Result `json:"checks"`
}

// Err combines every failed check so users can fix all missing prerequisites
// in one pass. Successful checks never contribute an error.
func (r Report) Err() error {
	var failures []error
	for _, check := range r.Checks {
		if check.Ready {
			continue
		}
		cause := check.cause
		if cause == nil {
			cause = errors.New(check.Problem)
		}
		failures = append(failures, fmt.Errorf("%s: %w; %s", check.Name, cause, check.Action))
	}
	if len(failures) == 0 {
		return nil
	}
	return fmt.Errorf("%s preflight failed: %w", r.Stage, errors.Join(failures...))
}

type environment struct {
	files    fs.FS
	euid     func() int
	database func(context.Context) error
	api      func(context.Context) error
}

// Check reports installed dependencies, their usability and local API access.
// Missing dependencies cause an error before the caller activates the stack.
// A stopped manager is allowed at Installed stage; Runtime must be called after
// the caller has initialized/started the manager.
func Check(ctx context.Context, opts Options) (Report, error) {
	return check(ctx, opts, environment{
		files:    os.DirFS("/"),
		euid:     os.Geteuid,
		database: checkDatabase,
		api:      checkAPI,
	})
}

func check(ctx context.Context, opts Options, env environment) (Report, error) {
	if opts.Stage == "" {
		opts.Stage = Installed
	}
	report := Report{Stage: opts.Stage, Checks: []Result{}}
	add := func(name, action string, err error) {
		result := Result{Name: name, Ready: err == nil}
		if err != nil {
			result.Problem = err.Error()
			result.Action = action
			result.cause = err
		}
		report.Checks = append(report.Checks, result)
	}
	if opts.Stage != Installed && opts.Stage != Runtime {
		add("stage", "Use installed or runtime.", fmt.Errorf("unknown stage %q", opts.Stage))
		return report, report.Err()
	}
	if err := ctx.Err(); err != nil {
		add("context", "Retry the check with a live context.", err)
		return report, report.Err()
	}
	if opts.CommandTimeout <= 0 {
		opts.CommandTimeout = defaultCommandTimeout
	}
	if opts.Runner == nil {
		opts.Runner = commandRunner{}
	}
	if env.euid() != 0 {
		add("privileges", "Run vpn-guardian as root on the router.", errors.New("root privileges are required"))
	} else {
		add("privileges", "", nil)
	}

	commands := []commandCheck{
		{"xray", "xray", []string{"version"}, "Install or reinstall xray-core for this router architecture."},
		{"nft", "nft", []string{"list", "tables"}, "Install nftables-json and check root access to the kernel firewall."},
		{"ip-rules", "ip", []string{"rule", "show"}, "Install ip-full and check access to policy routing."},
		{"ip-routes", "ip", []string{"route", "show"}, "Install ip-full and check access to kernel routes."},
		{"uci", "uci", []string{"-q", "show", "network"}, "Install uci and restore readable OpenWrt network configuration."},
		{"ubus", "ubus", []string{"call", "system", "board"}, "Check that ubus and procd are installed and running."},
		{"network-manager", "ubus", []string{"call", "network.interface", "dump"}, "Check that netifd is installed, running and accessible through ubus."},
	}
	if opts.Stack != nil {
		commands = append(commands,
			commandCheck{"lan-interface", "ip", []string{"link", "show", "dev", opts.Stack.LANInterface}, "Correct lanInterface or restore the LAN network device."},
			commandCheck{"wan-interface", "ip", []string{"link", "show", "dev", opts.Stack.WANInterface}, "Correct wanInterface or restore the WAN network device."},
		)
	}
	for _, cmd := range commands {
		if err := ctx.Err(); err != nil {
			add("context", "Retry the check with a live context.", err)
			return report, report.Err()
		}
		add(cmd.name, cmd.action, runCheck(ctx, opts, cmd))
	}

	manager, managerErr := runVersionCheck(ctx, opts, "v2raya", []string{"--version"}, managerVersion)
	add("v2raya", v2rayAPackageAction, managerErr)
	core, coreErr := runVersionCheck(ctx, opts, "v2raya_core", []string{"version"}, coreVersion)
	if coreErr == nil && managerErr == nil && core != manager {
		coreErr = errors.New("v2raya_core release does not match the v2rayA manager release")
	}
	add("v2raya-core", v2rayAPackageAction, coreErr)

	for _, file := range []struct {
		name string
		path string
	}{
		{"api-service", paths.APIServiceInit},
		{"bootstrap-service", paths.BootstrapServiceInit},
		{"routing-hotplug", paths.FrontRoutingHotplug},
		{"v2raya-service", paths.V2rayAServiceInit},
	} {
		add(file.name, "Reinstall the package providing "+file.path+" and restore its read/execute permissions.", checkFile(env.files, file.path, true))
	}

	assetsDir := opts.AssetsDir
	if assetsDir == "" && opts.Stack != nil {
		assetsDir = opts.Stack.AssetsDir
	}
	if assetsDir == "" {
		assetsDir = detectAssetsDir(env.files)
	}
	add("geosite", "Install v2ray-geosite or correct assetsDir in stack.json.", checkFile(env.files, filepath.Join(assetsDir, "geosite.dat"), false))
	for _, asset := range []string{"geosite", "geoip"} {
		add("v2raya-"+asset, "Install or reinstall the companion v2raya package and v2ray-"+asset+" data.",
			checkFile(env.files, filepath.Join(paths.V2rayAAssetsDir, asset+".dat"), false))
	}
	add("ca-bundle", "Install or reinstall ca-bundle so HTTPS subscriptions and health checks can verify certificates.", checkCABundle(env.files, paths.CACertificateBundle))

	if opts.Stage == Runtime {
		dbErr := checkSQLiteFile(env.files, paths.V2rayADB)
		if dbErr == nil {
			dbCtx, cancel := context.WithTimeout(ctx, opts.CommandTimeout)
			dbErr = env.database(dbCtx)
			cancel()
		}
		add("v2raya-database", "Start or repair v2rayA and check access to its initialized database.", dbErr)
		// Do not ask the client to open a missing database; its normal token
		// source is also used by mutating control operations.
		if dbErr == nil {
			apiCtx, cancel := context.WithTimeout(ctx, opts.CommandTimeout)
			err := env.api(apiCtx)
			cancel()
			add("v2raya-api", "Check the local v2rayA manager, its database/JWT state and access to 127.0.0.1:2017.", err)
		}
	}
	return report, report.Err()
}

type commandCheck struct {
	name       string
	executable string
	args       []string
	action     string
}

func runCheck(ctx context.Context, opts Options, check commandCheck) error {
	path, err := opts.Runner.LookPath(check.executable)
	if err != nil {
		return fmt.Errorf("executable %s is missing or not executable: %w", check.executable, err)
	}
	cmdCtx, cancel := context.WithTimeout(ctx, opts.CommandTimeout)
	defer cancel()
	if err := opts.Runner.Run(cmdCtx, path, check.args...); err != nil {
		if cmdCtx.Err() != nil {
			return fmt.Errorf("%s usability check: %w", check.executable, cmdCtx.Err())
		}
		return fmt.Errorf("%s is installed but its read-only check failed: %w", check.executable, err)
	}
	return nil
}
