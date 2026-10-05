package stack

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mattn/go-isatty"
	"golang.org/x/term"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/lockfile"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/preflight"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/setup"
	v2rayautil "github.com/Yakwilik/openwrt-vpn-guardian/internal/v2raya"
)

func parseSetupArgs(command string, args []string) (setup.Options, error) {
	var opts setup.Options
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	nonInteractive := fs.Bool("non-interactive", false, "fail instead of prompting for missing setup data")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "check an existing configuration without changing the router")
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if fs.NArg() != 0 {
		return opts, fmt.Errorf("%s does not accept positional arguments", command)
	}
	opts.Interactive = !*nonInteractive && isatty.IsTerminal(os.Stdin.Fd()) && isatty.IsTerminal(os.Stdout.Fd())
	opts.Reconfigure = command == "init"
	if opts.Interactive {
		opts.ReadSecret = func() (string, error) {
			secret, err := term.ReadPassword(int(os.Stdin.Fd()))
			return string(secret), err
		}
	}
	return opts, nil
}

func setupCmd(command string, args []string) error {
	opts, err := parseSetupArgs(command, args)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	lock, err := lockfile.Try(paths.SetupLock)
	if err != nil {
		return fmt.Errorf("another initialization is running, or the setup lock is inaccessible: %w", err)
	}
	defer lockfile.Release(lock)

	env := &routerSetup{out: os.Stdout}
	return setup.Configure(ctx, env, opts, os.Stdin, os.Stdout)
}

// routerSetup is the operating-system boundary for the setup coordinator.
// Gathering user input never holds ControlLock; each runtime mutation does.
type routerSetup struct {
	out         io.Writer
	assetsDir   string
	backendPort int
}

func (e *routerSetup) CheckInstalled(ctx context.Context) error {
	var stored config.Stack
	if _, err := readSetupManifest(paths.StackConfig, &stored); err != nil {
		return err
	}
	e.assetsDir = stored.AssetsDir
	if e.assetsDir == "" {
		e.assetsDir = detectAssetsDir()
	}
	_, err := preflight.Check(ctx, preflight.Options{
		Stage: preflight.Installed, AssetsDir: e.assetsDir,
	})
	return err
}

func (e *routerSetup) LoadDraft(ctx context.Context) (setup.Draft, error) {
	lan := detectLANInterface()
	s := config.DefaultStack(lan, detectLANCIDR(lan), detectWANInterface(), detectAssetsDir())
	r := config.DefaultRouting()
	stackPresent, err := readSetupManifest(paths.StackConfig, &s)
	if err != nil {
		return setup.Draft{}, err
	}
	routingPresent, err := readSetupManifest(paths.RoutingConfig, &r)
	if err != nil {
		return setup.Draft{}, err
	}
	if stackPresent != routingPresent {
		return setup.Draft{}, errors.New("only one configuration manifest exists; restore the missing stack.json or routing.json before initialization")
	}
	selection := s.Selection
	if selection.Validate() != nil {
		selection = config.Selection{AllowedTransports: config.SupportedTransports()}
	}
	eligible, err := v2rayautil.HasEligibleNodes(ctx, selection)
	if err != nil {
		return setup.Draft{}, err
	}
	return setup.Draft{
		Stack: s, Routing: r, HasEligibleNodes: eligible,
		SelectionConfirmed: stackPresent && s.Selection.Validate() == nil,
	}, nil
}

// Existing manifests are decoded into a zero value, so missing fields cannot
// inherit defaults and silently pass the configuration gate.
func readSetupManifest[T any](path string, value *T) (bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var parsed T
	if err := json.Unmarshal(b, &parsed); err != nil {
		return false, fmt.Errorf("decode %s: %w", path, err)
	}
	*value = parsed
	return true, nil
}

func (e *routerSetup) Validate(ctx context.Context, s config.Stack, r config.Routing) error {
	e.assetsDir = s.AssetsDir
	e.backendPort = s.Backend.SocksPort
	if _, err := preflight.Check(ctx, preflight.Options{
		Stage: preflight.Installed, AssetsDir: s.AssetsDir, Stack: &s,
	}); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "vpn-guardian-setup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := generate(dir, s, r); err != nil {
		return err
	}
	return validateGenerated(ctx, dir, s.AssetsDir)
}

func (e *routerSetup) CheckBackend(ctx context.Context) error {
	_, err := preflight.Check(ctx, preflight.Options{Stage: preflight.Runtime, AssetsDir: e.assetsDir})
	return err
}

func (e *routerSetup) PrepareBackend(ctx context.Context) error {
	return withSetupControlLock(ctx, func() error {
		if err := ensureV2rayAService(); err != nil {
			return err
		}
		if err := v2rayautil.EnsureBackendOnly(); err != nil {
			return errors.New("v2rayA could not enter backend-only mode; check the v2rayA service log")
		}
		return nil
	})
}

func (e *routerSetup) NeedsAccount(ctx context.Context) (bool, error) {
	return v2rayautil.NeedsAccount(ctx)
}

func (e *routerSetup) ConfigureBackendAccess(ctx context.Context, credentials setup.Credentials) error {
	return withSetupControlLock(ctx, func() error {
		return v2rayautil.ConfigureBackendAccess(ctx, credentials.Username, credentials.Password, e.backendPort)
	})
}

func (e *routerSetup) HasEligibleNodes(ctx context.Context, selection config.Selection) (bool, error) {
	return v2rayautil.HasEligibleNodes(ctx, selection)
}

func (e *routerSetup) ImportSubscriptions(ctx context.Context, urls []string) error {
	if len(urls) == 0 {
		return nil
	}
	return withSetupControlLock(ctx, func() error {
		return v2rayautil.ImportSubscriptions(ctx, urls)
	})
}

func withSetupControlLock(ctx context.Context, f func() error) error {
	lockCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	lock, err := lockfile.Acquire(lockCtx, paths.ControlLock)
	if err != nil {
		return fmt.Errorf("VPN control is busy: %w", err)
	}
	defer lockfile.Release(lock)
	if err := ctx.Err(); err != nil {
		return err
	}
	return f()
}

func (e *routerSetup) Activate(ctx context.Context, s config.Stack, r config.Routing) error {
	return withSetupControlLock(ctx, func() (err error) {
		if err := e.CheckBackend(ctx); err != nil {
			return err
		}
		fmt.Fprintln(e.out, "Checking an allowed VPN node through the backend...")
		restoreBackend, err := v2rayautil.EnsureAllowedBackend(ctx, s.Selection)
		if err != nil {
			return err
		}
		committed := false
		defer func() {
			if !committed {
				restoreCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				err = errors.Join(err, restoreBackend(restoreCtx))
			}
		}()
		if err := ctx.Err(); err != nil {
			return err
		}

		rollback, err := installSetupManifests(paths.StackConfig, paths.RoutingConfig, s, r)
		if err != nil {
			return err
		}
		defer func() {
			if committed {
				return
			}
			err = errors.Join(err, rollback())
			// The API must not keep serving a failed first-time configuration.
			if _, _, loadErr := config.Load(); loadErr != nil {
				_, _ = run(paths.APIServiceInit, "stop")
			} else {
				_, _ = run(paths.APIServiceInit, "restart")
			}
		}()

		if err := setupDashboardRuntime(); err != nil {
			return err
		}
		if err := applyCmd(); err != nil {
			return err
		}
		committed = true
		if err := setupDashboardProxy(); err != nil {
			fmt.Fprintln(e.out, "The optional nginx proxy is unavailable; use the dashboard directly on port 20175.")
		}
		if err := writePrivateAtomic(paths.BootstrapMarker, []byte(time.Now().Format(time.RFC3339)+"\n")); err != nil {
			fmt.Fprintln(e.out, "Routing is active, but the initialization marker could not be saved; bootstrap will check again on boot.")
		}
		if err := setupDashboardDNS(); err != nil {
			fmt.Fprintln(e.out, "The optional vpn.home.arpa DNS name could not be configured; use the dashboard IP address.")
		}
		if addr := detectLANAddress(s.LANInterface); addr != "" {
			fmt.Fprintf(e.out, "Dashboard: http://%s:20175/\n", addr)
		}
		return nil
	})
}

type setupFile struct {
	path   string
	data   []byte
	exists bool
}

func captureSetupFile(path string) (setupFile, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return setupFile{path: path}, nil
	}
	return setupFile{path: path, data: b, exists: err == nil}, err
}

// installSetupManifests keeps the previous pair until activation succeeds.
// Each replacement is private and atomic; any failed second write restores
// the first file before control is returned to the caller.
func installSetupManifests(stackPath, routingPath string, s config.Stack, r config.Routing) (func() error, error) {
	previous := make([]setupFile, 0, 2)
	for _, path := range []string{stackPath, routingPath} {
		file, err := captureSetupFile(path)
		if err != nil {
			return nil, err
		}
		previous = append(previous, file)
	}
	restore := func() error {
		var errs []error
		for _, file := range previous {
			if file.exists {
				errs = append(errs, writePrivateAtomic(file.path, file.data))
			} else if err := os.Remove(file.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	for i, value := range []any{s, r} {
		b, err := json.MarshalIndent(value, "", "  ")
		if err == nil {
			err = writePrivateAtomic(previous[i].path, append(b, '\n'))
		}
		if err != nil {
			return nil, errors.Join(err, restore())
		}
	}
	return restore, nil
}

func writePrivateAtomic(path string, data []byte) (err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".vpn-guardian-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
