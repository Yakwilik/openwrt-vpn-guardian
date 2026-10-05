package setup

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
)

// Environment owns router operations. The coordinator keeps all input and
// validation ahead of activation, which is the only operation allowed to
// install interception or start Guardian's routing services.
type Environment interface {
	CheckInstalled(context.Context) error
	LoadDraft(context.Context) (Draft, error)
	Validate(context.Context, config.Stack, config.Routing) error
	CheckBackend(context.Context) error
	PrepareBackend(context.Context) error
	NeedsAccount(context.Context) (bool, error)
	ConfigureBackendAccess(context.Context, Credentials) error
	HasEligibleNodes(context.Context, config.Selection) (bool, error)
	ImportSubscriptions(context.Context, []string) error
	Activate(context.Context, config.Stack, config.Routing) error
}

type Options struct {
	Interactive bool
	Reconfigure bool
	DryRun      bool
	ReadSecret  func() (string, error)
}

// Configure gathers a complete draft, checks the runtime and only then hands
// it to Activate. Non-interactive callers never read stdin or invent answers.
func Configure(ctx context.Context, env Environment, opts Options, in io.Reader, out io.Writer) error {
	if env == nil || out == nil {
		return errors.New("setup environment and output are required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := env.CheckInstalled(ctx); err != nil {
		return fmt.Errorf("dependency checks failed: %w", err)
	}
	draft, err := env.LoadDraft(ctx)
	if err != nil {
		return fmt.Errorf("read setup configuration: %w", err)
	}

	needsInput := !draft.SelectionConfirmed || !draft.HasEligibleNodes ||
		draft.Stack.Validate() != nil || draft.Routing.Validate() != nil
	if opts.DryRun {
		if needsInput {
			return fmt.Errorf("%w: run vpn-guardian init in a terminal", ErrInputRequired)
		}
		if err := env.Validate(ctx, draft.Stack, draft.Routing); err != nil {
			return fmt.Errorf("configuration checks failed: %w", err)
		}
		if err := env.CheckBackend(ctx); err != nil {
			return fmt.Errorf("backend access checks failed: %w", err)
		}
		_, err := fmt.Fprintln(out, "Preflight OK; no configuration or services changed.")
		return err
	}

	if in != nil {
		if _, ok := in.(*bufio.Reader); !ok {
			in = bufio.NewReader(in)
		}
	}
	result := Result{Stack: draft.Stack, Routing: draft.Routing}
	if needsInput || opts.Reconfigure && opts.Interactive {
		if opts.Reconfigure {
			draft.SelectionConfirmed = false
		}
		if !opts.Interactive {
			return fmt.Errorf("%w: run vpn-guardian init in a terminal", ErrInputRequired)
		}
		result, err = Run(in, out, draft)
		if err != nil {
			return err
		}
	}
	if err := result.Stack.Validate(); err != nil {
		return fmt.Errorf("stack configuration incomplete: %w", err)
	}
	if err := result.Routing.Validate(); err != nil {
		return fmt.Errorf("routing configuration incomplete: %w", err)
	}
	if err := env.Validate(ctx, result.Stack, result.Routing); err != nil {
		return fmt.Errorf("configuration checks failed: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, "Configuration checked. Preparing VPN backend..."); err != nil {
		return err
	}
	if err := prepareBackendAccess(ctx, env, opts, in, out); err != nil {
		return err
	}
	if err := env.ImportSubscriptions(ctx, result.SubscriptionURLs); err != nil {
		return err
	}
	eligible, err := env.HasEligibleNodes(ctx, result.Stack.Selection)
	if err != nil {
		return fmt.Errorf("read allowed VPN nodes: %w", err)
	}
	if !eligible && opts.Interactive && len(result.SubscriptionURLs) == 0 {
		if _, err := fmt.Fprintln(out, "No nodes match the selected transports. Add a subscription:"); err != nil {
			return err
		}
		urls, err := RequestSubscriptions(in, out)
		if err != nil {
			return err
		}
		if err := env.ImportSubscriptions(ctx, urls); err != nil {
			return err
		}
		eligible, err = env.HasEligibleNodes(ctx, result.Stack.Selection)
		if err != nil {
			return fmt.Errorf("read imported VPN nodes: %w", err)
		}
	}
	if !eligible {
		return errors.New("no VPN nodes match selection.allowedTransports; update the subscription or run vpn-guardian init to change the selection")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := env.Activate(ctx, result.Stack, result.Routing); err != nil {
		return fmt.Errorf("activation checks failed: %w", err)
	}
	_, err = fmt.Fprintln(out, "Setup complete.")
	return err
}

func prepareBackendAccess(ctx context.Context, env Environment, opts Options, in io.Reader, out io.Writer) error {
	if err := env.PrepareBackend(ctx); err != nil {
		return fmt.Errorf("prepare VPN backend: %w", err)
	}
	needed, err := env.NeedsAccount(ctx)
	if err != nil {
		return fmt.Errorf("check v2rayA account: %w", err)
	}
	var credentials Credentials
	if needed {
		if !opts.Interactive {
			return fmt.Errorf("%w: create a v2rayA account with vpn-guardian init in a terminal", ErrInputRequired)
		}
		credentials, err = RequestAccount(in, out, opts.ReadSecret)
		if err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := env.ConfigureBackendAccess(ctx, credentials); err != nil {
		if needed {
			// This boundary receives a password. Never expose a downstream error
			// that might contain the request body or credentials.
			return errors.New("could not create the v2rayA account or configure backend access; check the v2rayA service")
		}
		return fmt.Errorf("configure v2rayA backend access: %w", err)
	}
	if err := env.CheckBackend(ctx); err != nil {
		return fmt.Errorf("backend access checks failed: %w", err)
	}
	return nil
}
