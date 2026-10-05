package setup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
)

func TestConfigureEarlyFailuresDoNotPrepareBackend(t *testing.T) {
	tests := []struct {
		name   string
		change func(*setupEnvironmentStub)
		opts   Options
		input  string
		want   error
		calls  []string
	}{
		{"missing dependencies", func(e *setupEnvironmentStub) { e.failAt = "installed" }, Options{}, "", errSetupFixture, []string{"installed"}},
		{"unreadable draft", func(e *setupEnvironmentStub) { e.failAt = "draft" }, Options{}, "", errSetupFixture, []string{"installed", "draft"}},
		{"missing network without terminal", func(e *setupEnvironmentStub) { e.draft.Stack.LANInterface = "" }, Options{}, "", ErrInputRequired, []string{"installed", "draft"}},
		{"unconfirmed selection without terminal", func(e *setupEnvironmentStub) { e.draft.SelectionConfirmed = false }, Options{}, "", ErrInputRequired, []string{"installed", "draft"}},
		{"missing selection without terminal", func(e *setupEnvironmentStub) { e.draft.Stack.Selection.AllowedTransports = nil }, Options{}, "", ErrInputRequired, []string{"installed", "draft"}},
		{"missing nodes without terminal", func(e *setupEnvironmentStub) { e.draft.HasEligibleNodes = false }, Options{}, "", ErrInputRequired, []string{"installed", "draft"}},
		{"invalid required configuration", func(e *setupEnvironmentStub) { e.draft.Stack.Backend.SocksPort = 0 }, Options{Interactive: true}, "yes\n", nil, []string{"installed", "draft"}},
		{"invalid routing configuration", func(e *setupEnvironmentStub) { e.draft.Routing.Version = 0 }, Options{Interactive: true}, "yes\n", nil, []string{"installed", "draft"}},
		{"wizard cancelled", func(e *setupEnvironmentStub) { e.draft.SelectionConfirmed = false }, Options{Interactive: true}, "cancel\n", ErrCancelled, []string{"installed", "draft"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newSetupEnvironmentStub()
			tt.change(env)
			var input io.Reader = unexpectedSetupInput{t}
			if tt.opts.Interactive {
				input = strings.NewReader(tt.input)
			}
			err := Configure(context.Background(), env, tt.opts, input, io.Discard)
			if err == nil || tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatal("expected setup to fail before backend preparation")
			}
			assertSetupCalls(t, env, tt.calls)
		})
	}
}

func TestConfigureRuntimeFailuresForbidActivation(t *testing.T) {
	tests := []struct {
		name     string
		failAt   string
		eligible []bool
		calls    []string
	}{
		{"generated configuration invalid", "validate", nil, []string{"installed", "draft", "validate"}},
		{"backend unavailable", "prepare", nil, []string{"installed", "draft", "validate", "prepare"}},
		{"account state unavailable", "account-check", nil, []string{"installed", "draft", "validate", "prepare", "account-check"}},
		{"backend access configuration fails", "access", nil, []string{"installed", "draft", "validate", "prepare", "account-check", "access"}},
		{"authenticated backend inaccessible", "backend-check", nil, []string{"installed", "draft", "validate", "prepare", "account-check", "access", "backend-check"}},
		{"subscription import fails", "import", nil, []string{"installed", "draft", "validate", "prepare", "account-check", "access", "backend-check", "import"}},
		{"node inventory unavailable", "nodes", nil, []string{"installed", "draft", "validate", "prepare", "account-check", "access", "backend-check", "import", "nodes"}},
		{"no allowed nodes remain", "", []bool{false}, []string{"installed", "draft", "validate", "prepare", "account-check", "access", "backend-check", "import", "nodes"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newSetupEnvironmentStub()
			env.failAt = tt.failAt
			env.eligible = tt.eligible
			err := Configure(context.Background(), env, Options{}, unexpectedSetupInput{t}, io.Discard)
			if err == nil || tt.failAt != "" && !errors.Is(err, errSetupFixture) {
				t.Fatal("runtime failure must abort setup")
			}
			assertSetupCalls(t, env, tt.calls)
		})
	}
}

func TestConfigureCompleteNonInteractiveNeverReadsInput(t *testing.T) {
	env := newSetupEnvironmentStub()
	var output bytes.Buffer
	if err := Configure(context.Background(), env, Options{}, unexpectedSetupInput{t}, &output); err != nil {
		t.Fatal(err)
	}
	assertSetupCalls(t, env, []string{"installed", "draft", "validate", "prepare", "account-check", "access", "backend-check", "import", "nodes", "activate"})
	if !strings.Contains(output.String(), "Setup complete.") {
		t.Fatal("successful setup did not report completion")
	}
}

func TestConfigureValidatesBeforeImportAndActivation(t *testing.T) {
	env := newSetupEnvironmentStub()
	env.draft.SelectionConfirmed = false
	env.draft.HasEligibleNodes = false
	env.eligible = []bool{true}
	url := "https://sub.example.test/" + privateToken
	input := "1,3\n" + url + "\n\nyes\n"
	var output bytes.Buffer
	if err := Configure(context.Background(), env, Options{Interactive: true}, strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	assertSetupCalls(t, env, []string{"installed", "draft", "validate", "prepare", "account-check", "access", "backend-check", "import", "nodes", "activate"})
	if len(env.imports) != 1 || !slices.Equal(env.imports[0], []string{url}) {
		t.Fatal("confirmed subscription batch was not imported exactly once")
	}
	if !reflect.DeepEqual(env.validatedStack, env.activatedStack) || !reflect.DeepEqual(env.validatedRouting, env.activatedRouting) {
		t.Fatal("activation used a configuration different from the validated draft")
	}
	if len(env.selections) != 1 || !slices.Equal(env.selections[0].AllowedTransports, env.activatedStack.Selection.AllowedTransports) {
		t.Fatal("eligibility was not checked for the activated selection")
	}
	assertPrivate(t, output.String())
}

func TestConfigureImportedSubscriptionsMustProvideAllowedNodes(t *testing.T) {
	env := newSetupEnvironmentStub()
	env.draft.HasEligibleNodes = false
	env.eligible = []bool{false}
	input := "https://sub.example.test/" + privateToken + "\n\nyes\n"
	var output bytes.Buffer
	err := Configure(context.Background(), env, Options{Interactive: true}, strings.NewReader(input), &output)
	if err == nil || !strings.Contains(err.Error(), "no VPN nodes match") {
		t.Fatal("a successful import without allowed nodes must not activate routing")
	}
	assertSetupCalls(t, env, []string{"installed", "draft", "validate", "prepare", "account-check", "access", "backend-check", "import", "nodes"})
	assertPrivate(t, output.String()+err.Error())
}

func TestConfigureDryRunHasNoMutations(t *testing.T) {
	tests := []struct {
		name       string
		failAt     string
		incomplete bool
		want       error
		calls      []string
	}{
		{"ready", "", false, nil, []string{"installed", "draft", "validate", "backend-check"}},
		{"incomplete", "", true, ErrInputRequired, []string{"installed", "draft"}},
		{"invalid generated configuration", "validate", false, errSetupFixture, []string{"installed", "draft", "validate"}},
		{"backend inaccessible", "backend-check", false, errSetupFixture, []string{"installed", "draft", "validate", "backend-check"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newSetupEnvironmentStub()
			env.failAt = tt.failAt
			if tt.incomplete {
				env.draft.SelectionConfirmed = false
			}
			var output bytes.Buffer
			err := Configure(context.Background(), env, Options{DryRun: true, Interactive: true, Reconfigure: true}, unexpectedSetupInput{t}, &output)
			if !errors.Is(err, tt.want) {
				t.Fatalf("dry-run error = %v, want %v", err, tt.want)
			}
			assertSetupCalls(t, env, tt.calls)
			if len(env.imports) != 0 || !reflect.DeepEqual(env.activatedStack, config.Stack{}) {
				t.Fatal("dry-run performed an import or activation")
			}
			if tt.want == nil && !strings.Contains(output.String(), "Preflight OK") {
				t.Fatal("successful dry-run did not report preflight completion")
			}
		})
	}
}

func TestConfigureChangedSelectionRequestsAdditionalSubscription(t *testing.T) {
	env := newSetupEnvironmentStub()
	env.eligible = []bool{false, true}
	url := "https://sub.example.test/" + privateToken
	// Both prompts share one input source. The first prompt must leave later
	// subscription input available even if the reader returns it in one read.
	input := "1\nyes\n" + url + "\n\nyes\n"
	var output bytes.Buffer
	err := Configure(context.Background(), env, Options{Interactive: true, Reconfigure: true}, strings.NewReader(input), &output)
	if err != nil {
		t.Fatal(err)
	}
	assertSetupCalls(t, env, []string{"installed", "draft", "validate", "prepare", "account-check", "access", "backend-check", "import", "nodes", "import", "nodes", "activate"})
	wantSelection := config.SupportedTransports()[:1]
	if !slices.Equal(env.activatedStack.Selection.AllowedTransports, wantSelection) {
		t.Fatal("reconfigure did not replace the previous transport selection")
	}
	if len(env.imports) != 2 || len(env.imports[0]) != 0 || !slices.Equal(env.imports[1], []string{url}) {
		t.Fatal("additional subscription input was lost or imported incorrectly")
	}
	if len(env.selections) != 2 {
		t.Fatal("additional import must be followed by a fresh eligibility check")
	}
	for _, selection := range env.selections {
		if !slices.Equal(selection.AllowedTransports, wantSelection) {
			t.Fatal("eligibility check used the previous transport selection")
		}
	}
	assertPrivate(t, output.String())
}

func TestConfigureAdditionalSubscriptionCancellationForbidsActivation(t *testing.T) {
	env := newSetupEnvironmentStub()
	env.eligible = []bool{false}
	input := "1\nyes\ncancel\n"
	err := Configure(context.Background(), env, Options{Interactive: true, Reconfigure: true}, strings.NewReader(input), io.Discard)
	if !errors.Is(err, ErrCancelled) {
		t.Fatal("expected cancellation of the additional subscription prompt")
	}
	assertSetupCalls(t, env, []string{"installed", "draft", "validate", "prepare", "account-check", "access", "backend-check", "import", "nodes"})
}

func TestConfigureContextCancellationStopsNextMutation(t *testing.T) {
	tests := []struct {
		name  string
		stage string
		calls []string
	}{
		{"before dependency checks", "before", nil},
		{"after validation", "validate", []string{"installed", "draft", "validate"}},
		{"before activation", "nodes", []string{"installed", "draft", "validate", "prepare", "account-check", "access", "backend-check", "import", "nodes"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			env := newSetupEnvironmentStub()
			env.afterCall = func(stage string) {
				if stage == tt.stage {
					cancel()
				}
			}
			if tt.stage == "before" {
				cancel()
			}
			if err := Configure(ctx, env, Options{}, unexpectedSetupInput{t}, io.Discard); !errors.Is(err, context.Canceled) {
				t.Fatal("cancelled setup must return the context error")
			}
			assertSetupCalls(t, env, tt.calls)
		})
	}
}

var errSetupFixture = errors.New("setup fixture failure")

type setupEnvironmentStub struct {
	draft            Draft
	calls            []string
	failAt           string
	needsAccount     bool
	credentials      Credentials
	accessError      error
	eligible         []bool
	afterCall        func(string)
	imports          [][]string
	selections       []config.Selection
	validatedStack   config.Stack
	validatedRouting config.Routing
	activatedStack   config.Stack
	activatedRouting config.Routing
}

func newSetupEnvironmentStub() *setupEnvironmentStub {
	draft := readyDraft()
	draft.SelectionConfirmed = true
	return &setupEnvironmentStub{draft: draft}
}

func (e *setupEnvironmentStub) record(stage string) error {
	e.calls = append(e.calls, stage)
	if e.afterCall != nil {
		e.afterCall(stage)
	}
	if e.failAt == stage {
		return errSetupFixture
	}
	return nil
}

func (e *setupEnvironmentStub) CheckInstalled(context.Context) error { return e.record("installed") }

func (e *setupEnvironmentStub) LoadDraft(context.Context) (Draft, error) {
	return e.draft, e.record("draft")
}

func (e *setupEnvironmentStub) Validate(_ context.Context, stack config.Stack, routing config.Routing) error {
	e.validatedStack, e.validatedRouting = stack, routing
	return e.record("validate")
}

func (e *setupEnvironmentStub) CheckBackend(context.Context) error { return e.record("backend-check") }

func (e *setupEnvironmentStub) PrepareBackend(context.Context) error { return e.record("prepare") }

func (e *setupEnvironmentStub) NeedsAccount(context.Context) (bool, error) {
	return e.needsAccount, e.record("account-check")
}

func (e *setupEnvironmentStub) ConfigureBackendAccess(_ context.Context, credentials Credentials) error {
	e.credentials = credentials
	if err := e.record("access"); err != nil {
		return err
	}
	return e.accessError
}

func (e *setupEnvironmentStub) HasEligibleNodes(_ context.Context, selection config.Selection) (bool, error) {
	selection.AllowedTransports = slices.Clone(selection.AllowedTransports)
	e.selections = append(e.selections, selection)
	if err := e.record("nodes"); err != nil {
		return false, err
	}
	if len(e.eligible) > 0 {
		value := e.eligible[0]
		e.eligible = e.eligible[1:]
		return value, nil
	}
	return e.draft.HasEligibleNodes, nil
}

func (e *setupEnvironmentStub) ImportSubscriptions(_ context.Context, urls []string) error {
	e.imports = append(e.imports, slices.Clone(urls))
	return e.record("import")
}

func (e *setupEnvironmentStub) Activate(_ context.Context, stack config.Stack, routing config.Routing) error {
	e.activatedStack, e.activatedRouting = stack, routing
	return e.record("activate")
}

func assertSetupCalls(t *testing.T, env *setupEnvironmentStub, want []string) {
	t.Helper()
	if !slices.Equal(env.calls, want) {
		t.Fatalf("setup operation order = %v, want %v", env.calls, want)
	}
}

type unexpectedSetupInput struct{ t *testing.T }

func (r unexpectedSetupInput) Read([]byte) (int, error) {
	r.t.Fatal("non-interactive setup attempted to read input")
	return 0, io.EOF
}
