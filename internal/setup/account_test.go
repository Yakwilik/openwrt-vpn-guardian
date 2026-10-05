package setup

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestRequestAccountValidatesAndKeepsPasswordBytes(t *testing.T) {
	for _, password := range []string{"p4sswd", strings.Repeat("ab", 16), "пар", "  padded-password  "} {
		var output bytes.Buffer
		input := "\n \t\n  admin  \n" + password + "\n" + password + "\nyes\n"
		credentials, err := RequestAccount(strings.NewReader(input), &output, nil)
		if err != nil {
			t.Fatal(err)
		}
		if credentials.Username != "admin" || credentials.Password != password {
			t.Fatal("account input was not preserved correctly")
		}
		data, err := json.Marshal(credentials)
		if err != nil || string(data) != "{}" {
			t.Fatal("credentials must not appear in JSON")
		}
		assertAccountPrivate(t, output.String()+string(data), password)
	}
}

func TestRequestAccountRejectsInvalidPasswordAndMismatch(t *testing.T) {
	input := strings.Join([]string{
		"admin", "short", strings.Repeat("x", 33), strings.Repeat("я", 17),
		privateToken, "different-password", privateToken, privateToken, "yes",
	}, "\n")
	var output bytes.Buffer
	credentials, err := RequestAccount(strings.NewReader(input), &output, nil)
	if err != nil {
		t.Fatal(err)
	}
	if credentials.Password != privateToken {
		t.Fatal("wizard did not return the confirmed valid password")
	}
	if strings.Count(output.String(), "Password must contain 6-32 bytes.") != 3 || !strings.Contains(output.String(), "Passwords do not match.") {
		t.Fatal("password length and confirmation checks did not run")
	}
	assertAccountPrivate(t, output.String(), privateToken, "different-password")
}

func TestRequestAccountUsesHiddenInputCallback(t *testing.T) {
	var output bytes.Buffer
	reader := bufio.NewReader(strings.NewReader(" admin \nyes\nnext prompt\n"))
	calls := 0
	credentials, err := RequestAccount(reader, &output, func() (string, error) {
		calls++
		return privateToken, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if credentials.Password != privateToken || calls != 2 {
		t.Fatal("password and repeated password must come from the hidden input callback")
	}
	remainder, err := reader.ReadString('\n')
	if err != nil || remainder != "next prompt\n" {
		t.Fatal("account prompt consumed input belonging to the next prompt")
	}
	assertAccountPrivate(t, output.String(), privateToken)
}

func TestRequestAccountCancellationDiscardsCredentials(t *testing.T) {
	for _, input := range []string{
		"", "cancel\n", "admin\n", "admin\ncancel\n",
		"admin\n" + privateToken + "\n",
		"admin\n" + privateToken + "\ncancel\n",
		"admin\n" + privateToken + "\n" + privateToken + "\n",
		"admin\n" + privateToken + "\n" + privateToken + "\nno\n",
	} {
		var output bytes.Buffer
		credentials, err := RequestAccount(strings.NewReader(input), &output, nil)
		if !errors.Is(err, ErrCancelled) || credentials != (Credentials{}) {
			t.Fatal("cancelled account prompt must return no credentials")
		}
		assertAccountPrivate(t, output.String()+err.Error(), privateToken)
	}
}

func TestRequestAccountHiddenInputErrorsArePrivate(t *testing.T) {
	for _, failure := range []error{io.EOF, ErrCancelled, errors.New("terminal failure: " + privateToken)} {
		var output bytes.Buffer
		credentials, err := RequestAccount(strings.NewReader("admin\n"), &output, func() (string, error) {
			return privateToken, failure
		})
		if err == nil || credentials != (Credentials{}) {
			t.Fatal("failed hidden input must return no credentials")
		}
		if (failure == io.EOF || failure == ErrCancelled) && !errors.Is(err, ErrCancelled) {
			t.Fatal("hidden input EOF or cancellation must cancel the wizard")
		}
		assertAccountPrivate(t, output.String()+err.Error(), privateToken)
	}
}

func TestRequestAccountMissingAndFailedStreams(t *testing.T) {
	tests := []struct {
		input  io.Reader
		output io.Writer
	}{
		{nil, io.Discard}, {strings.NewReader("admin\n"), nil},
		{failingReader{}, io.Discard}, {strings.NewReader("admin\n"), failingWriter{}},
	}
	for _, tt := range tests {
		credentials, err := RequestAccount(tt.input, tt.output, nil)
		if err == nil || credentials != (Credentials{}) {
			t.Fatal("missing or broken streams must fail without credentials")
		}
		assertAccountPrivate(t, err.Error(), privateToken)
	}
}

func TestConfigureFreshInstallCreatesRequestedAccountBeforeImport(t *testing.T) {
	env := newSetupEnvironmentStub()
	env.draft.HasEligibleNodes = false
	env.draft.SelectionConfirmed = false
	env.needsAccount = true
	env.eligible = []bool{true}
	input := "all\nhttps://sub.example.test/feed\n\nyes\nadmin\n" + privateToken + "\n" + privateToken + "\nyes\n"
	var output bytes.Buffer
	err := Configure(context.Background(), env, Options{Interactive: true}, strings.NewReader(input), &output)
	if err != nil {
		t.Fatal(err)
	}
	if env.credentials.Username != "admin" || env.credentials.Password != privateToken {
		t.Fatal("the backend did not receive the user's confirmed account")
	}
	assertSetupCalls(t, env, []string{"installed", "draft", "validate", "prepare", "account-check", "access", "backend-check", "import", "nodes", "activate"})
	assertAccountPrivate(t, output.String(), privateToken)
}

func TestConfigureAccountRequirementStopsNonInteractiveSetup(t *testing.T) {
	env := newSetupEnvironmentStub()
	env.needsAccount = true
	err := Configure(context.Background(), env, Options{}, unexpectedSetupInput{t}, io.Discard)
	if !errors.Is(err, ErrInputRequired) {
		t.Fatal("a missing account must require interactive setup")
	}
	assertSetupCalls(t, env, []string{"installed", "draft", "validate", "prepare", "account-check"})
}

func TestConfigureAccountCancellationStopsBeforeCreation(t *testing.T) {
	env := newSetupEnvironmentStub()
	env.needsAccount = true
	err := Configure(context.Background(), env, Options{Interactive: true}, strings.NewReader("cancel\n"), io.Discard)
	if !errors.Is(err, ErrCancelled) {
		t.Fatal("account wizard should cancel setup")
	}
	assertSetupCalls(t, env, []string{"installed", "draft", "validate", "prepare", "account-check"})
}

func TestConfigureAccountCreationErrorsDoNotLeakPasswords(t *testing.T) {
	env := newSetupEnvironmentStub()
	env.needsAccount = true
	env.accessError = errors.New("failed account request with password " + privateToken)
	input := "admin\n" + privateToken + "\n" + privateToken + "\nyes\n"
	var output bytes.Buffer
	err := Configure(context.Background(), env, Options{Interactive: true}, strings.NewReader(input), &output)
	if err == nil {
		t.Fatal("failed account creation must abort setup")
	}
	assertSetupCalls(t, env, []string{"installed", "draft", "validate", "prepare", "account-check", "access"})
	assertAccountPrivate(t, output.String()+err.Error(), privateToken)
}

func TestConfigureExistingAccountDoesNotRequestPassword(t *testing.T) {
	env := newSetupEnvironmentStub()
	opts := Options{ReadSecret: func() (string, error) {
		t.Fatal("existing account must not prompt for a password")
		return "", nil
	}}
	if err := Configure(context.Background(), env, opts, unexpectedSetupInput{t}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if env.credentials != (Credentials{}) {
		t.Fatal("existing account must configure access without replacement credentials")
	}
}

func TestConfigureDryRunDoesNotCreateMissingAccount(t *testing.T) {
	env := newSetupEnvironmentStub()
	env.needsAccount = true
	env.failAt = "backend-check"
	err := Configure(context.Background(), env, Options{Interactive: true, DryRun: true}, unexpectedSetupInput{t}, io.Discard)
	if !errors.Is(err, errSetupFixture) {
		t.Fatal("dry-run must report inaccessible backend authentication")
	}
	assertSetupCalls(t, env, []string{"installed", "draft", "validate", "backend-check"})
}

func assertAccountPrivate(t *testing.T, output string, passwords ...string) {
	t.Helper()
	for _, password := range passwords {
		if strings.Contains(output, password) {
			t.Fatal("an account password leaked into output, JSON, or an error")
		}
	}
}
