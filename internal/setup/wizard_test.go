package setup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
)

const privateToken = "wizard-private-token"

func readyDraft() Draft {
	return Draft{
		Stack:            config.DefaultStack("br-lan", "192.168.40.0/24", "pppoe-wan", "/usr/share/xray"),
		Routing:          config.DefaultRouting(),
		HasEligibleNodes: true,
	}
}

func TestRunCollectsAndValidatesMissingSettings(t *testing.T) {
	draft := readyDraft()
	draft.Stack.LANInterface = ""
	draft.Stack.LANCIDR = ""
	draft.Stack.WANInterface = ""
	draft.HasEligibleNodes = false
	before, err := json.Marshal(draft)
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		"", "bad/interface", "br-home",
		"not-a-subnet", "2001:db8::/64", "192.168.50.1/24",
		"bad:interface", "eth0.2",
		"3,1",
		"https://sub.example.test/" + privateToken,
		"", "yes",
	}, "\n")
	var output bytes.Buffer
	result, err := Run(strings.NewReader(input), &output, draft)
	if err != nil {
		t.Fatal(err)
	}
	if result.Stack.LANInterface != "br-home" || result.Stack.LANCIDR != "192.168.50.0/24" || result.Stack.WANInterface != "eth0.2" {
		t.Fatal("network settings were not validated and normalized")
	}
	options := config.TransportOptions()
	wantTransports := []config.Transport{options[0].Value, options[2].Value}
	if !slices.Equal(result.Stack.Selection.AllowedTransports, wantTransports) {
		t.Fatalf("selected transports = %v, want %v", result.Stack.Selection.AllowedTransports, wantTransports)
	}
	if len(result.SubscriptionURLs) != 1 || !strings.Contains(result.SubscriptionURLs[0], privateToken) {
		t.Fatal("private subscription was not returned to the caller")
	}
	if err := result.Stack.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := result.Routing.Validate(); err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(draft)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("wizard mutated the supplied draft")
	}
	assertPrivate(t, output.String())
}

func TestRunRequiresExplicitTransportSelection(t *testing.T) {
	input := "\n0\n99\n1,1\n1,,3\ninvalid\nall,1\nall\nyes\n"
	var output bytes.Buffer
	result, err := Run(strings.NewReader(input), &output, readyDraft())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(result.Stack.Selection.AllowedTransports, config.SupportedTransports()) {
		t.Fatal("explicit all must select the supported transport list")
	}
	if strings.Count(output.String(), "Choose at least one listed number") != 7 {
		t.Fatal("empty, unknown, or duplicate selections must be rejected")
	}
	if strings.Contains(output.String(), "Subscription URL 1") {
		t.Fatal("existing eligible nodes must not require a new subscription")
	}
}

func TestRunKeepsConfirmedSelection(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		t.Run(fmt.Sprintf("previously-confirmed-%t", confirmed), func(t *testing.T) {
			draft := readyDraft()
			draft.Stack.Selection.AllowedTransports = config.SupportedTransports()[:1]
			draft.SelectionConfirmed = confirmed
			input := "keep\nyes\n"
			if confirmed {
				input = "yes\n"
			}
			var output bytes.Buffer
			result, err := Run(strings.NewReader(input), &output, draft)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(result.Stack.Selection.AllowedTransports, draft.Stack.Selection.AllowedTransports) {
				t.Fatal("current transport selection was not preserved")
			}
			if confirmed && strings.Contains(output.String(), "Choose numbers") {
				t.Fatal("already confirmed selection must not prompt again")
			}
		})
	}
}

func TestRunRepairsMissingSelectionEvenIfPreviouslyConfirmed(t *testing.T) {
	draft := readyDraft()
	draft.Stack.Selection.AllowedTransports = nil
	draft.SelectionConfirmed = true
	result, err := Run(strings.NewReader("keep\nall\nyes\n"), io.Discard, draft)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(result.Stack.Selection.AllowedTransports, config.SupportedTransports()) {
		t.Fatal("missing required selection was not populated")
	}
}

func TestRunValidatesCompleteDraftBeforeConfirmation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Draft)
	}{
		{"missing assets directory", func(d *Draft) { d.Stack.AssetsDir = "" }},
		{"missing backend port", func(d *Draft) { d.Stack.Backend.SocksPort = 0 }},
		{"missing routing version", func(d *Draft) { d.Routing.Version = 0 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			draft := readyDraft()
			tt.mutate(&draft)
			var output bytes.Buffer
			result, err := Run(strings.NewReader("all\nyes\n"), &output, draft)
			if err == nil {
				t.Fatal("incomplete configuration must fail")
			}
			assertEmptyResult(t, result)
			if strings.Contains(output.String(), "Use these settings?") {
				t.Fatal("invalid draft was presented for final confirmation")
			}
		})
	}
}

func TestRunCancellationDiscardsDraftAndSecrets(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		hasEligibleNodes bool
	}{
		{"EOF at transport selection", "", true},
		{"explicit cancel", "cancel\n", true},
		{"EOF at confirmation", "all\n", true},
		{"no at confirmation", "all\nno\n", true},
		{"empty confirmation", "all\n\n", true},
		{"empty subscription then EOF", "all\n\n", false},
		{"secret then EOF", "all\nhttps://sub.example.test/" + privateToken + "\n", false},
		{"secret then cancel", "all\nhttps://sub.example.test/" + privateToken + "\ncancel\n", false},
		{"secret then reject confirmation", "all\nhttps://sub.example.test/" + privateToken + "\n\nno\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			draft := readyDraft()
			draft.HasEligibleNodes = tt.hasEligibleNodes
			var output bytes.Buffer
			result, err := Run(strings.NewReader(tt.input), &output, draft)
			if !errors.Is(err, ErrCancelled) {
				t.Fatal("expected cancellation")
			}
			assertEmptyResult(t, result)
			assertPrivate(t, output.String()+err.Error())
		})
	}
}

func TestRunResultDoesNotAliasDraftSlices(t *testing.T) {
	draft := readyDraft()
	draft.Routing.ProxyIPs = []string{"203.0.113.0/24"}
	result, err := Run(strings.NewReader("keep\nyes\n"), io.Discard, draft)
	if err != nil {
		t.Fatal(err)
	}
	result.Stack.Selection.AllowedTransports[0] = "changed"
	result.Stack.Bypass4[0] = "changed"
	result.Routing.ProxyDomains[0] = "changed"
	result.Routing.ProxyIPs[0] = "changed"
	if draft.Stack.Selection.AllowedTransports[0] == "changed" || draft.Stack.Bypass4[0] == "changed" || draft.Routing.ProxyDomains[0] == "changed" || draft.Routing.ProxyIPs[0] == "changed" {
		t.Fatal("confirmed result shares mutable slices with its input")
	}
}

func TestPrivateSubscriptionInputIsNotEchoedOrSerialized(t *testing.T) {
	draft := readyDraft()
	draft.HasEligibleNodes = false
	validURL := "https://user:" + privateToken + "@sub.example.test/feed?token=" + privateToken
	invalidURL := "https://sub.example.test/%zz?token=" + privateToken
	var output bytes.Buffer
	result, err := Run(strings.NewReader("all\n"+invalidURL+"\n"+validURL+"\n\nyes\n"), &output, draft)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.SubscriptionURLs) != 1 || result.SubscriptionURLs[0] != validURL {
		t.Fatal("private URL was not preserved for import")
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	assertPrivate(t, output.String()+string(data))
	if strings.Contains(output.String(), "sub.example.test") || strings.Contains(string(data), "SubscriptionURLs") {
		t.Fatal("public summary or JSON exposed subscription inputs")
	}
	if !strings.Contains(output.String(), "Subscriptions to import: 1") {
		t.Fatal("summary must report the subscription count")
	}
}

func TestRequestSubscriptionsValidatesDeduplicatesAndConfirms(t *testing.T) {
	first := "https://sub.example.test/" + privateToken
	second := "http://192.168.1.2:8080/" + privateToken
	input := "\nftp://private.example/" + privateToken + "\n" + first + "\n" + first + "\n" + second + "\n\nmaybe\nyes\n"
	var output bytes.Buffer
	urls, err := RequestSubscriptions(strings.NewReader(input), &output)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(urls, []string{first, second}) {
		t.Fatal("subscription list did not preserve unique valid inputs")
	}
	assertPrivate(t, output.String())
	if !strings.Contains(output.String(), "Import 2 subscription(s)?") {
		t.Fatal("standalone collection must confirm the subscription count")
	}
}

func TestRequestSubscriptionsCancellation(t *testing.T) {
	for _, input := range []string{"", "q\n", "https://sub.example.test/" + privateToken + "\n\nno\n"} {
		var output bytes.Buffer
		urls, err := RequestSubscriptions(strings.NewReader(input), &output)
		if !errors.Is(err, ErrCancelled) || urls != nil {
			t.Fatal("cancelled collection must return no URLs")
		}
		assertPrivate(t, output.String()+err.Error())
	}
}

func TestWizardMissingStreamsAndIOFailures(t *testing.T) {
	tests := []struct {
		name   string
		input  io.Reader
		output io.Writer
		want   error
	}{
		{"nil input", nil, io.Discard, ErrInputRequired},
		{"nil output", strings.NewReader("all\nyes\n"), nil, ErrInputRequired},
		{"reader failure", failingReader{}, io.Discard, nil},
		{"writer failure", strings.NewReader("all\nyes\n"), failingWriter{}, nil},
		{"oversized input", strings.NewReader(privateToken + strings.Repeat("x", 64*1024)), io.Discard, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Run(tt.input, tt.output, readyDraft())
			if err == nil || (tt.want != nil && !errors.Is(err, tt.want)) {
				t.Fatal("expected a controlled input/output error")
			}
			assertEmptyResult(t, result)
			assertPrivate(t, err.Error())
		})
	}
}

func TestSubscriptionURLValidation(t *testing.T) {
	valid := []string{
		"https://sub.example.test/feed?token=" + privateToken,
		"http://192.168.1.1:8080/feed",
		"https://user:password@sub.example.test/feed",
		"https://[::1]:8443/feed",
	}
	invalid := []string{
		"", "relative/feed", "//sub.example.test/feed", "ftp://sub.example.test/feed",
		"https://", "https:///feed", "https://sub.example.test/a b", "https://sub.example.test/%zz",
		"https://sub.example.test:invalid/feed", "https://sub.example.test:0/feed", "https://sub.example.test:65536/feed",
		"https://sub.example.test:/feed", "https://sub.example.test/feed\nextra",
	}
	for i, value := range valid {
		if !validSubscriptionURL(value) {
			t.Errorf("valid fixture %d rejected", i)
		}
	}
	for i, value := range invalid {
		if validSubscriptionURL(value) {
			t.Errorf("invalid fixture %d accepted", i)
		}
	}
}

func assertEmptyResult(t *testing.T, result Result) {
	t.Helper()
	if !reflect.DeepEqual(result, Result{}) {
		t.Fatal("failure returned a partial result")
	}
}

func assertPrivate(t *testing.T, text string) {
	t.Helper()
	if strings.Contains(text, privateToken) {
		t.Fatal("private input leaked into output or an error")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("read failed for https://private.example/" + privateToken)
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed for https://private.example/" + privateToken)
}
