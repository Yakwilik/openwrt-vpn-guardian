// Package setup collects and validates first-run settings without changing the system.
package setup

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
)

var (
	ErrCancelled     = errors.New("setup cancelled")
	ErrInputRequired = errors.New("setup requires interactive input and output")
)

// Draft contains settings detected or loaded by the caller. HasEligibleNodes is
// an inventory check, not a health probe. The caller must check eligibility again
// if the selected transports change during setup.
type Draft struct {
	Stack              config.Stack
	Routing            config.Routing
	HasEligibleNodes   bool
	SelectionConfirmed bool
}

// Result is returned only after validation and confirmation. Subscription URLs
// are private import inputs: do not persist them in the public configuration or
// log them. Setup never writes files, imports subscriptions, or starts services.
type Result struct {
	Stack            config.Stack   `json:"stack"`
	Routing          config.Routing `json:"routing"`
	SubscriptionURLs []string       `json:"-"`
}

// Run completes missing settings and returns a confirmed, valid draft. The
// caller determines whether its streams are interactive before invoking Run.
// Any cancellation, incomplete input, or validation failure returns no result.
func Run(input io.Reader, output io.Writer, draft Draft) (Result, error) {
	w, err := newWizard(input, output)
	if err != nil {
		return Result{}, err
	}

	result := Result{Stack: draft.Stack, Routing: draft.Routing}
	result.Stack.Bypass4 = slices.Clone(draft.Stack.Bypass4)
	result.Stack.Selection.AllowedTransports = slices.Clone(draft.Stack.Selection.AllowedTransports)
	result.Routing.ProxyDomains = slices.Clone(draft.Routing.ProxyDomains)
	result.Routing.ProxyIPs = slices.Clone(draft.Routing.ProxyIPs)

	if err := w.print("VPN Guardian setup. Type cancel at any prompt to stop.\n"); err != nil {
		return Result{}, err
	}

	fields := []struct {
		label    string
		value    *string
		validate func(string) error
	}{
		{"LAN interface", &result.Stack.LANInterface, config.ValidateInterfaceName},
		{"LAN IPv4 subnet (CIDR, for example 192.168.1.0/24)", &result.Stack.LANCIDR, config.ValidateLANCIDR},
		{"WAN interface", &result.Stack.WANInterface, config.ValidateInterfaceName},
	}
	for _, field := range fields {
		value, err := w.requiredField(field.label, *field.value, field.validate)
		if err != nil {
			return Result{}, err
		}
		*field.value = value
	}
	// Validation accepts an interface address with its prefix; store the network
	// address because the runtime uses this field as a source subnet match.
	prefix, err := netip.ParsePrefix(result.Stack.LANCIDR)
	if err != nil {
		return Result{}, errors.New("LAN IPv4 subnet is invalid")
	}
	result.Stack.LANCIDR = prefix.Masked().String()

	if !draft.SelectionConfirmed || result.Stack.Selection.Validate() != nil {
		transports, err := w.selectTransports(result.Stack.Selection)
		if err != nil {
			return Result{}, err
		}
		result.Stack.Selection.AllowedTransports = transports
	}

	if !draft.HasEligibleNodes {
		result.SubscriptionURLs, err = w.subscriptions()
		if err != nil {
			return Result{}, err
		}
	}

	if err := result.Stack.Validate(); err != nil {
		return Result{}, fmt.Errorf("setup stack configuration: %w", err)
	}
	if err := result.Routing.Validate(); err != nil {
		return Result{}, fmt.Errorf("setup routing configuration: %w", err)
	}

	if err := w.print("\nReview setup:\n  LAN: %s (%s)\n  WAN: %s\n  Allowed transports: %s\n  Subscriptions to import: %d\n  Default policy: %s\n",
		result.Stack.LANInterface, result.Stack.LANCIDR, result.Stack.WANInterface,
		transportLabels(result.Stack.Selection), len(result.SubscriptionURLs), result.Stack.Policy.Default); err != nil {
		return Result{}, err
	}
	if err := w.confirm("Use these settings? [y/N]: "); err != nil {
		return Result{}, err
	}
	return result, nil
}

// RequestSubscriptions collects private URLs when a new selection has no
// eligible nodes. It confirms only their count and performs no network requests.
func RequestSubscriptions(input io.Reader, output io.Writer) ([]string, error) {
	w, err := newWizard(input, output)
	if err != nil {
		return nil, err
	}
	urls, err := w.subscriptions()
	if err != nil {
		return nil, err
	}
	if err := w.confirm(fmt.Sprintf("Import %d subscription(s)? [y/N]: ", len(urls))); err != nil {
		return nil, err
	}
	return urls, nil
}

type wizard struct {
	input  *bufio.Reader
	output io.Writer
}

func newWizard(input io.Reader, output io.Writer) (*wizard, error) {
	if input == nil || output == nil {
		return nil, ErrInputRequired
	}
	buffered, ok := input.(*bufio.Reader)
	if !ok {
		buffered = bufio.NewReader(input)
	}
	return &wizard{input: buffered, output: output}, nil
}

func (w *wizard) print(format string, args ...any) error {
	if _, err := fmt.Fprintf(w.output, format, args...); err != nil {
		// A stream's error may include previously entered private data.
		return errors.New("could not write setup prompt")
	}
	return nil
}

func (w *wizard) ask(prompt string) (string, error) {
	if err := w.print("%s", prompt); err != nil {
		return "", err
	}
	line, err := w.readLine()
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(line)
	switch strings.ToLower(value) {
	case "cancel", "quit", "q", "\x03":
		return "", ErrCancelled
	}
	return value, nil
}

// Keep unread input in the caller's buffered reader so that a later prompt can
// continue the same stream. Bound the line even when ReadSlice needs more than
// one buffer, and never include a stream error or its partial input in errors.
func (w *wizard) readLine() (string, error) {
	var line []byte
	for {
		fragment, err := w.input.ReadSlice('\n')
		if len(line)+len(fragment) >= 64*1024 {
			return "", errors.New("setup input must be shorter than 64 KiB per line")
		}
		line = append(line, fragment...)
		switch {
		case err == nil:
			return string(line), nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			if len(line) > 0 {
				return string(line), nil
			}
			return "", fmt.Errorf("%w: input ended before confirmation", ErrCancelled)
		default:
			return "", errors.New("could not read setup input")
		}
	}
}

func (w *wizard) requiredField(label, value string, validate func(string) error) (string, error) {
	value = strings.TrimSpace(value)
	for validate(value) != nil {
		var err error
		value, err = w.ask(label + ": ")
		if err != nil {
			return "", err
		}
		if validate(value) != nil {
			if err := w.print("Enter a valid %s.\n", label); err != nil {
				return "", err
			}
		}
	}
	return value, nil
}

func (w *wizard) selectTransports(current config.Selection) ([]config.Transport, error) {
	options := config.TransportOptions()
	if err := w.print("\nAllowed VPN transports:\n"); err != nil {
		return nil, err
	}
	for i, option := range options {
		if err := w.print("  %d. %s\n", i+1, option.Label); err != nil {
			return nil, err
		}
	}
	prompt := "Choose numbers separated by commas, or type all to allow every supported transport: "
	currentValid := current.Validate() == nil
	if currentValid {
		if err := w.print("Current selection: %s\n", transportLabels(current)); err != nil {
			return nil, err
		}
		prompt = "Choose numbers separated by commas, all, or keep to confirm the current selection: "
	}
	for {
		value, err := w.ask(prompt)
		if err != nil {
			return nil, err
		}
		switch strings.ToLower(value) {
		case "all":
			return config.SupportedTransports(), nil
		case "keep":
			if currentValid {
				return slices.Clone(current.AllowedTransports), nil
			}
		}
		if transports, ok := transportNumbers(value, options); ok {
			return transports, nil
		}
		if err := w.print("Choose at least one listed number without duplicates, or explicitly type all.\n"); err != nil {
			return nil, err
		}
	}
}

func transportNumbers(value string, options []config.TransportOption) ([]config.Transport, bool) {
	selected := make(map[int]bool)
	for _, part := range strings.Split(value, ",") {
		index, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || index < 1 || index > len(options) || selected[index] {
			return nil, false
		}
		selected[index] = true
	}
	var transports []config.Transport
	for i, option := range options {
		if selected[i+1] {
			transports = append(transports, option.Value)
		}
	}
	return transports, len(transports) > 0
}

func transportLabels(selection config.Selection) string {
	var labels []string
	for _, option := range config.TransportOptions() {
		if slices.Contains(selection.AllowedTransports, option.Value) {
			labels = append(labels, option.Label)
		}
	}
	return strings.Join(labels, ", ")
}

func (w *wizard) subscriptions() ([]string, error) {
	if err := w.print("\nNo eligible VPN nodes found. Enter one HTTP or HTTPS subscription URL per line.\nLeave a line empty when finished; type cancel to stop. URLs are private and omitted from the summary.\n"); err != nil {
		return nil, err
	}
	var urls []string
	for {
		value, err := w.ask(fmt.Sprintf("Subscription URL %d: ", len(urls)+1))
		if err != nil {
			return nil, err
		}
		if value == "" && len(urls) > 0 {
			return urls, nil
		}
		if !validSubscriptionURL(value) {
			if err := w.print("Enter a valid absolute HTTP or HTTPS subscription URL; at least one is required.\n"); err != nil {
				return nil, err
			}
			continue
		}
		if slices.Contains(urls, value) {
			if err := w.print("This subscription is already included.\n"); err != nil {
				return nil, err
			}
			continue
		}
		urls = append(urls, value)
	}
}

func validSubscriptionURL(value string) bool {
	if strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return false
	}
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" || u.Opaque != "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if strings.HasSuffix(u.Host, ":") {
		return false
	}
	if port := u.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return false
		}
	}
	return true
}

func (w *wizard) confirm(prompt string) error {
	for {
		value, err := w.ask(prompt)
		if err != nil {
			return err
		}
		switch strings.ToLower(value) {
		case "yes", "y":
			return nil
		case "no", "n", "":
			return ErrCancelled
		}
		if err := w.print("Please answer yes or no.\n"); err != nil {
			return err
		}
	}
}
