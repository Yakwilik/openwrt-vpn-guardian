package v2raya

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
)

type setupCall struct {
	method  string
	path    string
	payload any
}

type setupFakeAPI struct {
	calls []setupCall
	call  func(context.Context, string, string, any) (map[string]any, error)
}

func (api *setupFakeAPI) Call(ctx context.Context, method, path string, payload any) (map[string]any, error) {
	api.calls = append(api.calls, setupCall{method, path, payload})
	if api.call != nil {
		return api.call(ctx, method, path, payload)
	}
	return nil, nil
}

func setupTouchEnvelope(addresses ...string) map[string]any {
	subscriptions := make([]any, 0, len(addresses))
	for _, address := range addresses {
		subscriptions = append(subscriptions, map[string]any{"address": address})
	}
	return map[string]any{"data": map[string]any{"touch": map[string]any{"subscriptions": subscriptions}}}
}

func TestImportSubscriptionsDeduplicatesExactAddresses(t *testing.T) {
	existing := "https://provider.example/sub?token=one"
	newAddress := "https://provider.example/sub?token=two"
	api := &setupFakeAPI{call: func(_ context.Context, method, path string, _ any) (map[string]any, error) {
		if method == http.MethodGet && path == "touch" {
			return setupTouchEnvelope(existing), nil
		}
		return nil, nil
	}}
	if err := importSubscriptions(context.Background(), []string{existing, newAddress, newAddress, "  " + existing + " "}, api); err != nil {
		t.Fatal(err)
	}
	if len(api.calls) != 2 {
		t.Fatalf("expected one read and one import, got %+v", api.calls)
	}
	got := api.calls[1]
	body, ok := got.payload.(map[string]any)
	if !ok || got.method != http.MethodPost || got.path != "import" || body["url"] != newAddress || body["kind"] != "subscription" {
		t.Fatalf("wrong import contract: %+v", got)
	}
}

func TestImportErrorsNeverContainSubscriptionSecrets(t *testing.T) {
	secret := "https://provider.example/sub?token=private-token"
	for _, failRead := range []bool{false, true} {
		t.Run(fmt.Sprint(failRead), func(t *testing.T) {
			api := &setupFakeAPI{call: func(_ context.Context, method, _ string, _ any) (map[string]any, error) {
				if method == http.MethodGet && !failRead {
					return setupTouchEnvelope(), nil
				}
				return nil, &APIError{StatusCode: 400, Message: secret, Code: secret, ErrorCode: secret}
			}}
			err := importSubscriptions(context.Background(), []string{secret}, api)
			if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "private-token") {
				t.Fatalf("unsafe import error: %v", err)
			}
		})
	}
	api := &setupFakeAPI{}
	if err := importSubscriptions(context.Background(), []string{"https://provider.example:%private-token"}, api); err == nil || strings.Contains(err.Error(), "private-token") {
		t.Fatalf("URL parser error leaked input: %v", err)
	}
	if len(api.calls) != 0 {
		t.Fatal("invalid inputs reached the API")
	}
}

func TestImportDoesNotWriteWhenExistingAddressesAreUnavailable(t *testing.T) {
	api := &setupFakeAPI{call: func(context.Context, string, string, any) (map[string]any, error) {
		return map[string]any{"data": map[string]any{"touch": map[string]any{"subscriptions": []any{map[string]any{"host": "provider.example"}}}}}, nil
	}}
	err := importSubscriptions(context.Background(), []string{"https://provider.example/sub"}, api)
	if err == nil || len(api.calls) != 1 {
		t.Fatalf("import proceeded without reliable duplicate information: err=%v calls=%v", err, api.calls)
	}
	api.calls = nil
	if err := importSubscriptions(context.Background(), nil, api); err != nil || len(api.calls) != 0 {
		t.Fatal("empty import should not contact the manager")
	}
}

func setupSelection() config.Selection {
	return config.Selection{AllowedTransports: []config.Transport{config.TransportHysteria2}}
}

func TestHasEligibleNodesHandlesMissingDatabaseAndInvalidSelection(t *testing.T) {
	called := 0
	list := func(context.Context, CandidatePolicy) ([]Candidate, error) {
		called++
		return nil, os.ErrNotExist
	}
	if found, err := hasEligibleNodes(context.Background(), setupSelection(), list); err != nil || found {
		t.Fatalf("missing database: found=%v err=%v", found, err)
	}
	if _, err := hasEligibleNodes(context.Background(), config.Selection{}, list); err == nil {
		t.Fatal("missing transport selection passed")
	}
	if called != 1 {
		t.Fatal("invalid selection should be rejected before database access")
	}
	path := filepath.Join(t.TempDir(), "missing.db")
	if _, err := openSetupDB(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only setup opening did not preserve missing state: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("setup created a missing database")
	}
}

type setupFakeBackend struct {
	t              *testing.T
	nodes          []Candidate
	current        NodeTouch
	found          bool
	ready          bool
	healthy        map[NodeTouch]bool
	probed         []NodeTouch
	api            *setupFakeAPI
	beforeList     func(int)
	afterProbe     func()
	listCalls      int
	forceSelection *NodeTouch
}

func newSetupBackend(t *testing.T) *setupFakeBackend {
	t.Helper()
	backend := &setupFakeBackend{t: t, ready: true, healthy: make(map[NodeTouch]bool)}
	for i := 1; i <= 2; i++ {
		backend.nodes = append(backend.nodes, Candidate{TouchID: i, Sub: 0, SubscriptionID: 1, Priority: 20 + i, Name: fmt.Sprintf("node-%d", i), Protocol: "hysteria2", Address: fmt.Sprintf("node-%d.example:443", i)})
	}
	backend.api = &setupFakeAPI{call: func(ctx context.Context, method, path string, payload any) (map[string]any, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if (method == http.MethodPost || method == http.MethodDelete) && path == "v2ray" {
			backend.ready = method == http.MethodPost
			return nil, nil
		}
		if method != http.MethodPut || path != "outboundConnections" {
			t.Fatalf("unexpected setup mutation: %s %s", method, path)
		}
		body := payload.(map[string]any)
		if body["outbound"] != "proxy" {
			t.Fatalf("wrong outbound: %#v", body)
		}
		touches := body["touches"].([]any)
		backend.found = len(touches) != 0
		if len(touches) == 0 {
			backend.current = NodeTouch{}
			return nil, nil
		}
		touch := touches[0].(map[string]any)
		if len(touches) != 1 || touch["_type"] != "subscriptionServer" || touch["outbound"] != "proxy" {
			t.Fatalf("wrong touch payload: %#v", body)
		}
		backend.current = NodeTouch{ID: touch["id"].(int), Sub: touch["sub"].(int)}
		if backend.forceSelection != nil {
			backend.current = *backend.forceSelection
		}
		return nil, nil
	}}
	return backend
}

func (f *setupFakeBackend) operations() setupBackend {
	return setupBackend{
		api: f.api,
		candidates: func(ctx context.Context, policy CandidatePolicy) ([]Candidate, error) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			f.listCalls++
			if f.beforeList != nil {
				f.beforeList(f.listCalls)
			}
			var allowed []Candidate
			for _, node := range f.nodes {
				if policy.Eligible(node.Protocol, node.Network, node.Security) {
					allowed = append(allowed, node)
				}
			}
			return allowed, nil
		},
		connected: func(ctx context.Context) (NodeTouch, bool, error) { return f.current, f.found, ctx.Err() },
		listener:  func() bool { return f.ready },
		running:   func() bool { return f.ready },
		usable: func(ctx context.Context) bool {
			f.probed = append(f.probed, f.current)
			healthy := f.healthy[f.current] && ctx.Err() == nil
			if f.afterProbe != nil {
				f.afterProbe()
			}
			return healthy
		},
		poll: time.Millisecond,
	}
}

func TestSetupKeepsHealthyAllowedActiveNode(t *testing.T) {
	f := newSetupBackend(t)
	f.current, f.found = NodeTouch{ID: 2, Sub: 0}, true
	f.healthy[f.current] = true
	if _, err := ensureAllowedBackend(context.Background(), setupSelection(), f.operations()); err != nil {
		t.Fatal(err)
	}
	if len(f.api.calls) != 0 || f.current.ID != 2 {
		t.Fatal("healthy allowed node was unnecessarily changed")
	}
}

func TestSetupDoesNotAcceptHealthyForbiddenActiveNode(t *testing.T) {
	f := newSetupBackend(t)
	f.current, f.found = NodeTouch{ID: 9, Sub: 0}, true
	f.nodes = append(f.nodes, Candidate{TouchID: 9, Protocol: "vmess", Name: "forbidden"})
	f.healthy[f.current] = true
	f.healthy[NodeTouch{ID: 1, Sub: 0}] = true
	if _, err := ensureAllowedBackend(context.Background(), setupSelection(), f.operations()); err != nil {
		t.Fatal(err)
	}
	if f.current.ID != 1 || len(f.api.calls) != 1 {
		t.Fatalf("did not select an allowed node: current=%+v calls=%+v", f.current, f.api.calls)
	}
	for _, touch := range f.probed {
		if touch.ID == 9 {
			t.Fatal("forbidden node reached the backend health gate")
		}
	}
}

func TestSetupStartsStoppedCoreAndTriesNextAllowedNode(t *testing.T) {
	f := newSetupBackend(t)
	f.ready = false
	f.healthy[NodeTouch{ID: 2, Sub: 0}] = true
	if _, err := ensureAllowedBackend(context.Background(), setupSelection(), f.operations()); err != nil {
		t.Fatal(err)
	}
	if f.current.ID != 2 || !f.ready {
		t.Fatalf("failed to find usable backend: %+v", f.current)
	}
	starts := 0
	for _, call := range f.api.calls {
		if call.method == http.MethodPost && call.path == "v2ray" {
			starts++
		}
	}
	if starts != 1 {
		t.Fatalf("expected one bounded core start, got %d", starts)
	}
}

func TestSetupRestoresOriginalSelectionWhenAllCandidatesFail(t *testing.T) {
	f := newSetupBackend(t)
	original := NodeTouch{ID: 9, Sub: 0}
	f.current, f.found = original, true
	_, err := ensureAllowedBackend(context.Background(), setupSelection(), f.operations())
	if err == nil || f.current != original {
		t.Fatalf("original selection was not restored: current=%+v err=%v", f.current, err)
	}
	if len(f.api.calls) != 3 {
		t.Fatalf("expected two trials and rollback: %+v", f.api.calls)
	}
}

func TestSetupRevalidatesIdentityAfterSubscriptionReorder(t *testing.T) {
	f := newSetupBackend(t)
	f.beforeList = func(call int) {
		if call == 2 {
			f.nodes[0].TouchID, f.nodes[0].Sub = 4, 3
		}
	}
	f.healthy[NodeTouch{ID: 4, Sub: 3}] = true
	if _, err := ensureAllowedBackend(context.Background(), setupSelection(), f.operations()); err != nil {
		t.Fatal(err)
	}
	if f.current != (NodeTouch{ID: 4, Sub: 3}) {
		t.Fatalf("stale positional IDs were used: %+v", f.current)
	}
}

func TestSetupCannotSucceedIfIdentityChangesDuringHealthProbe(t *testing.T) {
	f := newSetupBackend(t)
	f.nodes = f.nodes[:1]
	original := NodeTouch{ID: 7, Sub: 0}
	f.current, f.found = original, true
	f.healthy[NodeTouch{ID: 1, Sub: 0}] = true
	f.afterProbe = func() { f.current = NodeTouch{ID: 9, Sub: 0} }
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := ensureAllowedBackend(ctx, setupSelection(), f.operations())
	if err == nil || f.current != original || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("changed identity was accepted or cancellation lost rollback: current=%+v err=%v", f.current, err)
	}
}

func TestSetupRejectsEmptyAllowlistBeforeMutations(t *testing.T) {
	f := newSetupBackend(t)
	if _, err := ensureAllowedBackend(context.Background(), config.Selection{}, f.operations()); err == nil {
		t.Fatal("empty allowlist passed")
	}
	if len(f.api.calls) != 0 || len(f.probed) != 0 || f.listCalls != 0 {
		t.Fatal("invalid selection reached the backend")
	}
}

func TestSetupReturnsCompensationForLaterActivationFailure(t *testing.T) {
	f := newSetupBackend(t)
	original := NodeTouch{ID: 9, Sub: 0}
	f.current, f.found = original, true
	f.healthy[NodeTouch{ID: 1, Sub: 0}] = true
	restore, err := ensureAllowedBackend(context.Background(), setupSelection(), f.operations())
	if err != nil || restore == nil {
		t.Fatalf("missing successful setup compensation: %v", err)
	}
	if err := restore(context.Background()); err != nil || f.current != original {
		t.Fatalf("later failure could not restore old selection: current=%+v err=%v", f.current, err)
	}
}

func TestSetupCompensationRestoresStoppedCoreAndEmptySelection(t *testing.T) {
	f := newSetupBackend(t)
	f.ready = false
	f.healthy[NodeTouch{ID: 1, Sub: 0}] = true
	restore, err := ensureAllowedBackend(context.Background(), setupSelection(), f.operations())
	if err != nil || !f.ready || !f.found {
		t.Fatalf("backend did not start: err=%v", err)
	}
	if err := restore(context.Background()); err != nil || f.ready || f.found {
		t.Fatalf("original stopped/empty state not restored: ready=%v found=%v err=%v", f.ready, f.found, err)
	}
}
