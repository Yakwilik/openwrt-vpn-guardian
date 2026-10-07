package v2raya

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
)

type selectionSnapshot struct {
	Nodes     []Candidate
	Active    NodeTouch
	Connected bool
}

func readSelection(ctx context.Context) (selectionSnapshot, error) {
	db, err := OpenDB()
	if err != nil {
		return selectionSnapshot{}, err
	}
	defer db.Close()
	cfg, err := config.LoadStack()
	if err != nil {
		return selectionSnapshot{}, err
	}
	policy, err := NewCandidatePolicy(cfg.Selection)
	if err != nil {
		return selectionSnapshot{}, err
	}
	nodes, err := ListCandidates(ctx, db, policy)
	if err != nil {
		return selectionSnapshot{}, err
	}
	active, ok, err := ConnectedTouch(ctx, db)
	return selectionSnapshot{Nodes: nodes, Active: active, Connected: ok}, err
}

// SelectCandidate is shared by the UI and watchdog. The caller holds the
// Guardian control lock. A live port alone is never a selection confirmation.
func SelectCandidate(ctx context.Context, want Candidate) (Candidate, error) {
	ctx, cancel := context.WithTimeout(ctx, 16*time.Second)
	defer cancel()
	client := NewClient("vpn-guardian-selection")
	send := func(ctx context.Context, c Candidate) error {
		_, err := client.Call(ctx, http.MethodPut, "outboundConnections", map[string]any{
			"outbound": "proxy", "touches": []any{map[string]any{"_type": "subscriptionServer", "id": c.TouchID, "sub": c.Sub, "outbound": "proxy"}},
		})
		return err
	}
	return selectConfirmed(ctx, want, readSelection, send, backendSOCKSReadyContext)
}

func selectConfirmed(ctx context.Context, want Candidate, read func(context.Context) (selectionSnapshot, error), send func(context.Context, Candidate) error, ready func(context.Context) bool) (Candidate, error) {
	initial, err := read(ctx)
	if err != nil {
		return Candidate{}, err
	}
	var fresh Candidate
	found := false
	for _, c := range initial.Nodes {
		if SameCandidate(c, want) {
			fresh = c
			found = true
			break
		}
	}
	if !found {
		return Candidate{}, errors.New("the selected node no longer exists; refresh the node list")
	}
	if err := send(ctx, fresh); err != nil {
		return Candidate{}, fmt.Errorf("request VPN selection: %w", err)
	}
	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		state, err := read(ctx)
		if err != nil {
			last = err
		} else if state.Connected {
			for _, c := range state.Nodes {
				if c.TouchID == state.Active.ID && c.Sub == state.Active.Sub {
					if SameCandidate(c, fresh) && ready(ctx) {
						return c, nil
					}
					last = fmt.Errorf("active node is %s, awaiting %s", c.Name, fresh.Name)
					break
				}
			}
		}
		select {
		case <-ctx.Done():
			return Candidate{}, errors.Join(fmt.Errorf("VPN selection was not confirmed: %w", ctx.Err()), last)
		case <-ticker.C:
		}
	}
}
