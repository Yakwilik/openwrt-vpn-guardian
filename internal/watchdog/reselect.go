package watchdog

import (
	"context"
	"errors"
	"fmt"
	"time"

	v "github.com/Yakwilik/openwrt-vpn-guardian/internal/v2raya"
)

// SelectAlternative is an explicit operator request, not a simulated outage.
// The caller holds ControlLock. Current-node duplicates and cooling candidates
// are excluded; a failed search restores the original selection.
func SelectAlternative(ctx context.Context) (Candidate, error) {
	db, err := openDB()
	if err != nil {
		return Candidate{}, err
	}
	cs, err := candidates(db)
	if err != nil {
		db.Close()
		return Candidate{}, err
	}
	id, sub, ok := current(db)
	db.Close()
	if !ok {
		return Candidate{}, errors.New("no active VPN node to replace")
	}
	original, known := findCandidate(cs, id, sub)
	if !known {
		return Candidate{}, errors.New("active node is not in the allowed inventory")
	}
	state := loadState()
	ready, _ := rankCandidates(cs, state, id, sub)
	filtered := alternativeCandidates(original, ready)
	if len(filtered) == 0 {
		return Candidate{}, errors.New("нет другой разрешённой ноды вне cooldown; текущая нода сохранена")
	}
	var last error
	for i, candidate := range filtered {
		if i >= 6 || ctx.Err() != nil {
			break
		}
		selected, err := v.SelectCandidate(ctx, candidate.Candidate)
		if err != nil {
			last = err
			markCandidateFailure(&state, candidate.Candidate)
			continue
		}
		check := health(4 * time.Second)
		if !check.Healthy {
			last = fmt.Errorf("%s: %s", selected.Name, healthSummary(check))
			markCandidateFailure(&state, selected)
			continue
		}
		markCandidateSuccess(&state, selected, check)
		state.LastHealth = check
		state.LastHealthy = time.Now().Unix()
		state.LastSwitch = time.Now().Unix()
		state.LastNode = selected.Name
		state.LastError = ""
		state.Failures = 0
		saveState(state)
		logLine("switched successfully by operator request id=%d sub=%d %s", selected.TouchID, selected.Sub, selected.Name)
		return selected, nil
	}
	restoreCtx, cancel := context.WithTimeout(context.Background(), 16*time.Second)
	defer cancel()
	_, restoreErr := v.SelectCandidate(restoreCtx, original)
	state.LastError = "alternative search found no healthy candidate"
	saveState(state)
	if restoreErr != nil {
		return Candidate{}, errors.Join(errors.New("no suitable alternative; failed to confirm restored selection"), last, restoreErr)
	}
	return Candidate{}, errors.Join(errors.New("подходящая другая нода не найдена; исходная нода восстановлена"), last)
}

func alternativeCandidates(original Candidate, ready []RankedCandidate) []RankedCandidate {
	out := make([]RankedCandidate, 0, len(ready))
	for _, c := range ready {
		if !v.SameCandidate(original, c.Candidate) {
			out = append(out, c)
		}
	}
	return out
}
