package v2raya

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Candidate is a subscription node accepted by the configured selection policy.
// TouchID and Sub address v2rayA's one-based node and zero-based subscription
// positions; SubscriptionID is the stable database identifier.
type Candidate struct {
	Key            string `json:"key"`
	TouchID        int    `json:"id"`
	Sub            int    `json:"sub"`
	SubscriptionID int    `json:"subscriptionId"`
	Priority       int    `json:"priority"`
	Sort           int    `json:"sort"`
	Name           string `json:"name"`
	Protocol       string `json:"protocol"`
	Network        string `json:"network"`
	Security       string `json:"security"`
	Address        string `json:"-"`
}

type NodeTouch struct {
	ID  int `json:"id"`
	Sub int `json:"sub"`
}

// ListCandidates reads one consistent database snapshot. It accepts an explicit
// policy so setup can validate a draft before committing stack.json.
func ListCandidates(ctx context.Context, db *sql.DB, policy CandidatePolicy) ([]Candidate, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("read candidate snapshot: %w", err)
	}
	defer tx.Rollback()

	subOrd, err := subscriptionOrder(ctx, tx)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT sub_id,sort,config_json FROM servers WHERE type='subscription_server' ORDER BY sub_id,sort,id")
	if err != nil {
		return nil, fmt.Errorf("read subscription nodes: %w", err)
	}
	defer rows.Close()

	var out []Candidate
	positions := map[int]int{}
	for rows.Next() {
		var subID sql.NullInt64
		var position int
		var raw string
		if err := rows.Scan(&subID, &position, &raw); err != nil {
			return nil, fmt.Errorf("read subscription node: %w", err)
		}
		sub, exists := subOrd[int(subID.Int64)]
		if !subID.Valid || !exists || position < 0 {
			continue
		}
		touchID := positions[int(subID.Int64)] + 1
		positions[int(subID.Int64)] = touchID
		node, valid := parseCandidate(raw, position, policy)
		if !valid {
			continue
		}
		node.TouchID = touchID
		node.Sub = sub
		node.SubscriptionID = int(subID.Int64)
		node.Key = stableNodeKey(node.SubscriptionID, raw)
		out = append(out, node)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read subscription nodes: %w", err)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].Sort < out[j].Sort
	})
	return out, nil
}

func subscriptionOrder(ctx context.Context, tx *sql.Tx) (map[int]int, error) {
	rows, err := tx.QueryContext(ctx, "SELECT id FROM subscriptions ORDER BY sort,id")
	if err != nil {
		return nil, fmt.Errorf("read subscriptions: %w", err)
	}
	defer rows.Close()

	order := make(map[int]int)
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("read subscription: %w", err)
		}
		order[id] = len(order)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read subscriptions: %w", err)
	}
	return order, nil
}

func parseCandidate(raw string, position int, policy CandidatePolicy) (Candidate, bool) {
	var obj map[string]any
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		return Candidate{}, false
	}
	if nested, ok := obj["serverObj"].(map[string]any); ok {
		obj = nested
	}

	protocol := strings.ToLower(strings.TrimSpace(nodeField(obj, "protocol")))
	network := strings.ToLower(strings.TrimSpace(nodeField(obj, "net", "network")))
	security := strings.ToLower(strings.TrimSpace(nodeField(obj, "tls", "security")))
	priority, eligible := policy.Priority(protocol, network, security, position)
	if !eligible {
		return Candidate{}, false
	}
	address := nodeField(obj, "add", "address", "host")
	if port := nodeField(obj, "port"); address != "" && port != "" {
		address += ":" + port
	}
	return Candidate{
		Sort: position, Priority: priority,
		Name:     nodeField(obj, "ps", "name", "remarks"),
		Protocol: protocol, Network: network, Security: security, Address: address,
	}, true
}

// nodeField preserves v2rayA's string or JSON number representation of fields
// such as port, while treating optional null fields as absent.
func nodeField(obj map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, exists := obj[key]; exists && value != nil {
			return fmt.Sprint(value)
		}
	}
	return ""
}

// ConnectedTouch returns the single selected backend node. Multiple outbound
// touches are rejected because checking only the first could hide a forbidden node.
func ConnectedTouch(ctx context.Context, db *sql.DB) (NodeTouch, bool, error) {
	var raw string
	err := db.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key='outbound.proxy:connectedServers'").Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return NodeTouch{}, false, nil
	}
	if err != nil {
		return NodeTouch{}, false, fmt.Errorf("read connected node: %w", err)
	}
	var connected struct {
		Touches []NodeTouch `json:"touches"`
	}
	if err := json.Unmarshal([]byte(raw), &connected); err != nil {
		return NodeTouch{}, false, fmt.Errorf("decode connected node: %w", err)
	}
	if len(connected.Touches) == 0 {
		return NodeTouch{}, false, nil
	}
	if len(connected.Touches) != 1 {
		return NodeTouch{}, false, fmt.Errorf("expected one connected node, found %d", len(connected.Touches))
	}
	touch := connected.Touches[0]
	if touch.ID < 1 || touch.Sub < 0 {
		return NodeTouch{}, false, errors.New("connected node must have a positive id and nonnegative sub")
	}
	return touch, true, nil
}

// Key is a digest of the connection identity, never the credentials themselves.
// Positions and subscription order change on refresh and are not identities.
func stableNodeKey(sub int, raw string) string {
	var obj map[string]any
	if json.Unmarshal([]byte(raw), &obj) != nil {
		return ""
	}
	if nested, ok := obj["serverObj"].(map[string]any); ok {
		obj = nested
	}
	for _, k := range []string{"ps", "name", "remarks", "pingLatency", "latency", "_type", "sub", "selected", "status"} {
		delete(obj, k)
	}
	b, _ := json.Marshal(obj)
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%d:%x", sub, sum)
}
func SameCandidate(a, b Candidate) bool {
	if a.Key != "" && b.Key != "" {
		return a.Key == b.Key
	}
	return a.SubscriptionID == b.SubscriptionID && a.Name == b.Name && a.Protocol == b.Protocol && a.Network == b.Network && a.Security == b.Security && a.Address == b.Address
}
