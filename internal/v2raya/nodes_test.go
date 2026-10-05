package v2raya

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
)

func TestListCandidatesAppliesPolicyAndStableTouchMapping(t *testing.T) {
	db := candidateTestDB(t)
	for _, statement := range []string{
		"INSERT INTO subscriptions (id,sort) VALUES (5,1),(9,0)",
		"CREATE TABLE servers (id INTEGER PRIMARY KEY, type TEXT, sub_id INTEGER, sort INTEGER, config_json TEXT)",
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	rows := []struct {
		kind string
		sub  any
		sort int
		raw  string
	}{
		{"subscription_server", 5, 0, `{"serverObj":{"protocol":"VLESS","net":"XHTTP","tls":"Reality","ps":"allowed-xhttp","add":"xhttp.example","port":443}}`},
		{"subscription_server", 9, 1, `{"protocol":"hysteria2","ps":"denied-hysteria2"}`},
		{"subscription_server", 5, 2, `{"protocol":"shadowsocks","ps":"denied-shadowsocks"}`},
		{"subscription_server", 9, 3, `{"protocol":"vless","net":"xhttp","tls":"tls","ps":"unsupported-security"}`},
		{"subscription_server", 5, 4, `{"protocol":"vless","net":"ws","tls":"tls","ps":"denied-ws"}`},
		{"subscription_server", 9, 5, `{"protocol":"vless","network":"tcp","security":"reality","remarks":"allowed-tcp","host":"tcp.example","port":"8443"}`},
		{"subscription_server", 88, 0, `{"protocol":"vless","net":"tcp","tls":"reality","ps":"orphan"}`},
		{"subscription_server", nil, 0, `{"protocol":"vless","net":"tcp","tls":"reality","ps":"missing-sub"}`},
		{"subscription_server", 5, -1, `{"protocol":"vless","net":"tcp","tls":"reality","ps":"negative-sort"}`},
		{"subscription_server", 9, 6, "invalid-json"},
		{"server", 5, 7, `{"protocol":"vless","net":"tcp","tls":"reality","ps":"not-subscription-node"}`},
	}
	for _, row := range rows {
		if _, err := db.Exec("INSERT INTO servers (type,sub_id,sort,config_json) VALUES (?,?,?,?)", row.kind, row.sub, row.sort, row.raw); err != nil {
			t.Fatal(err)
		}
	}
	policy, err := NewCandidatePolicy(config.Selection{AllowedTransports: []config.Transport{
		config.TransportVLESSXHTTPReality,
		config.TransportVLESSTCPReality,
	}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := ListCandidates(context.Background(), db, policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("candidates = %+v, want two allowed nodes", got)
	}
	want := []Candidate{
		{TouchID: 1, Sub: 1, SubscriptionID: 5, Priority: 40, Sort: 0, Name: "allowed-xhttp", Protocol: "vless", Network: "xhttp", Security: "reality", Address: "xhttp.example:443"},
		{TouchID: 6, Sub: 0, SubscriptionID: 9, Priority: 105, Sort: 5, Name: "allowed-tcp", Protocol: "vless", Network: "tcp", Security: "reality", Address: "tcp.example:8443"},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("candidate %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	none, err := ListCandidates(context.Background(), db, CandidatePolicy{})
	if err != nil || len(none) != 0 {
		t.Fatalf("zero policy result = %+v, %v; want no candidates", none, err)
	}
}

func TestListCandidatesPropagatesCancelledContext(t *testing.T) {
	db := candidateTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ListCandidates(ctx, db, CandidatePolicy{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestConnectedTouch(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		insert  bool
		found   bool
		want    NodeTouch
		wantErr bool
	}{
		{name: "missing setting"},
		{name: "empty touches", raw: `{"touches":[]}`, insert: true},
		{name: "null touches", raw: `{"touches":null}`, insert: true},
		{name: "connected", raw: `{"touches":[{"id":3,"sub":1}]}`, insert: true, found: true, want: NodeTouch{ID: 3, Sub: 1}},
		{name: "invalid JSON", raw: "invalid", insert: true, wantErr: true},
		{name: "missing id", raw: `{"touches":[{"sub":0}]}`, insert: true, wantErr: true},
		{name: "negative sub", raw: `{"touches":[{"id":1,"sub":-1}]}`, insert: true, wantErr: true},
		{name: "fractional id", raw: `{"touches":[{"id":1.5,"sub":0}]}`, insert: true, wantErr: true},
		{name: "ambiguous nodes", raw: `{"touches":[{"id":1,"sub":0},{"id":2,"sub":0}]}`, insert: true, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := candidateTestDB(t)
			if tt.insert {
				if _, err := db.Exec("INSERT INTO system_config (key,value) VALUES ('outbound.proxy:connectedServers',?)", tt.raw); err != nil {
					t.Fatal(err)
				}
			}
			touch, found, err := ConnectedTouch(context.Background(), db)
			if (err != nil) != tt.wantErr || found != tt.found || touch != tt.want {
				t.Fatalf("ConnectedTouch = (%+v,%v,%v), want (%+v,%v,error=%v)", touch, found, err, tt.want, tt.found, tt.wantErr)
			}
		})
	}
}

func candidateTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "candidates.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, statement := range []string{
		"CREATE TABLE subscriptions (id INTEGER PRIMARY KEY, sort INTEGER)",
		"CREATE TABLE system_config (key TEXT PRIMARY KEY, value TEXT)",
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	return db
}
