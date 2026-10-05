package collector

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
	v2rayautil "github.com/Yakwilik/openwrt-vpn-guardian/internal/v2raya"
)

func TestDBStatusCountsOnlyConfiguredCandidates(t *testing.T) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "collector.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, statement := range []string{
		"CREATE TABLE subscriptions (id INTEGER PRIMARY KEY, sort INTEGER)",
		"CREATE TABLE servers (id INTEGER PRIMARY KEY, type TEXT, sub_id INTEGER, sort INTEGER, config_json TEXT)",
		"CREATE TABLE system_config (key TEXT PRIMARY KEY, value TEXT)",
		"INSERT INTO subscriptions (id,sort) VALUES (7,0)",
		`INSERT INTO system_config (key,value) VALUES ('outbound.proxy:connectedServers','{"touches":[{"id":1,"sub":0}]}')`,
		`INSERT INTO system_config (key,value) VALUES ('system:setting','{"transparent":"close","pacMode":"none"}')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	rows := []struct {
		sub int
		raw string
	}{
		{7, `{"protocol":"hysteria2","ps":"current-node","add":"current.example","port":443}`},
		{7, `{"serverObj":{"protocol":"vless","net":"xhttp","tls":"reality","ps":"allowed-xhttp"}}`},
		{9, `{"protocol":"vless","net":"xhttp","tls":"reality","ps":"orphan"}`},
		{7, `{"protocol":"vless","net":"ws","tls":"tls","ps":"disallowed-ws"}`},
		{7, "invalid-json"},
	}
	for i, row := range rows {
		if _, err := db.Exec("INSERT INTO servers (type,sub_id,sort,config_json) VALUES ('subscription_server',?,?,?)", row.sub, i, row.raw); err != nil {
			t.Fatal(err)
		}
	}
	selection, err := v2rayautil.NewCandidatePolicy(config.Selection{AllowedTransports: []config.Transport{
		config.TransportVLESSXHTTPReality,
	}})
	if err != nil {
		t.Fatal(err)
	}
	node, protocol, endpoint, candidates, total, transparent, pacMode, err := dbStatus(db, selection)
	if err != nil {
		t.Fatal(err)
	}
	if candidates != 1 || total != len(rows) {
		t.Fatalf("candidate count=%d/%d, want 1/%d", candidates, total, len(rows))
	}
	if node != "current-node" || protocol != "hysteria2" || endpoint != "current.example:443" {
		t.Fatalf("current node=(%q,%q,%q), want unchanged active node and numeric port", node, protocol, endpoint)
	}
	if transparent != "close" || pacMode != "none" {
		t.Fatalf("settings=(%q,%q), want close/none", transparent, pacMode)
	}
}
