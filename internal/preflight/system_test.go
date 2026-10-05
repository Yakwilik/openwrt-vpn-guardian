package preflight

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/v2raya"
)

func TestDatabaseReadinessDoesNotCreateMissingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.db")
	if err := checkDatabasePath(context.Background(), path); err == nil {
		t.Fatal("missing database passed readiness")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("readiness created a database: %v", err)
	}
}

func TestDatabaseReadinessChecksSchemaAndSettingsReadOnly(t *testing.T) {
	for _, tc := range []struct {
		name     string
		schema   bool
		settings string
		wantErr  bool
	}{
		{"missing schema", false, "", true},
		{"missing setting", true, "", true},
		{"null setting", true, "null", true},
		{"malformed setting", true, "private_subscription_token", true},
		{"usable settings", true, `{"transparent":"close"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "v2raya.db")
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec("CREATE TABLE unrelated (id INTEGER)"); err != nil {
				t.Fatal(err)
			}
			if tc.schema {
				if _, err := db.Exec("CREATE TABLE system_config (key TEXT PRIMARY KEY, value TEXT)"); err != nil {
					t.Fatal(err)
				}
				if tc.settings != "" {
					if _, err := db.Exec("INSERT INTO system_config(key,value) VALUES(?,?)", "system:setting", tc.settings); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			err = checkDatabasePath(context.Background(), path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("readiness error=%v, wantErr=%v", err, tc.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), "private_subscription_token") {
				t.Fatalf("private configuration leaked: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("readiness changed database bytes: %v", err)
			}
		})
	}
}

func TestAPIReadinessErrorsRedactPrivateDetails(t *testing.T) {
	secret := "https://subscription.example/secret-token"
	for _, input := range []error{
		fmt.Errorf("transport error for %s", secret),
		&v2raya.APIError{Method: http.MethodGet, Path: "touch", StatusCode: 403, Message: secret},
	} {
		err := apiAccessError(context.Background(), input)
		if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "secret-token") {
			t.Fatalf("unsafe error: %v", err)
		}
	}
	if err := apiAccessError(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := apiAccessError(ctx, errors.New(secret)); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost context cancellation: %v", err)
	}
}

func TestCorruptDatabaseHeaderIsRejected(t *testing.T) {
	files := fstest.MapFS{"v2raya.db": &fstest.MapFile{Data: []byte("this is not a database")}}
	if err := checkSQLiteFile(files, "/v2raya.db"); err == nil {
		t.Fatal("corrupt database header passed")
	}
}

func TestCommandRunnerDiscardsPrivateOutput(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("shell not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := (commandRunner{}).Run(ctx, "sh", "-c", "printf secret-token >&2; printf private-config; exit 7")
	if err == nil || strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), "private-config") {
		t.Fatalf("private command output appeared in an error: %v", err)
	}
}

func TestVersionRunnerBoundsAndRedactsOutput(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("shell not installed")
	}
	for _, tc := range []struct {
		name    string
		command string
		want    string
		wantErr bool
	}{
		{"first stdout line", "printf '2.5.8\\nprivate-config\\n'; printf secret-token >&2", "2.5.8", false},
		{"oversized output", "printf '%5000s' x", "", true},
		{"failed command", "printf private-config; printf secret-token >&2; exit 7", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			line, err := (commandRunner{}).Version(ctx, "sh", "-c", tc.command)
			if line != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("Version result=(%q,%v), want (%q,error=%v)", line, err, tc.want, tc.wantErr)
			}
			if err != nil && (strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), "private-config")) {
				t.Fatal("version failure exposed process output")
			}
		})
	}
}
