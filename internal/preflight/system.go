package preflight

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
	"github.com/Yakwilik/openwrt-vpn-guardian/internal/v2raya"
)

type commandRunner struct{}

func (commandRunner) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

func (commandRunner) Run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 250 * time.Millisecond
	// UCI and other dependencies can print private configuration. No command
	// output is captured or included in readiness errors.
	return cmd.Run()
}

const maxVersionOutputBytes = 4096

// Version captures only a bounded first stdout line from an explicit version
// command. Stderr and additional lines never appear in readiness diagnostics.
func (commandRunner) Version(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 250 * time.Millisecond
	output := versionOutput{limit: maxVersionOutputBytes}
	cmd.Stdout = &output
	if err := cmd.Run(); err != nil {
		return "", err
	}
	if output.overflow {
		return "", errors.New("version output exceeds the size limit")
	}
	first, _, _ := strings.Cut(output.buffer.String(), "\n")
	return strings.TrimSpace(first), nil
}

type versionOutput struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (b *versionOutput) Write(data []byte) (int, error) {
	n := len(data)
	remaining := b.limit - b.buffer.Len()
	if len(data) > remaining {
		data = data[:remaining]
		b.overflow = true
	}
	_, _ = b.buffer.Write(data)
	return n, nil
}

func checkFile(files fs.FS, path string, executable bool) error {
	file, err := files.Open(strings.TrimPrefix(path, "/"))
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("cannot inspect %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if executable && info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("%s is not executable", path)
	}
	var first [1]byte
	if _, err := io.ReadFull(file, first[:]); err != nil {
		return fmt.Errorf("%s is empty or unreadable: %w", path, err)
	}
	return nil
}

func detectAssetsDir(files fs.FS) string {
	for _, dir := range []string{"/usr/share/xray", "/usr/share/v2ray"} {
		if checkFile(files, filepath.Join(dir, "geosite.dat"), false) == nil {
			return dir
		}
	}
	return "/usr/share/xray"
}

func checkCABundle(files fs.FS, path string) error {
	file, err := files.Open(strings.TrimPrefix(path, "/"))
	if err != nil {
		return fmt.Errorf("cannot read CA bundle %s: %w", path, err)
	}
	defer file.Close()
	const maxBundleSize = 4 << 20
	data, err := io.ReadAll(io.LimitReader(file, maxBundleSize+1))
	if err != nil {
		return fmt.Errorf("cannot read CA bundle %s: %w", path, err)
	}
	if len(data) > maxBundleSize {
		return fmt.Errorf("CA bundle %s exceeds %d bytes", path, maxBundleSize)
	}
	if !x509.NewCertPool().AppendCertsFromPEM(data) {
		return fmt.Errorf("CA bundle %s contains no usable certificates", path)
	}
	return nil
}

func checkSQLiteFile(files fs.FS, path string) error {
	file, err := files.Open(strings.TrimPrefix(path, "/"))
	if err != nil {
		return fmt.Errorf("cannot read v2rayA database %s: %w", path, err)
	}
	defer file.Close()
	var header [16]byte
	if _, err := io.ReadFull(file, header[:]); err != nil {
		return errors.New("v2rayA database is empty or unreadable")
	}
	if !bytes.Equal(header[:], []byte("SQLite format 3\x00")) {
		return errors.New("v2rayA database does not contain a valid SQLite header")
	}
	return nil
}

func checkDatabase(ctx context.Context) error {
	return checkDatabasePath(ctx, paths.V2rayADB)
}

func checkDatabasePath(ctx context.Context, path string) error {
	uri := url.URL{Scheme: "file", Path: path}
	query := url.Values{"mode": {"ro"}, "_pragma": {"busy_timeout(1000)"}}
	uri.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return errors.New("cannot open the v2rayA database for read-only checks")
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var setting string
	if err := db.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = ?", "system:setting").Scan(&setting); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("v2rayA database schema/settings are missing or inaccessible")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(setting), &object); err != nil || object == nil {
		return errors.New("v2rayA database settings are not a JSON object")
	}
	return nil
}

func checkAPI(ctx context.Context) error {
	_, err := v2raya.NewClient("vpn-guardian-preflight").Call(ctx, http.MethodGet, "touch", nil)
	return apiAccessError(ctx, err)
}

func apiAccessError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var apiErr *v2raya.APIError
	if errors.As(err, &apiErr) {
		return fmt.Errorf("local v2rayA API rejected the readiness request (HTTP %d)", apiErr.StatusCode)
	}
	// Client errors may contain response bodies or local auth details. The
	// diagnostic deliberately describes the failing boundary without them.
	return errors.New("local v2rayA API or its database authentication is inaccessible")
}
