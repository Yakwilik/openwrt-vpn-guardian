package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/paths"
)

type serviceAuthConfig struct {
	Hash      string `json:"hash"`
	CreatedAt int64  `json:"createdAt"`
}

func RunAPIKey(args []string) error {
	if len(args) == 0 {
		return errors.New("api-key command required: create, revoke or status")
	}

	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("vpn-guardian api-key create", flag.ContinueOnError)
		output := fs.String("output", "", "write the plaintext key once to this file")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("api-key create accepts no positional arguments")
		}
		if strings.TrimSpace(*output) == "" {
			return errors.New("api-key create requires --output")
		}
		if err := createServiceAPIKey(*output); err != nil {
			return err
		}
		fmt.Printf("service API key created; plaintext written to %s\n", *output)
		return nil

	case "revoke":
		if len(args) != 1 {
			return errors.New("api-key revoke accepts no arguments")
		}
		if err := os.Remove(serviceAuthConfigPath()); err != nil && !os.IsNotExist(err) {
			return err
		}
		fmt.Println("service API key revoked")
		return nil

	case "status":
		if len(args) != 1 {
			return errors.New("api-key status accepts no arguments")
		}
		if serviceAPIKeyConfigured() {
			fmt.Println("configured")
		} else {
			fmt.Println("not configured")
		}
		return nil

	default:
		return fmt.Errorf("unknown api-key command %q", args[0])
	}
}

func createServiceAPIKey(outputPath string) error {
	token, err := randomHex(32)
	if err != nil {
		return err
	}

	outputPath = filepath.Clean(outputPath)
	if err := os.MkdirAll(filepath.Dir(outputPath), 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create service API key output: %w", err)
	}
	cleanupOutput := true
	defer func() {
		_ = file.Close()
		if cleanupOutput {
			_ = os.Remove(outputPath)
		}
	}()

	if _, err := file.WriteString(token + "\n"); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}

	sum := sha256.Sum256([]byte(token))
	cfg := serviceAuthConfig{
		Hash:      hex.EncodeToString(sum[:]),
		CreatedAt: time.Now().Unix(),
	}
	if err := writeJSONFileAtomic(serviceAuthConfigPath(), cfg, 0600); err != nil {
		return err
	}
	cleanupOutput = false
	return nil
}

func serviceAPIKeyConfigured() bool {
	var cfg serviceAuthConfig
	if err := readJSONFile(serviceAuthConfigPath(), &cfg); err != nil {
		return false
	}
	decoded, err := hex.DecodeString(cfg.Hash)
	return err == nil && len(decoded) == sha256.Size
}

func verifyServiceAPIKey(token string) bool {
	token = strings.TrimSpace(token)
	if !validServiceAPIKeyToken(token) {
		return false
	}

	var cfg serviceAuthConfig
	if err := readJSONFile(serviceAuthConfigPath(), &cfg); err != nil {
		return false
	}
	want, err := hex.DecodeString(cfg.Hash)
	if err != nil || len(want) != sha256.Size {
		return false
	}
	got := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(got[:], want) == 1
}

func validServiceAPIKeyToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	_, err := hex.DecodeString(token)
	return err == nil
}

func requestServiceAPIKey(r *http.Request) string {
	if r == nil {
		return ""
	}
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	const prefix = "Bearer "
	if !strings.HasPrefix(value, prefix) {
		return ""
	}
	token := strings.TrimSpace(strings.TrimPrefix(value, prefix))
	if strings.ContainsAny(token, " \t\r\n") || !validServiceAPIKeyToken(token) {
		return ""
	}
	return token
}

func serviceAPIAuthenticated(r *http.Request) bool {
	return verifyServiceAPIKey(requestServiceAPIKey(r))
}

func serviceAPIActionAllowed(action string) bool {
	switch action {
	case "login", "logout", "change_pin":
		return false
	default:
		return true
	}
}

func serviceAuthConfigPath() string {
	if value := strings.TrimSpace(os.Getenv("VPN_GUARDIAN_SERVICE_AUTH_PATH")); value != "" {
		return value
	}
	return paths.ServiceAuthConfig
}
