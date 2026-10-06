package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func authConfigured() bool {
	var cfg authConfig
	if err := readJSONFile(authConfigPath(), &cfg); err != nil {
		return false
	}
	return cfg.Salt != "" && cfg.Hash != "" && cfg.Iterations > 0
}

func savePIN(pin string) error {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	cfg := authConfig{
		Salt:       hex.EncodeToString(salt),
		Iterations: pinRounds,
	}
	cfg.Hash = hex.EncodeToString(pinDigest(pin, salt, cfg.Iterations))
	return writeJSONFileAtomic(authConfigPath(), cfg, 0600)
}

func verifyPIN(pin string) bool {
	var cfg authConfig
	if readJSONFile(authConfigPath(), &cfg) != nil || cfg.Iterations <= 0 {
		return false
	}
	salt, err := hex.DecodeString(cfg.Salt)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(cfg.Hash)
	if err != nil {
		return false
	}
	got := pinDigest(pin, salt, cfg.Iterations)
	return len(got) == len(want) && subtle.ConstantTimeCompare(got, want) == 1
}

func pinDigest(pin string, salt []byte, rounds int) []byte {
	first := make([]byte, 0, len(salt)+len(pin))
	first = append(first, salt...)
	first = append(first, pin...)
	sum := sha256.Sum256(first)
	for i := 1; i < rounds; i++ {
		h := sha256.New()
		_, _ = h.Write(sum[:])
		_, _ = h.Write(salt)
		_, _ = h.Write([]byte(pin))
		copy(sum[:], h.Sum(nil))
	}
	out := make([]byte, len(sum))
	copy(out, sum[:])
	return out
}

func createSession() (string, session, error) {
	if err := os.MkdirAll(sessionDirectory(), 0700); err != nil {
		return "", session{}, err
	}
	token, err := randomHex(24)
	if err != nil {
		return "", session{}, err
	}
	csrf, err := randomHex(24)
	if err != nil {
		return "", session{}, err
	}
	sess := session{CSRF: csrf, Expires: time.Now().Add(sessionTTL).Unix()}
	if err := writeJSONFileAtomic(sessionFile(token), sess, 0600); err != nil {
		return "", session{}, err
	}
	return token, sess, nil
}

func currentSession(r *http.Request) (string, session, bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || !validSessionToken(cookie.Value) {
		return "", session{}, false
	}
	token := cookie.Value
	var sess session
	if err := readJSONFile(sessionFile(token), &sess); err != nil {
		return "", session{}, false
	}
	if sess.CSRF == "" || sess.Expires <= time.Now().Unix() {
		_ = os.Remove(sessionFile(token))
		return "", session{}, false
	}
	return token, sess, true
}

func refreshSession(token string, sess *session) {
	if !validSessionToken(token) || sess == nil {
		return
	}
	sess.Expires = time.Now().Add(sessionTTL).Unix()
	_ = writeJSONFileAtomic(sessionFile(token), *sess, 0600)
}

func sessionFile(token string) string {
	return filepath.Join(sessionDirectory(), token+".json")
}

func validSessionToken(token string) bool {
	if len(token) != 48 {
		return false
	}
	_, err := hex.DecodeString(token)
	return err == nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func authConfigPath() string {
	if v := strings.TrimSpace(os.Getenv("VPN_GUARDIAN_AUTH_PATH")); v != "" {
		return v
	}
	return authPath
}

func sessionDirectory() string {
	if v := strings.TrimSpace(os.Getenv("VPN_GUARDIAN_SESSION_DIR")); v != "" {
		return v
	}
	return sessionDir
}
