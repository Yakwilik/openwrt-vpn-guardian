package setup

import (
	"errors"
	"io"
	"strings"
)

// Credentials are transient input for account creation, never configuration or
// status data. Neither field is serialized, and callers must not log them.
type Credentials struct {
	Username string `json:"-"`
	Password string `json:"-"`
}

// RequestAccount gathers a confirmed v2rayA administrator account. readSecret
// is the caller's hidden terminal input function. With no callback, tests and
// other stream callers use the same buffered reader as the rest of setup.
func RequestAccount(input io.Reader, output io.Writer, readSecret func() (string, error)) (Credentials, error) {
	w, err := newWizard(input, output)
	if err != nil {
		return Credentials{}, err
	}
	if err := w.print("\nv2rayA needs an administrator account. Choose the credentials you will use in its web interface.\nType cancel at any prompt to stop.\n"); err != nil {
		return Credentials{}, err
	}
	var credentials Credentials
	for credentials.Username == "" {
		credentials.Username, err = w.ask("Username: ")
		if err != nil {
			return Credentials{}, err
		}
		if credentials.Username == "" {
			if err := w.print("Username must not be empty.\n"); err != nil {
				return Credentials{}, err
			}
		}
	}
	credentials.Password, err = w.accountPassword(readSecret)
	if err != nil {
		return Credentials{}, err
	}
	if err := w.confirm("Create this v2rayA account? [y/N]: "); err != nil {
		return Credentials{}, err
	}
	return credentials, nil
}

func (w *wizard) accountPassword(readSecret func() (string, error)) (string, error) {
	for {
		password, err := w.secret("Password (6-32 bytes): ", readSecret)
		if err != nil {
			return "", err
		}
		if len(password) < 6 || len(password) > 32 {
			if err := w.print("Password must contain 6-32 bytes.\n"); err != nil {
				return "", err
			}
			continue
		}
		repeated, err := w.secret("Repeat password: ", readSecret)
		if err != nil {
			return "", err
		}
		if password == repeated {
			return password, nil
		}
		if err := w.print("Passwords do not match. Enter a new password.\n"); err != nil {
			return "", err
		}
	}
}

func (w *wizard) secret(prompt string, readSecret func() (string, error)) (string, error) {
	if err := w.print("%s", prompt); err != nil {
		return "", err
	}
	var value string
	var err error
	if readSecret != nil {
		value, err = readSecret()
	} else {
		value, err = w.readLine()
		value = strings.TrimSuffix(strings.TrimSuffix(value, "\n"), "\r")
	}
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, ErrCancelled) {
			return "", ErrCancelled
		}
		return "", errors.New("could not read account password")
	}
	if err := w.print("\n"); err != nil {
		return "", err
	}
	switch strings.ToLower(value) {
	case "cancel", "quit", "q", "\x03":
		return "", ErrCancelled
	}
	return value, nil
}
