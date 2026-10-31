package diagnostics

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	maxLogBytes = 2 << 20
	logBackups  = 3
)

// rotatedLog bounds persistent storage. One active file and three backups use
// at most 8 MiB per stream. This deliberately does not run logrotate or rely
// on volatile /var/log, which disappears on OpenWrt reboot.
type rotatedLog struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	backups  int
	file     *os.File
	size     int64
}

func newRotatedLog(dir, name string, limit int64, backups int) (*rotatedLog, error) {
	if limit < 1024 || backups < 0 || backups > 8 {
		return nil, fmt.Errorf("invalid diagnostic log limits")
	}
	if name != filepath.Base(name) || strings.ContainsAny(name, "/\\") {
		return nil, fmt.Errorf("invalid diagnostic log name")
	}
	if info, err := os.Lstat(dir); err == nil && !info.IsDir() {
		return nil, fmt.Errorf("diagnostic log directory must not be a symlink or file")
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	log := &rotatedLog{path: filepath.Join(dir, name), maxBytes: limit, backups: backups}
	if err := log.open(); err != nil {
		return nil, err
	}
	return log, nil
}

func (l *rotatedLog) open() error {
	// Never follow a symlink in persistent log storage.
	if info, err := os.Lstat(l.path); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("diagnostic log %s is not a regular file", l.path)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.file, l.size = f, info.Size()
	return nil
}

func (l *rotatedLog) rotate() error {
	if err := l.file.Close(); err != nil {
		return err
	}
	l.file = nil
	_ = os.Remove(fmt.Sprintf("%s.%d", l.path, l.backups))
	for i := l.backups - 1; i >= 1; i-- {
		old, next := fmt.Sprintf("%s.%d", l.path, i), fmt.Sprintf("%s.%d", l.path, i+1)
		if err := os.Rename(old, next); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if l.backups > 0 {
		if err := os.Rename(l.path, l.path+".1"); err != nil && !os.IsNotExist(err) {
			return err
		}
	} else {
		_ = os.Remove(l.path)
	}
	return l.open()
}

func (l *rotatedLog) WriteLine(line string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	line = strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ").Replace(line))
	if len(line) > 4095 {
		line = line[:4095] + " [truncated]"
	}
	payload := []byte(line + "\n")
	if l.file == nil {
		if err := l.open(); err != nil {
			return err
		}
	}
	if l.size+int64(len(payload)) > l.maxBytes {
		if err := l.rotate(); err != nil {
			return err
		}
	}
	n, err := l.file.Write(payload)
	l.size += int64(n)
	return err
}

func (l *rotatedLog) Sync() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	return l.file.Sync()
}

func (l *rotatedLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}
