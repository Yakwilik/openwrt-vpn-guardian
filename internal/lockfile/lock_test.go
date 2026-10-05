package lockfile

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestContentionIsBoundedAndLockCanBeReacquired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.lock")
	first, err := Try(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Release(first) })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := Acquire(ctx, path); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline, got %v", err)
	}
	Release(first)
	first = nil
	next, err := Try(path)
	if err != nil {
		t.Fatal(err)
	}
	Release(next)
}
