package stack

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

type archiveEntry struct {
	name     string
	typeflag byte
	linkname string
	body     string
	mode     int64
}

func writeTestArchive(t *testing.T, entries []archiveEntry) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "test.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	for _, entry := range entries {
		h := &tar.Header{
			Name:     entry.name,
			Typeflag: entry.typeflag,
			Linkname: entry.linkname,
			Mode:     entry.mode,
			Size:     int64(len(entry.body)),
		}
		if entry.typeflag == tar.TypeSymlink {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if entry.body != "" && entry.typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(entry.body)); err != nil {
				t.Fatal(err)
			}
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExtractArchivePreservesRelativeSymlink(t *testing.T) {
	archive := writeTestArchive(t, []archiveEntry{
		{name: "usr/lib/vpn-guardian/runtime", typeflag: tar.TypeReg, body: "payload", mode: 0644},
		{name: "usr/lib/vpn-guardian/current", typeflag: tar.TypeSymlink, linkname: "runtime", mode: 0777},
	})

	dst := t.TempDir()
	if err := extractArchive(archive, dst); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(dst, "usr/lib/vpn-guardian/current")
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%s is not a symlink", link)
	}
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if target != "runtime" {
		t.Fatalf("symlink target = %q, want runtime", target)
	}
}

func TestExtractArchiveRejectsEscapingSymlink(t *testing.T) {
	archive := writeTestArchive(t, []archiveEntry{
		{name: "usr/lib/vpn-guardian/current", typeflag: tar.TypeSymlink, linkname: "../../../../outside", mode: 0777},
	})

	if err := extractArchive(archive, t.TempDir()); err == nil {
		t.Fatal("expected escaping symlink to be rejected")
	}
}
