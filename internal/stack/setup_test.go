package stack

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/config"
)

func TestReadSetupManifestDoesNotMergeExistingManifestWithDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stack.json")
	writeSetupTestFile(t, path, []byte(`{"version":1,"lanInterface":"br-existing"}`))
	stack, _ := setupTestPair()
	present, err := readSetupManifest(path, &stack)
	if err != nil || !present {
		t.Fatalf("existing manifest read: present=%t, error=%v", present, err)
	}
	want := config.Stack{Version: 1, LANInterface: "br-existing"}
	if !reflect.DeepEqual(stack, want) {
		t.Fatal("missing fields in an existing manifest inherited proposed defaults")
	}
	if stack.Validate() == nil {
		t.Fatal("incomplete existing manifest must not pass the configuration gate")
	}

	routingPath := filepath.Join(t.TempDir(), "routing.json")
	writeSetupTestFile(t, routingPath, []byte(`{"version":1}`))
	routing := config.DefaultRouting()
	if present, err := readSetupManifest(routingPath, &routing); err != nil || !present {
		t.Fatalf("existing routing manifest read: present=%t, error=%v", present, err)
	}
	if len(routing.ProxyDomains) != 0 || len(routing.ProxyIPs) != 0 {
		t.Fatal("existing routing manifest inherited unrequested default routes")
	}
}

func TestReadSetupManifestMissingFilePreservesProposedDefaults(t *testing.T) {
	stack, routing := setupTestPair()
	wantStack, wantRouting := stack, routing
	dir := t.TempDir()
	if present, err := readSetupManifest(filepath.Join(dir, "stack.json"), &stack); err != nil || present {
		t.Fatalf("missing stack manifest: present=%t, error=%v", present, err)
	}
	if present, err := readSetupManifest(filepath.Join(dir, "routing.json"), &routing); err != nil || present {
		t.Fatalf("missing routing manifest: present=%t, error=%v", present, err)
	}
	if !reflect.DeepEqual(stack, wantStack) || !reflect.DeepEqual(routing, wantRouting) {
		t.Fatal("missing manifests changed the proposed defaults")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("reading a missing manifest must not create files")
	}
}

func TestReadSetupManifestErrorsPreserveDraft(t *testing.T) {
	for _, kind := range []string{"malformed JSON", "unreadable file"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "stack.json")
			if kind == "malformed JSON" {
				writeSetupTestFile(t, path, []byte(`{"version":1,"front":`))
			} else if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			stack, _ := setupTestPair()
			before := stack
			present, err := readSetupManifest(path, &stack)
			if err == nil || present {
				t.Fatal("manifest read failure must be reported")
			}
			if !reflect.DeepEqual(stack, before) {
				t.Fatal("failed read partially overwrote the proposed draft")
			}
		})
	}
}

func TestInstallSetupManifestsPrivateAtomicReplacementsAndExactRollback(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "configuration")
	stackPath, routingPath := filepath.Join(dir, "stack.json"), filepath.Join(dir, "routing.json")
	oldStack := []byte("  {\n\t\"version\": 1, \"original\": \"stack\"\n  }\n\n")
	oldRouting := []byte("{ \"version\" : 1, \"original\" : \"routing\" }\n")
	writeSetupTestFile(t, stackPath, oldStack)
	writeSetupTestFile(t, routingPath, oldRouting)
	oldHandles := make([]*os.File, 0, 2)
	for _, path := range []string{stackPath, routingPath} {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		oldHandles = append(oldHandles, f)
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
	}
	stack, routing := setupTestPair()
	rollback, err := installSetupManifests(stackPath, routingPath, stack, routing)
	if err != nil || rollback == nil {
		t.Fatalf("install manifests: %v", err)
	}
	assertSetupInstalledPair(t, stackPath, routingPath, stack, routing)
	for i, want := range [][]byte{oldStack, oldRouting} {
		got, err := io.ReadAll(oldHandles[i])
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("replacement modified an already open old file instead of replacing it atomically")
		}
	}
	assertSetupNoTemporaryFiles(t, dir)
	if err := rollback(); err != nil {
		t.Fatal(err)
	}
	assertSetupFileBytes(t, stackPath, oldStack)
	assertSetupFileBytes(t, routingPath, oldRouting)
	assertSetupNoTemporaryFiles(t, dir)
}

func TestInstallSetupManifestsRollbackPreservesOriginalExistence(t *testing.T) {
	tests := []struct {
		name                         string
		stackPresent, routingPresent bool
	}{
		{"new pair", false, false},
		{"only stack existed", true, false},
		{"only routing existed", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "configuration")
			stackPath, routingPath := filepath.Join(dir, "stack.json"), filepath.Join(dir, "routing.json")
			original := []byte("original bytes\n")
			if tt.stackPresent {
				writeSetupTestFile(t, stackPath, original)
			}
			if tt.routingPresent {
				writeSetupTestFile(t, routingPath, original)
			}
			stack, routing := setupTestPair()
			rollback, err := installSetupManifests(stackPath, routingPath, stack, routing)
			if err != nil || rollback == nil {
				t.Fatalf("install manifests: %v", err)
			}
			assertSetupInstalledPair(t, stackPath, routingPath, stack, routing)
			info, err := os.Stat(dir)
			if err != nil || info.Mode().Perm() != 0700 {
				t.Fatal("new configuration directory must be private")
			}
			for i := 0; i < 2; i++ {
				if err := rollback(); err != nil {
					t.Fatal(err)
				}
			}
			for path, existed := range map[string]bool{stackPath: tt.stackPresent, routingPath: tt.routingPresent} {
				if existed {
					assertSetupFileBytes(t, path, original)
				} else if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("rollback retained a manifest that did not previously exist")
				}
			}
			assertSetupNoTemporaryFiles(t, dir)
		})
	}
}

func TestInstallSetupManifestsCaptureFailureDoesNotWriteEitherFile(t *testing.T) {
	for _, failedIndex := range []int{0, 1} {
		t.Run([]string{"stack capture", "routing capture"}[failedIndex], func(t *testing.T) {
			dir := t.TempDir()
			paths := []string{filepath.Join(dir, "stack.json"), filepath.Join(dir, "routing.json")}
			if err := os.Mkdir(paths[failedIndex], 0700); err != nil {
				t.Fatal(err)
			}
			original := []byte("original manifest bytes\n")
			writeSetupTestFile(t, paths[1-failedIndex], original)
			stack, routing := setupTestPair()
			rollback, err := installSetupManifests(paths[0], paths[1], stack, routing)
			if err == nil || rollback != nil {
				t.Fatal("capture failure must abort before writing manifests")
			}
			assertSetupFileBytes(t, paths[1-failedIndex], original)
			info, err := os.Stat(paths[failedIndex])
			if err != nil || !info.IsDir() {
				t.Fatal("capture failure changed its source")
			}
			assertSetupNoTemporaryFiles(t, dir)
		})
	}
}

func TestInstallSetupManifestsSecondWriteFailureRestoresExistingPair(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission failure requires a process without root privileges")
	}
	dir := t.TempDir()
	stackPath := filepath.Join(dir, "stack.json")
	routingDir := filepath.Join(dir, "routing-directory")
	routingPath := filepath.Join(routingDir, "routing.json")
	oldStack, oldRouting := []byte("original stack\n"), []byte("original routing\n")
	writeSetupTestFile(t, stackPath, oldStack)
	writeSetupTestFile(t, routingPath, oldRouting)
	if err := os.Chmod(routingDir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(routingDir, 0700) })
	stack, routing := setupTestPair()
	rollback, err := installSetupManifests(stackPath, routingPath, stack, routing)
	if err == nil || rollback != nil {
		t.Fatal("failed second write must report failure and roll back internally")
	}
	assertSetupFileBytes(t, stackPath, oldStack)
	assertSetupFileBytes(t, routingPath, oldRouting)
	assertSetupNoTemporaryFiles(t, dir, routingDir)
}

func TestInstallSetupManifestsSecondWriteFailureRemovesNewFirstFile(t *testing.T) {
	dir := t.TempDir()
	stackPath := filepath.Join(dir, "first-manifest")
	// Both reads initially return not-exist. Installing the first manifest
	// then makes the second parent unusable, forcing a failure after write 1.
	routingPath := filepath.Join(stackPath, "routing.json")
	stack, routing := setupTestPair()
	rollback, err := installSetupManifests(stackPath, routingPath, stack, routing)
	if err == nil || rollback != nil {
		t.Fatal("second-write path conflict must fail")
	}
	if _, err := os.Stat(stackPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed second write retained a new first manifest")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("failed pair installation left files behind")
	}
}

func TestParseSetupArgs(t *testing.T) {
	for _, command := range []string{"init", "bootstrap"} {
		for _, args := range [][]string{
			{"--non-interactive"},
			{"--dry-run", "--non-interactive"},
			{"--non-interactive=true", "--dry-run=true"},
		} {
			opts, err := parseSetupArgs(command, args)
			if err != nil {
				t.Fatal(err)
			}
			if opts.Interactive || opts.Reconfigure != (command == "init") {
				t.Fatal("non-interactive or command-specific setup options are incorrect")
			}
			wantDryRun := len(args) == 2
			if opts.DryRun != wantDryRun {
				t.Fatal("dry-run option was parsed incorrectly")
			}
		}
	}
	for _, args := range [][]string{
		{"extra"}, {"--dry-run", "extra"}, {"--unknown"}, {"--force"},
		{"--dry-run=invalid"}, {"--non-interactive=invalid"},
	} {
		if _, err := parseSetupArgs("init", args); err == nil {
			t.Fatalf("unexpected acceptance of arguments %q", args)
		}
	}
}

func setupTestPair() (config.Stack, config.Routing) {
	return config.DefaultStack("br-setup", "192.0.2.0/24", "wan0", "/usr/share/xray"), config.DefaultRouting()
}

func writeSetupTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func assertSetupFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("manifest contents differ from the original byte sequence")
	}
}

func assertSetupInstalledPair(t *testing.T, stackPath, routingPath string, stack config.Stack, routing config.Routing) {
	t.Helper()
	var gotStack config.Stack
	var gotRouting config.Routing
	for path, value := range map[string]any{stackPath: &gotStack, routingPath: &gotRouting} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, value); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatal("installed manifest must be a private regular file")
		}
	}
	if !reflect.DeepEqual(gotStack, stack) || !reflect.DeepEqual(gotRouting, routing) {
		t.Fatal("installed manifest pair differs from the confirmed configuration")
	}
}

func assertSetupNoTemporaryFiles(t *testing.T, dirs ...string) {
	t.Helper()
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".vpn-guardian-") {
				t.Fatal("manifest operation left an atomic-write temporary file behind")
			}
		}
	}
}
