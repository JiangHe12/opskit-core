//go:build !windows

package securefile

import (
	"os"
	"path/filepath"
	"testing"
)

func secureTestRoot(*testing.T, string) {}

func TestWriteFileCreatesMode0600(t *testing.T) {
	path := secureTestPath(t, "state")
	if err := WriteFile(path, []byte("value")); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %#o, want 0600", got)
	}
}

func TestReadAndWriteRejectSymlinkTarget(t *testing.T) {
	dir := filepath.Dir(secureTestPath(t, "state"))
	target := filepath.Join(dir, "target")
	path := filepath.Join(dir, "state")
	if err := WriteFile(target, []byte("old")); err != nil {
		t.Fatalf("WriteFile(target) error = %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if _, err := ReadFile(path); err == nil {
		t.Fatal("ReadFile() error = nil, want symlink rejection")
	}
	if err := WriteFile(path, []byte("new")); err == nil {
		t.Fatal("WriteFile() error = nil, want symlink rejection")
	}
	data, err := ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile(target) error = %v", err)
	}
	if string(data) != "old" {
		t.Fatalf("symlink target changed to %q", data)
	}
}

func TestReadAndWriteRejectInsecureTargetMode(t *testing.T) {
	path := secureTestPath(t, "state")
	if err := EnsureParent(path); err != nil {
		t.Fatalf("EnsureParent() error = %v", err)
	}
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	if _, err := ReadFile(path); err == nil {
		t.Fatal("ReadFile() error = nil, want insecure mode rejection")
	}
	if err := WriteFile(path, []byte("new")); err == nil {
		t.Fatal("WriteFile() error = nil, want insecure mode rejection")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if string(data) != "old" {
		t.Fatalf("insecure target changed to %q", data)
	}
}

func TestWriteFileRejectsWritableParent(t *testing.T) {
	root := t.TempDir()
	secureTestRoot(t, root)
	parent := filepath.Join(root, "unsafe")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	path := filepath.Join(parent, "state")
	if err := WriteFile(path, []byte("value")); err == nil {
		t.Fatal("WriteFile() error = nil, want writable parent rejection")
	}
}
