//go:build !windows

package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAppendPreservesExistingDirectoryPermissions(t *testing.T) {
	t.Run("relative audit path preserves working directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Chdir(dir)
		if err := Append("audit.log", Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess}); err != nil {
			t.Fatalf("Append() error = %v", err)
		}
		assertDirectoryMode(t, dir, 0o755)
	})

	t.Run("custom key preserves shared parent", func(t *testing.T) {
		dir := t.TempDir()
		shared := filepath.Join(dir, "shared")
		if err := os.Mkdir(shared, 0o750); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "audit.log")
		keyPath := filepath.Join(shared, "audit.key")
		if err := AppendWithOptions(
			path,
			Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess},
			Options{IntegrityKeyPath: keyPath},
		); err != nil {
			t.Fatalf("AppendWithOptions() error = %v", err)
		}
		assertDirectoryMode(t, shared, 0o750)
	})

	t.Run("nested creation preserves existing ancestor", func(t *testing.T) {
		dir := t.TempDir()
		ancestor := filepath.Join(dir, "existing")
		if err := os.Mkdir(ancestor, 0o755); err != nil {
			t.Fatal(err)
		}
		firstNew := filepath.Join(ancestor, "new-one")
		secondNew := filepath.Join(firstNew, "new-two")
		if err := AppendWithOptions(
			filepath.Join(dir, "audit.log"),
			Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess},
			Options{IntegrityKeyPath: filepath.Join(secondNew, "audit.key")},
		); err != nil {
			t.Fatalf("AppendWithOptions() error = %v", err)
		}
		assertDirectoryMode(t, ancestor, 0o755)
		assertDirectoryMode(t, firstNew, 0o700)
		assertDirectoryMode(t, secondNew, 0o700)
	})

	t.Run("world writable parent fails closed", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		t.Chdir(dir)
		if err := Append("audit.log", Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess}); err == nil {
			t.Fatal("Append() error = nil, want insecure-directory rejection")
		}
		assertDirectoryMode(t, dir, 0o777)
	})

	t.Run("missing child under unsafe ancestor fails closed", func(t *testing.T) {
		dir := privateTestDir(t)
		unsafe := filepath.Join(dir, "unsafe")
		if err := os.Mkdir(unsafe, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(unsafe, 0o777); err != nil {
			t.Fatal(err)
		}
		missing := filepath.Join(unsafe, "missing")
		if err := AppendWithOptions(
			filepath.Join(dir, "audit.log"),
			Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess},
			Options{IntegrityKeyPath: filepath.Join(missing, "audit.key")},
		); err == nil {
			t.Fatal("AppendWithOptions() error = nil, want unsafe-ancestor rejection")
		}
		assertDirectoryMode(t, unsafe, 0o777)
		if _, err := os.Stat(missing); !os.IsNotExist(err) {
			t.Fatalf("missing child was created: %v", err)
		}
	})

	t.Run("secure leaf under unsafe grandparent fails closed", func(t *testing.T) {
		dir := privateTestDir(t)
		unsafe := filepath.Join(dir, "unsafe-grandparent")
		if err := os.Mkdir(unsafe, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(unsafe, 0o777); err != nil {
			t.Fatal(err)
		}
		leaf := filepath.Join(unsafe, "secure-leaf")
		if err := os.Mkdir(leaf, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := Append(
			filepath.Join(leaf, "audit.log"),
			Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess},
		); err == nil {
			t.Fatal("Append() error = nil, want unsafe-grandparent rejection")
		}
	})

	t.Run("symlink ancestor fails closed", func(t *testing.T) {
		dir := privateTestDir(t)
		target := filepath.Join(dir, "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if err := Append(
			filepath.Join(link, "audit.log"),
			Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess},
		); err == nil {
			t.Fatal("Append() error = nil, want symlink-ancestor rejection")
		}
	})

	t.Run("sticky shared ancestor permits private child", func(t *testing.T) {
		dir := privateTestDir(t)
		sticky := filepath.Join(dir, "sticky")
		if err := os.Mkdir(sticky, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(sticky, 0o777|os.ModeSticky); err != nil {
			t.Fatal(err)
		}
		missing := filepath.Join(sticky, "missing")
		if err := AppendWithOptions(
			filepath.Join(dir, "audit.log"),
			Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess},
			Options{IntegrityKeyPath: filepath.Join(missing, "audit.key")},
		); err != nil {
			t.Fatalf("AppendWithOptions() error = %v", err)
		}
		assertDirectoryMode(t, missing, 0o700)
	})

	t.Run("existing key parent becoming unsafe fails closed", func(t *testing.T) {
		dir := privateTestDir(t)
		keyDir := filepath.Join(dir, "keys")
		if err := os.Mkdir(keyDir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "audit.log")
		keyPath := filepath.Join(keyDir, "audit.key")
		options := Options{IntegrityKeyPath: keyPath}
		if err := AppendWithOptions(
			path,
			Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess},
			options,
		); err != nil {
			t.Fatalf("initial AppendWithOptions() error = %v", err)
		}
		beforeLog := mustReadFile(t, path)
		beforeKey := mustReadFile(t, keyPath)
		beforeCheckpoint := mustReadFile(t, checkpointPath(path))
		if err := os.Chmod(keyDir, 0o777); err != nil {
			t.Fatal(err)
		}

		if err := AppendWithOptions(
			path,
			Event{EventType: "resource.update", Operator: "bob", Status: StatusSuccess},
			options,
		); err == nil {
			t.Fatal("AppendWithOptions() error = nil, want unsafe key-parent rejection")
		}
		if _, err := Query(path, Filter{IntegrityKeyPath: keyPath}); err == nil {
			t.Fatal("Query() error = nil, want unsafe key-parent rejection")
		}
		if _, err := Verify(path, VerifyOptions{IntegrityKeyPath: keyPath}); err == nil {
			t.Fatal("Verify() error = nil, want unsafe key-parent rejection")
		}
		if got := mustReadFile(t, path); string(got) != string(beforeLog) {
			t.Fatal("unsafe key parent changed audit log")
		}
		if got := mustReadFile(t, keyPath); string(got) != string(beforeKey) {
			t.Fatal("unsafe key parent changed integrity key")
		}
		if got := mustReadFile(t, checkpointPath(path)); string(got) != string(beforeCheckpoint) {
			t.Fatal("unsafe key parent changed checkpoint")
		}
	})

	t.Run("existing log parent becoming unsafe fails closed", func(t *testing.T) {
		dir := privateTestDir(t)
		path := filepath.Join(dir, "audit.log")
		if err := Append(path, Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess}); err != nil {
			t.Fatalf("initial Append() error = %v", err)
		}
		beforeLog := mustReadFile(t, path)
		beforeKey := mustReadFile(t, defaultIntegrityKeyPath(path))
		beforeCheckpoint := mustReadFile(t, checkpointPath(path))
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}

		if err := Append(path, Event{EventType: "resource.update", Operator: "bob", Status: StatusSuccess}); err == nil {
			t.Fatal("Append() error = nil, want unsafe log-parent rejection")
		}
		if _, err := Query(path, Filter{}); err == nil {
			t.Fatal("Query() error = nil, want unsafe log-parent rejection")
		}
		if _, err := Verify(path, VerifyOptions{}); err == nil {
			t.Fatal("Verify() error = nil, want unsafe log-parent rejection")
		}
		if got := mustReadFile(t, path); string(got) != string(beforeLog) {
			t.Fatal("unsafe log parent changed audit log")
		}
		if got := mustReadFile(t, defaultIntegrityKeyPath(path)); string(got) != string(beforeKey) {
			t.Fatal("unsafe log parent changed integrity key")
		}
		if got := mustReadFile(t, checkpointPath(path)); string(got) != string(beforeCheckpoint) {
			t.Fatal("unsafe log parent changed checkpoint")
		}
	})
}

func assertDirectoryMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("directory mode = %#o, want %#o", got, want)
	}
}

func secureTestDirectory(t testing.TB, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("Mkdir(%s) error = %v", path, err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatalf("Chmod(%s) error = %v", path, err)
	}
}

func makeTestAuditFileInsecure(t testing.TB, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod(%s) error = %v", path, err)
	}
}
