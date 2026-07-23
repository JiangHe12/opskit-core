package securefile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

func TestWriteReadAndCheckFile(t *testing.T) {
	path := secureTestPath(t, "state.json")

	if err := WriteFile(path, []byte("first")); err != nil {
		t.Fatalf("WriteFile(first) error = %v", err)
	}
	result, err := WriteFileWithResult(path, []byte("second"))
	if err != nil {
		t.Fatalf("WriteFileWithResult(second) error = %v", err)
	}
	if result.State != WriteCommitCommitted || !result.IsCommitted() {
		t.Fatalf("WriteFileWithResult(second) result = %#v, want committed", result)
	}
	data, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != "second" {
		t.Fatalf("ReadFile() = %q, want second", data)
	}
	exists, err := CheckFile(path)
	if err != nil {
		t.Fatalf("CheckFile() error = %v", err)
	}
	if !exists {
		t.Fatal("CheckFile() exists = false, want true")
	}
}

func TestCheckFileMissing(t *testing.T) {
	path := secureTestPath(t, "missing")
	exists, err := CheckFile(path)
	if err != nil {
		t.Fatalf("CheckFile() error = %v", err)
	}
	if exists {
		t.Fatal("CheckFile() exists = true, want false")
	}
}

func TestWriteFileRejectsDirectoryTarget(t *testing.T) {
	path := secureTestPath(t, "target")
	if err := EnsureParent(path); err != nil {
		t.Fatalf("EnsureParent() error = %v", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := WriteFile(path, []byte("replacement")); err == nil {
		t.Fatal("WriteFile() error = nil, want non-regular target rejection")
	}
}

func TestWriteFileSyncsBeforeAtomicReplace(t *testing.T) {
	path := secureTestPath(t, "state")
	var events []string
	runtime := productionWriteRuntime
	runtime.write = func(file *os.File, data []byte) (int, error) {
		events = append(events, "write")
		return file.Write(data)
	}
	runtime.sync = func(file *os.File) error {
		events = append(events, "sync-file")
		return file.Sync()
	}
	runtime.close = func(file *os.File) error {
		events = append(events, "close")
		return file.Close()
	}
	runtime.replace = func(from, to string) error {
		events = append(events, "replace")
		return atomicReplaceFile(from, to)
	}
	runtime.syncParent = func(path string) error {
		events = append(events, "sync-parent")
		return syncParentDirectory(path)
	}

	if err := writeFileWithRuntime(path, []byte("value"), runtime); err != nil {
		t.Fatalf("writeFileWithRuntime() error = %v", err)
	}
	want := []string{"write", "sync-file", "close", "replace", "sync-parent"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %#v, want %#v", events, want)
	}
}

func TestWriteFileResultDistinguishesCommittedPostCommitFailure(t *testing.T) {
	path := secureTestPath(t, "state")
	if err := WriteFile(path, []byte("old")); err != nil {
		t.Fatalf("WriteFile(old) error = %v", err)
	}
	injected := errors.New("injected parent sync failure")
	runtime := productionWriteRuntime
	runtime.syncParent = func(string) error {
		return injected
	}

	result, err := writeFileWithResultRuntime(path, []byte("new"), runtime)
	if err == nil || !errors.Is(err, injected) {
		t.Fatalf("writeFileWithResultRuntime() error = %v, want injected failure", err)
	}
	if result.State != WriteCommitCommittedPostCommitError || !result.IsCommitted() {
		t.Fatalf("write result = %#v, want committed post-commit error", result)
	}
	data, readErr := ReadFile(path)
	if readErr != nil {
		t.Fatalf("ReadFile() error = %v", readErr)
	}
	if string(data) != "new" {
		t.Fatalf("committed file = %q, want new", data)
	}
	assertNoTempArtifacts(t, path)
}

func TestWriteFilePreCommitFailuresPreserveOldFileAndCleanTemp(t *testing.T) {
	injected := errors.New("injected failure")
	tests := map[string]func(*writeRuntime){
		"write": func(runtime *writeRuntime) {
			runtime.write = func(*os.File, []byte) (int, error) {
				return 0, injected
			}
		},
		"short write": func(runtime *writeRuntime) {
			runtime.write = func(*os.File, []byte) (int, error) {
				return 1, nil
			}
		},
		"sync": func(runtime *writeRuntime) {
			runtime.sync = func(*os.File) error {
				return injected
			}
		},
		"close": func(runtime *writeRuntime) {
			runtime.close = func(file *os.File) error {
				_ = file.Close()
				return injected
			}
		},
		"replace": func(runtime *writeRuntime) {
			runtime.replace = func(string, string) error {
				return injected
			}
		},
	}
	for name, inject := range tests {
		t.Run(name, func(t *testing.T) {
			path := secureTestPath(t, "state")
			if err := WriteFile(path, []byte("old")); err != nil {
				t.Fatalf("WriteFile(old) error = %v", err)
			}
			runtime := productionWriteRuntime
			inject(&runtime)

			err := writeFileWithRuntime(path, []byte("new"), runtime)
			if err == nil {
				t.Fatal("writeFileWithRuntime() error = nil, want injected failure")
			}
			if name == "short write" && !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("short write error = %v, want io.ErrShortWrite", err)
			}
			data, readErr := ReadFile(path)
			if readErr != nil {
				t.Fatalf("ReadFile() error = %v", readErr)
			}
			if string(data) != "old" {
				t.Fatalf("old file changed to %q after failed write", data)
			}
			assertNoTempArtifacts(t, path)
		})
	}
}

func TestWriteFileUsesRandomSameDirectoryTemp(t *testing.T) {
	path := secureTestPath(t, "state")
	injected := errors.New("stop before replace")
	var sources []string
	for range 2 {
		runtime := productionWriteRuntime
		runtime.replace = func(from, _ string) error {
			sources = append(sources, from)
			return injected
		}
		if err := writeFileWithRuntime(path, []byte("value"), runtime); err == nil {
			t.Fatal("writeFileWithRuntime() error = nil, want injected failure")
		}
	}
	if filepath.Dir(sources[0]) != filepath.Dir(path) || filepath.Dir(sources[1]) != filepath.Dir(path) {
		t.Fatalf("temp files not created beside target: %#v", sources)
	}
	if sources[0] == sources[1] || sources[0] == path+".tmp" || sources[1] == path+".tmp" {
		t.Fatalf("temp names are not unique random paths: %#v", sources)
	}
	assertNoTempArtifacts(t, path)
}

func TestWriteFileDoesNotClobberTargetCreatedDuringPreparation(t *testing.T) {
	path := secureTestPath(t, "state")
	runtime := productionWriteRuntime
	runtime.close = func(file *os.File) error {
		if err := file.Close(); err != nil {
			return err
		}
		return WriteFile(path, []byte("concurrent"))
	}

	err := writeFileWithRuntime(path, []byte("prepared"), runtime)
	if appErr := apperrors.AsAppError(err); appErr.Code != apperrors.CodeConflict {
		t.Fatalf("writeFileWithRuntime() error = %v, want conflict", err)
	}
	data, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != "concurrent" {
		t.Fatalf("concurrent target changed to %q", data)
	}
	assertNoTempArtifacts(t, path)
}

func assertNoTempArtifacts(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	prefix := "." + filepath.Base(path) + ".tmp-"
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) {
			t.Fatalf("temporary artifact was not cleaned: %s", entry.Name())
		}
	}
}

func secureTestPath(t *testing.T, name string) string {
	t.Helper()
	root := t.TempDir()
	secureTestRoot(t, root)
	return filepath.Join(root, "private", name)
}
