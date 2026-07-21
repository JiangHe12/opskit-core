package credstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/v2/lockfile"
)

func TestEncryptedFilePutGetRoundTrip(t *testing.T) {
	backend := newTestEncryptedFileBackend(t)

	if err := backend.Put(context.Background(), "dev", "nacos-secret"); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	got, err := backend.Get(context.Background(), "dev")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got != "nacos-secret" {
		t.Fatalf("Get() = %q", got)
	}
}

func TestEncryptedFileGetMissingReturnsErrNotFound(t *testing.T) {
	backend := newTestEncryptedFileBackend(t)

	if _, err := backend.Get(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}
}

func TestEncryptedFilePutOverwrites(t *testing.T) {
	backend := newTestEncryptedFileBackend(t)

	if err := backend.Put(context.Background(), "dev", "old"); err != nil {
		t.Fatalf("Put(old) error = %v", err)
	}
	if err := backend.Put(context.Background(), "dev", "new"); err != nil {
		t.Fatalf("Put(new) error = %v", err)
	}
	got, err := backend.Get(context.Background(), "dev")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got != "new" {
		t.Fatalf("Get() = %q, want new", got)
	}
}

func TestEncryptedFileDeleteRemovesEntry(t *testing.T) {
	backend := newTestEncryptedFileBackend(t)

	if err := backend.Put(context.Background(), "dev", "secret"); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if err := backend.Delete(context.Background(), "dev"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := backend.Get(context.Background(), "dev"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}
}

func TestEncryptedFileDeleteMissingIsNoop(t *testing.T) {
	backend := newTestEncryptedFileBackend(t)

	if err := backend.Delete(context.Background(), "missing"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
}

func TestEncryptedFileWrongPasswordFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.enc")
	backend := newTestEncryptedFileBackendAt(t, path, "password-a")
	if err := backend.Put(context.Background(), "dev", "secret"); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	backend = newTestEncryptedFileBackendAt(t, path, "password-b")
	_, err := backend.Get(context.Background(), "dev")
	if err == nil || !strings.Contains(err.Error(), "failed to decrypt credentials") {
		t.Fatalf("Get() error = %v, want decrypt failure", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("Get() error leaks plaintext: %v", err)
	}
}

func TestEncryptedFileFileCorruptionFails(t *testing.T) {
	backend := newTestEncryptedFileBackend(t)
	if err := os.WriteFile(backend.path, []byte("not-opskit"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := backend.Get(context.Background(), "dev")
	if err == nil || !strings.Contains(err.Error(), "invalid encrypted credential file") {
		t.Fatalf("Get() error = %v, want invalid file", err)
	}
}

func TestEncryptedFileFilePermsRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose owner-only file mode through os.FileMode")
	}
	backend := newTestEncryptedFileBackend(t)
	if err := os.WriteFile(backend.path, []byte("bad"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if _, err := backend.Get(context.Background(), "dev"); err == nil {
		t.Fatal("Get() error = nil, want permission error")
	}
	if err := backend.Put(context.Background(), "dev", "secret"); err == nil {
		t.Fatal("Put() error = nil, want permission error")
	}
}

func TestEncryptedFileAvailableWithoutEnvFails(t *testing.T) {
	t.Setenv("OPSKIT_MASTER_PASSWORD", "")
	if err := (&encryptedFileBackend{}).Available(); err == nil {
		t.Fatal("Available() error = nil, want error")
	}
}

func TestEncryptedFileAvailableWithEnvSucceeds(t *testing.T) {
	t.Setenv("OPSKIT_MASTER_PASSWORD", "test-pass-123")
	if err := (&encryptedFileBackend{}).Available(); err != nil {
		t.Fatalf("Available() error = %v", err)
	}
}

func TestEncryptedFilePutWaitsForCrossProcessLock(t *testing.T) {
	backend := newTestEncryptedFileBackend(t)
	externalLock := lockfile.New(backend.path)
	if err := externalLock.Acquire(); err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	t.Cleanup(func() { _ = externalLock.Release() })

	done := make(chan error, 1)
	go func() {
		done <- backend.Put(context.Background(), "dev", "secret")
	}()
	select {
	case err := <-done:
		t.Fatalf("Put() completed while external lock was held: %v", err)
	case <-time.After(250 * time.Millisecond):
	}
	if err := externalLock.Release(); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Put() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Put() did not resume after external lock release")
	}
}

func TestEncryptedFileConcurrentBackendInstancesDoNotLoseUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.enc")
	t.Setenv("OPSKIT_MASTER_PASSWORD", "test-pass-123")
	backends := []*encryptedFileBackend{{path: path}, {path: path}}
	start := make(chan struct{})
	errorsByWriter := make([]error, len(backends))
	var writers sync.WaitGroup
	for index, backend := range backends {
		writers.Add(1)
		go func() {
			defer writers.Done()
			<-start
			errorsByWriter[index] = backend.Put(
				context.Background(),
				fmt.Sprintf("context-%d", index),
				fmt.Sprintf("secret-%d", index),
			)
		}()
	}
	close(start)
	writers.Wait()
	for index, err := range errorsByWriter {
		if err != nil {
			t.Fatalf("Put(%d) error = %v", index, err)
		}
	}
	for index := range backends {
		value, err := backends[0].Get(context.Background(), fmt.Sprintf("context-%d", index))
		if err != nil {
			t.Fatalf("Get(%d) error = %v", index, err)
		}
		if want := fmt.Sprintf("secret-%d", index); value != want {
			t.Fatalf("Get(%d) = %q, want %q", index, value, want)
		}
	}
}

func newTestEncryptedFileBackend(t *testing.T) *encryptedFileBackend {
	t.Helper()
	return newTestEncryptedFileBackendAt(t, filepath.Join(t.TempDir(), "credentials.enc"), "test-pass-123")
}

func newTestEncryptedFileBackendAt(t *testing.T, path string, password string) *encryptedFileBackend {
	t.Helper()
	t.Setenv("OPSKIT_MASTER_PASSWORD", password)
	return &encryptedFileBackend{path: path}
}
