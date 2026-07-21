package lockfile

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAcquireRelease(t *testing.T) {
	base := filepath.Join(t.TempDir(), "config")
	lock := New(base)

	if err := lock.Acquire(); err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if _, err := os.Stat(base + ".lock"); err != nil {
		t.Fatalf("lock file stat error = %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	if _, err := os.Stat(base + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("lock file still exists or unexpected error: %v", err)
	}
}

func TestReleaseDoesNotRemoveOtherOwner(t *testing.T) {
	base := filepath.Join(t.TempDir(), "config")
	first := New(base)
	second := New(base)

	if err := first.Acquire(); err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if err := second.Release(); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	if _, err := os.Stat(base + ".lock"); err != nil {
		t.Fatalf("lock file should remain: %v", err)
	}
	_ = first.Release()
}

func TestReleaseNonExistentLockIsNoop(t *testing.T) {
	base := filepath.Join(t.TempDir(), "config")
	lock := New(base)
	if err := lock.Release(); err != nil {
		t.Fatalf("Release() of missing lock error = %v", err)
	}
}

func TestAcquireStaleLockIsReclaimed(t *testing.T) {
	base := filepath.Join(t.TempDir(), "config")
	lockPath := base + ".lock"

	// Write a lock file with PID 0 — guaranteed to not correspond to a live process.
	stale := fmt.Sprintf("pid=%d\ntoken=deadbeef\nts=%s\n", 0, time.Now().UTC().Format(time.RFC3339))
	file, err := createLockFileExclusive(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(stale); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	staleTime := time.Now().Add(-lockInitializationGrace - time.Second)
	if err := os.Chtimes(lockPath, staleTime, staleTime); err != nil {
		t.Fatal(err)
	}

	lock := New(base)
	if err := lock.Acquire(); err != nil {
		t.Fatalf("Acquire() with stale lock error = %v", err)
	}
	defer func() { _ = lock.Release() }()

	// The new owner must now be reflected in the lock file.
	data, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	pid, token, err := parseLockFile(string(data))
	if err != nil {
		t.Fatalf("parseLockFile() error = %v", err)
	}
	if pid != lock.pid || token != lock.token {
		t.Fatalf("lock owner mismatch: got pid=%d token=%s, want pid=%d token=%s", pid, token, lock.pid, lock.token)
	}
}

func TestInspectAndAcquireRejectOversizedLock(t *testing.T) {
	base := filepath.Join(t.TempDir(), "config")
	lockPath := base + ".lock"
	file, err := createLockFileExclusive(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(bytes.Repeat([]byte{'x'}, maxLockBytes+1)); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Inspect(base); err == nil {
		t.Fatal("Inspect() error = nil, want oversized-lock rejection")
	}
	if err := New(base).Acquire(); err == nil {
		t.Fatal("Acquire() error = nil, want oversized-lock rejection")
	}
}

func TestInspectRejectsNonRegularLock(t *testing.T) {
	base := filepath.Join(t.TempDir(), "config")
	if err := os.Mkdir(base+".lock", 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Inspect(base); err == nil {
		t.Fatal("Inspect() error = nil, want non-regular-lock rejection")
	}
}

func TestEffectiveMaxRetriesDefault(t *testing.T) {
	t.Setenv("OPSKIT_LOCK_TIMEOUT", "")
	if got := effectiveMaxRetries(); got != maxRetries {
		t.Fatalf("effectiveMaxRetries() = %d, want %d", got, maxRetries)
	}
}

func TestEffectiveMaxRetriesFromEnv(t *testing.T) {
	t.Setenv("OPSKIT_LOCK_TIMEOUT", "2s")
	want := int(2 * time.Second / retryInterval)
	if got := effectiveMaxRetries(); got != want {
		t.Fatalf("effectiveMaxRetries() = %d, want %d", got, want)
	}
}

func TestEffectiveMaxRetriesInvalidEnvFallsBack(t *testing.T) {
	t.Setenv("OPSKIT_LOCK_TIMEOUT", "not-a-duration")
	if got := effectiveMaxRetries(); got != maxRetries {
		t.Fatalf("effectiveMaxRetries() = %d, want %d", got, maxRetries)
	}
}

func TestParseLockFileValid(t *testing.T) {
	data := "pid=12345\ntoken=abc123\nts=2026-01-01T00:00:00Z\n"
	pid, token, err := parseLockFile(data)
	if err != nil {
		t.Fatalf("parseLockFile() error = %v", err)
	}
	if pid != 12345 || token != "abc123" {
		t.Fatalf("pid=%d token=%s", pid, token)
	}
}

func TestParseLockFileInvalidReturnsError(t *testing.T) {
	for _, bad := range []string{"", "garbage", "pid=0\n"} {
		_, _, err := parseLockFile(bad)
		if err == nil {
			t.Fatalf("parseLockFile(%q) error = nil, want error", bad)
		}
	}
}

func TestAcquireTimeoutWhenLockHeld(t *testing.T) {
	if os.Getenv("CI") == "" {
		t.Skip("skipping timeout test outside CI (would take several seconds)")
	}
	base := filepath.Join(t.TempDir(), "config")
	holder := New(base)
	if err := holder.Acquire(); err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer func() { _ = holder.Release() }()

	// Limit retry window to 300 ms.
	t.Setenv("OPSKIT_LOCK_TIMEOUT", "300ms")
	waiter := New(base)
	err := waiter.Acquire()
	if err == nil {
		t.Fatal("Acquire() error = nil, want timeout error")
	}
}

func TestAcquireTimeoutCanUseDetailedMessage(t *testing.T) {
	base := filepath.Join(t.TempDir(), "config")
	holder := New(base)
	if err := holder.Acquire(); err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer func() { _ = holder.Release() }()

	Configure(Options{TimeoutEnvVar: "OPSKIT_LOCK_TIMEOUT", DetailedTimeoutError: true})
	t.Setenv("OPSKIT_LOCK_TIMEOUT", "1ms")
	waiter := New(base)
	err := waiter.Acquire()
	if err == nil {
		t.Fatal("Acquire() error = nil, want timeout")
	}
	want := "lock acquire: timed out after 100ms waiting for " + base + ".lock"
	if got := err.Error(); got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
	Configure(Options{TimeoutEnvVar: "OPSKIT_LOCK_TIMEOUT", DetailedTimeoutError: false})
}

func TestEffectiveMaxRetriesWarnsBelowMinimumWhenConfigured(t *testing.T) {
	var stderr bytes.Buffer
	Configure(Options{
		TimeoutEnvVar:       "TEST_LOCK_TIMEOUT",
		WarnBelowMinTimeout: true,
		Stderr:              &stderr,
	})
	t.Setenv("TEST_LOCK_TIMEOUT", "1ms")

	if got := effectiveMaxRetries(); got != 1 {
		t.Fatalf("effectiveMaxRetries() = %d, want 1", got)
	}
	if !strings.Contains(stderr.String(), "warning: TEST_LOCK_TIMEOUT below minimum 100ms; using 100ms") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	Configure(Options{TimeoutEnvVar: "OPSKIT_LOCK_TIMEOUT"})
}
