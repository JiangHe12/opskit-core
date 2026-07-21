package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/lockfile"
)

func TestVerifyRepairWaitsForAuditLock(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	original := writeLegacyRepairFixture(t, path)
	lock := lockfile.New(path)
	if err := lock.Acquire(); err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer func() { _ = lock.Release() }()
	t.Setenv("OPSKIT_LOCK_TIMEOUT", "100ms")

	_, err := Verify(path, VerifyOptions{Repair: true, Confirm: true})
	if err == nil || apperrors.AsAppError(err).Code != apperrors.CodeLocalIOError {
		t.Fatalf("Verify() error = %v, want lock timeout", err)
	}
	assertAuditFileEquals(t, path, original)
	assertNoRepairArtifacts(t, path)
}

func TestVerifyRepairExcludesConcurrentAppend(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	writeLegacyRepairFixture(t, path)
	runtime := productionAuditRepairRuntime
	repairHasLock := make(chan struct{})
	continueRepair := make(chan struct{})
	var paused atomic.Bool
	runtime.syncFile = func(file *os.File) error {
		if paused.CompareAndSwap(false, true) {
			close(repairHasLock)
			<-continueRepair
		}
		return file.Sync()
	}
	repairDone := make(chan error, 1)
	go func() {
		_, err := verifyWithRepairRuntime(path, VerifyOptions{Repair: true, Confirm: true}, runtime)
		repairDone <- err
	}()

	select {
	case <-repairHasLock:
	case <-time.After(5 * time.Second):
		close(continueRepair)
		t.Fatal("repair did not reach the locked staging phase")
	}
	t.Setenv("OPSKIT_LOCK_TIMEOUT", "100ms")
	appendErr := Append(path, Event{
		Timestamp: time.Date(2026, 7, 21, 1, 2, 4, 0, time.UTC),
		EventType: "resource.update",
		Operator:  "bob",
		Status:    StatusSuccess,
	})
	close(continueRepair)
	if appendErr == nil || apperrors.AsAppError(appendErr).Code != apperrors.CodeLocalIOError {
		t.Fatalf("Append() error = %v, want repair lock timeout", appendErr)
	}
	if err := <-repairDone; err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestVerifyRepairRejectsChangedTargetBeforeCommit(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	writeLegacyRepairFixture(t, path)
	replacement := []byte("replacement written by a non-cooperating writer\n")
	runtime := productionAuditRepairRuntime
	var swapped atomic.Bool
	runtime.lstat = func(candidate string) (os.FileInfo, error) {
		if candidate == path && swapped.CompareAndSwap(false, true) {
			swapPath := path + ".swap"
			if err := os.WriteFile(swapPath, replacement, 0o600); err != nil {
				return nil, err
			}
			if err := atomicReplaceFile(swapPath, path); err != nil {
				return nil, err
			}
		}
		return os.Lstat(candidate)
	}

	_, err := verifyWithRepairRuntime(path, VerifyOptions{Repair: true, Confirm: true}, runtime)
	if err == nil || apperrors.AsAppError(err).Code != apperrors.CodeConflict {
		t.Fatalf("Verify() error = %v, want target-change conflict", err)
	}
	if !swapped.Load() {
		t.Fatal("target replacement hook was not reached")
	}
	assertAuditFileEquals(t, path, replacement)
	assertNoRepairArtifacts(t, path)
}

func TestVerifyRepairFailuresLeaveOriginalIntact(t *testing.T) {
	injected := errors.New("injected repair failure")
	tests := []struct {
		name   string
		mutate func(*auditRepairRuntime)
	}{
		{
			name: "staged file sync",
			mutate: func(runtime *auditRepairRuntime) {
				runtime.syncFile = func(*os.File) error {
					return injected
				}
			},
		},
		{
			name: "rollback copy sync",
			mutate: func(runtime *auditRepairRuntime) {
				var calls atomic.Int32
				runtime.syncFile = func(file *os.File) error {
					if calls.Add(1) == 2 {
						return injected
					}
					return file.Sync()
				}
			},
		},
		{
			name: "atomic replace",
			mutate: func(runtime *auditRepairRuntime) {
				runtime.atomicReplace = func(string, string) error {
					return injected
				}
			},
		},
		{
			name: "commit directory sync",
			mutate: func(runtime *auditRepairRuntime) {
				var calls atomic.Int32
				runtime.syncParent = func(path string) error {
					if calls.Add(1) == 1 {
						return injected
					}
					return syncParentDirectory(path)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(privateTestDir(t), "audit.log")
			original := writeLegacyRepairFixture(t, path)
			runtime := productionAuditRepairRuntime
			test.mutate(&runtime)

			_, err := verifyWithRepairRuntime(path, VerifyOptions{Repair: true, Confirm: true}, runtime)
			if err == nil || !errors.Is(err, injected) {
				t.Fatalf("Verify() error = %v, want injected failure", err)
			}
			assertAuditFileEquals(t, path, original)
			assertNoRepairArtifacts(t, path)
		})
	}
}

func TestVerifyRepairStagesAndCommitsInAuditDirectory(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	writeLegacyRepairFixture(t, path)
	runtime := productionAuditRepairRuntime
	var fileSyncs atomic.Int32
	var directorySyncs atomic.Int32
	var replacements atomic.Int32
	runtime.syncFile = func(file *os.File) error {
		fileSyncs.Add(1)
		return file.Sync()
	}
	runtime.syncParent = func(path string) error {
		directorySyncs.Add(1)
		return syncParentDirectory(path)
	}
	runtime.atomicReplace = func(from, to string) error {
		if filepath.Dir(from) != filepath.Dir(to) {
			t.Fatalf("atomic replacement crossed directories: %s -> %s", from, to)
		}
		replacements.Add(1)
		return atomicReplaceFile(from, to)
	}

	result, err := verifyWithRepairRuntime(path, VerifyOptions{Repair: true, Confirm: true}, runtime)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if len(result.Files) != 1 || !result.Files[0].Repaired {
		t.Fatalf("Verify() files = %+v, want repaired file", result.Files)
	}
	if fileSyncs.Load() != 2 {
		t.Fatalf("staged file syncs = %d, want replacement plus rollback copy", fileSyncs.Load())
	}
	if directorySyncs.Load() < 1 {
		t.Fatal("repaired audit directory was not synced")
	}
	if replacements.Load() != 1 {
		t.Fatalf("atomic replacements = %d, want 1", replacements.Load())
	}
	assertNoTemporaryRepairArtifacts(t, path)
}

func writeLegacyRepairFixture(t *testing.T, path string) []byte {
	t.Helper()
	event := Event{
		Timestamp: time.Date(2026, 7, 21, 1, 2, 3, 0, time.UTC),
		EventType: "resource.create",
		Operator:  "alice",
		Status:    StatusSuccess,
	}
	valid, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	original := append(append(valid, '\n'), []byte("not json\n")...)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	return original
}

func assertAuditFileEquals(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("audit file = %q, want unchanged %q", got, want)
	}
}

func assertNoRepairArtifacts(t *testing.T, path string) {
	t.Helper()
	assertNoTemporaryRepairArtifacts(t, path)
	matches, err := filepath.Glob(path + ".quarantine.*.log")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("failed repair left quarantine artifacts: %v", matches)
	}
}

func assertNoTemporaryRepairArtifacts(t *testing.T, path string) {
	t.Helper()
	for _, pattern := range []string{
		path + ".repair-new-*",
		path + ".repair-original-*",
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 0 {
			t.Fatalf("repair left temporary artifacts: %v", matches)
		}
	}
}
