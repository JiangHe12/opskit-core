package audit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/v2/lockfile"
)

var errAppendResultFault = errors.New("injected append result fault")

func TestAppendRecordWithResultSuccessAndPreCommitFailure(t *testing.T) {
	t.Run("committed", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "audit.log")
		result, err := AppendRecordWithResult(path, appendResultEvent("committed"), Options{})
		if err != nil {
			t.Fatal(err)
		}
		if result.State != AppendCommitCommitted || !result.IsCommitted() {
			t.Fatalf("result = %+v, want committed", result)
		}
	})

	t.Run("not committed before write", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "audit.log")
		result, err := AppendRecordWithResult(path, make(chan int), Options{})
		if err == nil {
			t.Fatal("AppendRecordWithResult() error = nil")
		}
		if result.State != AppendCommitNotCommitted || result.IsCommitted() {
			t.Fatalf("result = %+v, want not committed", result)
		}
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatalf("active audit log exists after pre-write failure: %v", statErr)
		}
	})
}

func TestAppendRecordWriteFailuresRollbackUnderLock(t *testing.T) {
	for _, test := range []struct {
		name  string
		write func(*os.File, []byte) (int, error)
	}{
		{
			name: "partial write with error",
			write: func(file *os.File, data []byte) (int, error) {
				written, _ := file.Write(data[:len(data)/2])
				return written, errAppendResultFault
			},
		},
		{
			name: "short write without error",
			write: func(file *os.File, data []byte) (int, error) {
				return file.Write(data[:len(data)/2])
			},
		},
		{
			name: "full write with error",
			write: func(file *os.File, data []byte) (int, error) {
				written, _ := file.Write(data)
				return written, errAppendResultFault
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(privateTestDir(t), "audit.log")
			if err := Append(path, appendResultEvent("seed")); err != nil {
				t.Fatal(err)
			}
			original := bytes.TrimSuffix(mustReadFile(t, path), []byte{'\n'})
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
			runtime := productionAppendRecordRuntime
			runtime.writeFile = test.write

			result, err := appendRecordWithResult(
				path,
				appendResultEvent("rolled-back"),
				Options{},
				runtime,
			)
			if err == nil {
				t.Fatal("appendRecordWithResult() error = nil")
			}
			if result.State != AppendCommitNotCommitted || result.IsCommitted() {
				t.Fatalf("result = %+v, want not committed", result)
			}
			if got := mustReadFile(t, path); !bytes.Equal(got, original) {
				t.Fatalf("rollback changed original bytes:\ngot  %q\nwant %q", got, original)
			}
			verified, verifyErr := Verify(path, VerifyOptions{})
			if verifyErr != nil || verified.HasProblems() || verified.Total != 1 {
				t.Fatalf("Verify() after rollback = (%+v, %v)", verified, verifyErr)
			}
		})
	}
}

func TestAppendRecordRollbackFailureIsIndeterminate(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*appendRecordRuntime)
	}{
		{
			name: "truncate failure",
			mutate: func(runtime *appendRecordRuntime) {
				runtime.writeFile = func(file *os.File, data []byte) (int, error) {
					written, _ := file.Write(data[:len(data)/2])
					return written, errAppendResultFault
				}
				runtime.truncateFile = func(*os.File, int64) error {
					return errAppendResultFault
				}
			},
		},
		{
			name: "rollback sync failure",
			mutate: func(runtime *appendRecordRuntime) {
				runtime.syncFile = func(*os.File) error {
					return errAppendResultFault
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(privateTestDir(t), "audit.log")
			if err := Append(path, appendResultEvent("seed")); err != nil {
				t.Fatal(err)
			}
			runtime := productionAppendRecordRuntime
			test.mutate(&runtime)
			result, err := appendRecordWithResult(
				path,
				appendResultEvent("indeterminate"),
				Options{},
				runtime,
			)
			if err == nil {
				t.Fatal("appendRecordWithResult() error = nil")
			}
			if result.State != AppendCommitIndeterminate || result.IsCommitted() {
				t.Fatalf("result = %+v, want indeterminate", result)
			}
		})
	}
}

func TestAppendRecordSyncFailureCanRollbackDurably(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	if err := Append(path, appendResultEvent("seed")); err != nil {
		t.Fatal(err)
	}
	original := mustReadFile(t, path)
	runtime := productionAppendRecordRuntime
	var syncCalls atomic.Int32
	runtime.syncFile = func(file *os.File) error {
		if syncCalls.Add(1) == 1 {
			return errAppendResultFault
		}
		return file.Sync()
	}

	result, err := appendRecordWithResult(
		path,
		appendResultEvent("rolled-back"),
		Options{},
		runtime,
	)
	if err == nil {
		t.Fatal("appendRecordWithResult() error = nil")
	}
	if result.State != AppendCommitNotCommitted {
		t.Fatalf("result = %+v, want not committed", result)
	}
	if syncCalls.Load() != 2 {
		t.Fatalf("sync calls = %d, want commit attempt plus rollback sync", syncCalls.Load())
	}
	if got := mustReadFile(t, path); !bytes.Equal(got, original) {
		t.Fatal("sync-failure rollback did not restore the original audit bytes")
	}
}

func TestAppendRecordPostCommitFailuresAreReported(t *testing.T) {
	t.Run("checkpoint", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "audit.log")
		if err := Append(path, appendResultEvent("seed")); err != nil {
			t.Fatal(err)
		}
		runtime := productionAppendRecordRuntime
		runtime.writeCheckpoint = func(string, auditCheckpoint) error {
			return errAppendResultFault
		}
		result, err := appendRecordWithResult(
			path,
			appendResultEvent("checkpoint-failed"),
			Options{},
			runtime,
		)
		if err == nil {
			t.Fatal("appendRecordWithResult() error = nil")
		}
		if result.State != AppendCommitCommittedPostCommitError || !result.IsCommitted() {
			t.Fatalf("result = %+v, want committed post-commit error", result)
		}

		if err := Append(path, appendResultEvent("reconciled")); err != nil {
			t.Fatalf("Append() did not reconcile the lagging checkpoint: %v", err)
		}
		verified, verifyErr := Verify(path, VerifyOptions{})
		if verifyErr != nil || verified.HasProblems() || verified.Total != 3 {
			t.Fatalf("Verify() after checkpoint recovery = (%+v, %v)", verified, verifyErr)
		}
	})

	t.Run("existing file close", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "audit.log")
		if err := Append(path, appendResultEvent("seed")); err != nil {
			t.Fatal(err)
		}
		runtime := productionAppendRecordRuntime
		runtime.closeFile = func(file *os.File) error {
			_ = file.Close()
			return errAppendResultFault
		}
		result, err := appendRecordWithResult(
			path,
			appendResultEvent("close-failed"),
			Options{},
			runtime,
		)
		if err == nil {
			t.Fatal("appendRecordWithResult() error = nil")
		}
		if result.State != AppendCommitCommittedPostCommitError || !result.IsCommitted() {
			t.Fatalf("result = %+v, want committed post-commit error", result)
		}
	})

	t.Run("lock release", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "audit.log")
		runtime := productionAppendRecordRuntime
		runtime.releaseLock = func(lock *lockfile.Lock) error {
			_ = lock.Release()
			return errAppendResultFault
		}
		result, err := appendRecordWithResult(
			path,
			appendResultEvent("release-failed"),
			Options{},
			runtime,
		)
		if err == nil {
			t.Fatal("appendRecordWithResult() error = nil")
		}
		if result.State != AppendCommitCommittedPostCommitError || !result.IsCommitted() {
			t.Fatalf("result = %+v, want committed post-commit error", result)
		}
	})
}

func TestAppendRecordNewFileDurabilityFailuresAreIndeterminate(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*appendRecordRuntime)
	}{
		{
			name: "close before directory sync",
			mutate: func(runtime *appendRecordRuntime) {
				runtime.closeFile = func(file *os.File) error {
					_ = file.Close()
					return errAppendResultFault
				}
			},
		},
		{
			name: "directory sync",
			mutate: func(runtime *appendRecordRuntime) {
				runtime.syncParent = func(string) error {
					return errAppendResultFault
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(privateTestDir(t), "audit.log")
			runtime := productionAppendRecordRuntime
			test.mutate(&runtime)
			result, err := appendRecordWithResult(
				path,
				appendResultEvent("new-file"),
				Options{},
				runtime,
			)
			if err == nil {
				t.Fatal("appendRecordWithResult() error = nil")
			}
			if result.State != AppendCommitIndeterminate || result.IsCommitted() {
				t.Fatalf("result = %+v, want indeterminate", result)
			}
		})
	}
}

func TestAppendRecordRollbackKeepsAuditLockHeld(t *testing.T) {
	t.Setenv("OPSKIT_LOCK_TIMEOUT", "10s")
	path := filepath.Join(privateTestDir(t), "audit.log")
	if err := Append(path, appendResultEvent("seed")); err != nil {
		t.Fatal(err)
	}
	writeStarted := make(chan struct{})
	allowWriteFailure := make(chan struct{})
	firstDone := make(chan struct{})
	var firstResult AppendResult
	var firstErr error
	runtime := productionAppendRecordRuntime
	runtime.writeFile = func(file *os.File, data []byte) (int, error) {
		written, _ := file.Write(data[:len(data)/2])
		close(writeStarted)
		<-allowWriteFailure
		return written, errAppendResultFault
	}
	go func() {
		defer close(firstDone)
		firstResult, firstErr = appendRecordWithResult(
			path,
			appendResultEvent("rolled-back"),
			Options{},
			runtime,
		)
	}()
	<-writeStarted

	secondDone := make(chan error, 1)
	go func() {
		secondDone <- Append(path, appendResultEvent("second"))
	}()
	select {
	case err := <-secondDone:
		t.Fatalf("concurrent append completed before rollback: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(allowWriteFailure)
	<-firstDone
	if firstErr == nil || firstResult.State != AppendCommitNotCommitted {
		t.Fatalf("first append = (%+v, %v), want rolled-back failure", firstResult, firstErr)
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(path, VerifyOptions{})
	if err != nil || verified.HasProblems() || verified.Total != 2 {
		t.Fatalf("Verify() after serialized rollback = (%+v, %v)", verified, err)
	}
}

func appendResultEvent(operator string) Event {
	return Event{
		Timestamp: time.Date(2026, 7, 20, 1, 2, 3, 0, time.UTC),
		EventType: "resource.update",
		Operator:  operator,
		Status:    StatusSuccess,
	}
}
