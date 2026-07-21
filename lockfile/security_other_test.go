//go:build !windows

package lockfile

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	lockfileSubprocessModeEnv = "OPSKIT_LOCKFILE_TEST_SUBPROCESS_MODE"
	lockfileSubprocessBaseEnv = "OPSKIT_LOCKFILE_TEST_SUBPROCESS_BASE"
)

func TestInspectRejectsSymlinkAndBroadPermissions(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		if err := os.WriteFile(target, []byte("pid=1\ntoken=x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		base := filepath.Join(dir, "config")
		if err := os.Symlink(target, base+".lock"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Inspect(base); err == nil {
			t.Fatal("Inspect() error = nil, want symlink rejection")
		}
	})

	t.Run("broad permissions", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "config")
		path := base + ".lock"
		if err := os.WriteFile(path, []byte("pid=1\ntoken=x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Inspect(base); err == nil {
			t.Fatal("Inspect() error = nil, want permission rejection")
		}
	})
}

func TestInspectRejectsDifferentOwnerWhenPrivileged(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("owner mutation requires root")
	}
	base := filepath.Join(t.TempDir(), "config")
	path := base + ".lock"
	if err := os.WriteFile(path, []byte("pid=1\ntoken=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 65534, -1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Inspect(base); err == nil {
		t.Fatal("Inspect() error = nil, want owner rejection")
	}
}

func TestAcquireDoesNotReclaimFreshInitializingLock(t *testing.T) {
	if os.Getenv(lockfileSubprocessModeEnv) == "initializing" {
		t.Setenv("OPSKIT_LOCK_TIMEOUT", "300ms")
		lock := New(os.Getenv(lockfileSubprocessBaseEnv))
		if err := lock.Acquire(); err == nil {
			_ = lock.Release()
			t.Fatal("Acquire() succeeded while the existing lock was still initializing")
		}
		return
	}

	base := filepath.Join(t.TempDir(), "config")
	lockPath := base + ".lock"
	file, err := createLockFileExclusive(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = file.Close()
		_ = os.Remove(lockPath)
	})
	before, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}

	runLockfileSubprocess(
		t,
		"TestAcquireDoesNotReclaimFreshInitializingLock",
		"initializing",
		base,
	)

	after, err := os.Stat(lockPath)
	if err != nil {
		t.Fatalf("initializing lock disappeared: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("initializing lock was replaced by a concurrent Acquire()")
	}
}

func TestLockOperationsRejectFIFOWithoutBlocking(t *testing.T) {
	if os.Getenv(lockfileSubprocessModeEnv) != "" {
		base := os.Getenv(lockfileSubprocessBaseEnv)
		var err error
		switch os.Getenv(lockfileSubprocessModeEnv) {
		case "inspect":
			_, _, err = Inspect(base)
		case "acquire":
			err = New(base).Acquire()
		case "release":
			err = New(base).Release()
		default:
			t.Fatal("unknown lockfile subprocess mode")
		}
		if err == nil {
			t.Fatalf("%s accepted a FIFO lock", os.Getenv(lockfileSubprocessModeEnv))
		}
		return
	}

	base := filepath.Join(t.TempDir(), "config")
	if err := unix.Mkfifo(base+".lock", 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"inspect", "acquire", "release"} {
		t.Run(mode, func(t *testing.T) {
			runLockfileSubprocess(t, "TestLockOperationsRejectFIFOWithoutBlocking", mode, base)
		})
	}
}

func runLockfileSubprocess(t *testing.T, testName, mode, base string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+testName+"$", "-test.count=1")
	command.Env = append(
		os.Environ(),
		lockfileSubprocessModeEnv+"="+mode,
		lockfileSubprocessBaseEnv+"="+base,
	)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("%s subprocess blocked: %v\n%s", mode, ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("%s subprocess failed: %v\n%s", mode, err, output)
	}
}
