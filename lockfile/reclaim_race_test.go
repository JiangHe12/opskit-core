package lockfile

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	reclaimRaceRoleEnv = "OPSKIT_LOCKFILE_RECLAIM_RACE_ROLE"
	reclaimRaceBaseEnv = "OPSKIT_LOCKFILE_RECLAIM_RACE_BASE"
)

type reclaimRaceProcess struct {
	role   string
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr bytes.Buffer
	waited bool
}

func TestFailedInitializationCleanupDoesNotRemoveReplacementLock(t *testing.T) {
	base := filepath.Join(t.TempDir(), "config")
	lockPath := base + ".lock"
	failed, err := createLockFileExclusive(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	failedInfo, err := failed.Stat()
	if err != nil {
		_ = failed.Close()
		t.Fatal(err)
	}
	partial := []byte("pid=0\ntoken=failed")
	if _, err := failed.Write(partial); err != nil {
		_ = failed.Close()
		t.Fatal(err)
	}
	if err := failed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}

	replacement := New(base)
	if err := replacement.Acquire(); err != nil {
		t.Fatalf("replacement Acquire() error = %v", err)
	}
	defer func() { _ = replacement.Release() }()

	cleanupFailedLockFile(lockPath, failed, failedInfo, partial)
	data, _, err := readLockFile(lockPath)
	if err != nil {
		t.Fatalf("replacement lock disappeared during old cleanup: %v", err)
	}
	pid, token, err := parseLockFile(string(data))
	if err != nil {
		t.Fatalf("replacement lock is invalid: %v", err)
	}
	if pid != replacement.pid || token != replacement.token {
		t.Fatalf("replacement owner = pid %d token %q, want pid %d token %q", pid, token, replacement.pid, replacement.token)
	}

	t.Setenv("OPSKIT_LOCK_TIMEOUT", "1ms")
	if err := New(base).Acquire(); err == nil {
		t.Fatal("third contender acquired while replacement lock was held")
	}
}

func TestLockReclaimSerializesThreeProcessABA(t *testing.T) {
	if role := os.Getenv(reclaimRaceRoleEnv); role != "" {
		runReclaimRaceChild(t, role)
		return
	}

	base := filepath.Join(t.TempDir(), "config")
	lockPath := base + ".lock"
	file, err := createLockFileExclusive(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("pid=0\ntoken=stale\nts=2026-01-01T00:00:00Z\n"); err != nil {
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
	staleData, staleInfo, err := readLockFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var contenders []*reclaimRaceProcess
	t.Cleanup(func() {
		for _, contender := range contenders {
			contender.release()
			if err := contender.wait(); err != nil {
				t.Errorf("%s subprocess failed: %v\n%s", contender.role, err, contender.stderr.String())
			}
		}
	})

	removed, err := removeLockFileIfSameObserved(lockPath, staleInfo, staleData, func() {
		for _, role := range []string{"B", "C"} {
			contender := startReclaimRaceProcess(t, ctx, role, base)
			contenders = append(contenders, contender)
		}
		current, statErr := os.Stat(lockPath)
		if statErr != nil {
			t.Fatalf("stale lock path disappeared during identity-checked reclaim: %v", statErr)
		}
		if !os.SameFile(staleInfo, current) {
			t.Fatal("stale lock path changed while the reclaimer held its inode lock")
		}
	})
	if err != nil {
		t.Fatalf("removeLockFileIfSameObserved() error = %v", err)
	}
	if !removed {
		t.Fatal("removeLockFileIfSameObserved() did not remove the stale lock")
	}

	acquired := 0
	for _, contender := range contenders {
		switch result := contender.readLine(t); result {
		case "ACQUIRED":
			acquired++
		case "FAILED":
		default:
			t.Fatalf("%s result = %q", contender.role, result)
		}
	}
	if acquired != 1 {
		t.Fatalf("successful Acquire() calls = %d, want exactly one", acquired)
	}
	if _, present, err := Inspect(base); err != nil || !present {
		t.Fatalf("replacement lock before stale observer = (present=%t, err=%v)", present, err)
	}

	removed, err = removeLockFileIfSame(lockPath, staleInfo, staleData)
	if err != nil {
		t.Fatalf("stale observer removal error = %v", err)
	}
	if removed {
		t.Fatal("stale observer removed the replacement owner's lock")
	}
	if _, present, err := Inspect(base); err != nil || !present {
		t.Fatalf("replacement lock after stale observer = (present=%t, err=%v)", present, err)
	}

	for _, contender := range contenders {
		contender.release()
		if err := contender.wait(); err != nil {
			t.Fatalf("%s subprocess failed: %v\n%s", contender.role, err, contender.stderr.String())
		}
	}
}

func runReclaimRaceChild(t *testing.T, role string) {
	base := os.Getenv(reclaimRaceBaseEnv)
	if base == "" {
		t.Fatal("reclaim race base path is required")
	}
	t.Setenv("OPSKIT_LOCK_TIMEOUT", "1500ms")
	if _, err := fmt.Fprintln(os.Stdout, "START"); err != nil {
		t.Fatal(err)
	}
	lock := New(base)
	if err := lock.Acquire(); err != nil {
		_, _ = fmt.Fprintln(os.Stdout, "FAILED")
		return
	}
	if _, err := fmt.Fprintln(os.Stdout, "ACQUIRED"); err != nil {
		_ = lock.Release()
		t.Fatal(err)
	}
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	if err := lock.Release(); err != nil {
		t.Fatalf("%s Release() error = %v", role, err)
	}
}

func startReclaimRaceProcess(
	t *testing.T,
	ctx context.Context,
	role string,
	base string,
) *reclaimRaceProcess {
	t.Helper()
	process := &reclaimRaceProcess{role: role}
	process.cmd = exec.CommandContext(
		ctx,
		os.Args[0],
		"-test.run=^TestLockReclaimSerializesThreeProcessABA$",
		"-test.count=1",
	)
	process.cmd.Env = append(
		os.Environ(),
		reclaimRaceRoleEnv+"="+role,
		reclaimRaceBaseEnv+"="+base,
	)
	process.cmd.Stderr = &process.stderr
	var err error
	process.stdin, err = process.cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := process.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	process.stdout = bufio.NewReader(stdout)
	if err := process.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if ready := process.readLine(t); ready != "START" {
		t.Fatalf("%s readiness = %q", role, ready)
	}
	return process
}

func (process *reclaimRaceProcess) readLine(t *testing.T) string {
	t.Helper()
	line, err := process.stdout.ReadString('\n')
	if err != nil {
		t.Fatalf("%s output error = %v\n%s", process.role, err, process.stderr.String())
	}
	return strings.TrimSpace(line)
}

func (process *reclaimRaceProcess) release() {
	if process.stdin != nil {
		_, _ = io.WriteString(process.stdin, "\n")
		_ = process.stdin.Close()
		process.stdin = nil
	}
}

func (process *reclaimRaceProcess) wait() error {
	if process.waited {
		return nil
	}
	process.waited = true
	return process.cmd.Wait()
}
