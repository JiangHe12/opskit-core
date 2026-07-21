//go:build !windows

package lockfile

import (
	"bufio"
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

const initializingLockPathEnv = "OPSKIT_LOCKFILE_INITIALIZING_PATH"

func TestActiveInitializingLockIsNotReclaimed(t *testing.T) {
	if lockPath := os.Getenv(initializingLockPathEnv); lockPath != "" {
		runInitializingLockChild(t, lockPath)
		return
	}

	base := filepath.Join(t.TempDir(), "config")
	lockPath := base + ".lock"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		os.Args[0],
		"-test.run=^TestActiveInitializingLockIsNotReclaimed$",
		"-test.count=1",
	)
	command.Env = append(os.Environ(), initializingLockPathEnv+"="+lockPath)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(stdout)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	finished := false
	t.Cleanup(func() {
		if !finished {
			_, _ = io.WriteString(stdin, "\n")
			_ = stdin.Close()
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	if got := readInitializingLockLine(t, reader); got != "INITIALIZING" {
		t.Fatalf("child readiness = %q", got)
	}
	initialInfo, err := os.Stat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	staleTime := time.Now().Add(-lockInitializationGrace - time.Second)
	if err := os.Chtimes(lockPath, staleTime, staleTime); err != nil {
		t.Fatal(err)
	}

	removed, err := New(base).reclaimIfStale(lockPath)
	if err != nil {
		t.Fatalf("reclaimIfStale() error = %v", err)
	}
	if removed {
		t.Fatal("reclaimer removed an active initializing lock")
	}
	currentInfo, err := os.Stat(lockPath)
	if err != nil {
		t.Fatalf("initializing lock disappeared: %v", err)
	}
	if !os.SameFile(initialInfo, currentInfo) {
		t.Fatal("initializing lock inode changed")
	}

	if _, err := io.WriteString(stdin, "publish\n"); err != nil {
		t.Fatal(err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if got := readInitializingLockLine(t, reader); got != "PUBLISHED" {
		t.Fatalf("child publication = %q", got)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("initializer subprocess failed: %v", err)
	}
	finished = true

	data, _, err := readLockFile(lockPath)
	if err != nil {
		t.Fatalf("readLockFile() error = %v", err)
	}
	pid, token, err := parseLockFile(string(data))
	if err != nil {
		t.Fatalf("published lock is invalid: %v", err)
	}
	if pid != command.Process.Pid || token != "initializer" {
		t.Fatalf("published lock = pid %d token %q", pid, token)
	}
	removed, err = New(base).reclaimIfStale(lockPath)
	if err != nil || !removed {
		t.Fatalf("dead initializer reclaim = (%t, %v), want removed", removed, err)
	}
}

func runInitializingLockChild(t *testing.T, lockPath string) {
	file, err := createLockFileExclusive(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if _, err := fmt.Fprintln(os.Stdout, "INITIALIZING"); err != nil {
		t.Fatal(err)
	}
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	content := fmt.Sprintf(
		"pid=%d\ntoken=initializer\nts=%s\n",
		os.Getpid(),
		time.Now().UTC().Format(time.RFC3339),
	)
	if _, err := file.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintln(os.Stdout, "PUBLISHED"); err != nil {
		t.Fatal(err)
	}
}

func readInitializingLockLine(t *testing.T, reader *bufio.Reader) string {
	t.Helper()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(line)
}
