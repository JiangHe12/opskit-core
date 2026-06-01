// Package lockfile provides owner-token based local file locking.
package lockfile

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/JiangHe12/opskit-core/apperrors"
)

const (
	maxRetries    = 60
	retryInterval = 100 * time.Millisecond
)

// Options configures lock acquisition behavior.
type Options struct {
	TimeoutEnvVar        string
	DetailedTimeoutError bool
	WarnBelowMinTimeout  bool
	Stderr               io.Writer
}

var options = Options{TimeoutEnvVar: "OPSKIT_LOCK_TIMEOUT"}

// Configure sets package-level defaults for locks created by New.
func Configure(next Options) {
	if next.TimeoutEnvVar != "" {
		options.TimeoutEnvVar = next.TimeoutEnvVar
	}
	options.DetailedTimeoutError = next.DetailedTimeoutError
	options.WarnBelowMinTimeout = next.WarnBelowMinTimeout
	options.Stderr = next.Stderr
}

// Lock provides owner-token based file locking.
type Lock struct {
	path  string
	pid   int
	token string
}

// New creates a Lock for the given base path.
func New(path string) *Lock {
	tokenBytes := make([]byte, 8)
	_, _ = rand.Read(tokenBytes)
	return &Lock{path: path, pid: os.Getpid(), token: hex.EncodeToString(tokenBytes)}
}

// Acquire attempts to acquire the lock.
func (l *Lock) Acquire() error {
	lockPath := l.path + ".lock"
	retries := effectiveMaxRetries()
	timeout := time.Duration(retries) * retryInterval
	for i := 0; i < retries; i++ {
		if err := l.tryAcquire(lockPath); err == nil {
			return nil
		} else if !os.IsExist(err) {
			return fmt.Errorf("lock acquire: %w", err)
		}
		if l.reclaimIfStale(lockPath) {
			continue
		}
		time.Sleep(retryInterval)
	}
	if options.DetailedTimeoutError {
		return apperrors.New(apperrors.CodeLocalIOError, fmt.Sprintf("lock acquire: timed out after %s waiting for %s", timeout, lockPath), nil)
	}
	return apperrors.New(apperrors.CodeLocalIOError, fmt.Sprintf("lock acquire timed out for %s", lockPath), nil)
}

// Release removes the lock only if this process still owns it.
func (l *Lock) Release() error {
	lockPath := l.path + ".lock"
	data, err := os.ReadFile(lockPath) //nolint:gosec // lockPath is derived from caller-provided base path.
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	pid, token, err := parseLockFile(string(data))
	if err != nil || pid != l.pid || token != l.token {
		return nil //nolint:nilerr // A replaced or corrupted lock is no longer owned by this instance.
	}
	return os.Remove(lockPath)
}

func (l *Lock) tryAcquire(lockPath string) error {
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // lockPath is derived from caller-provided base path.
	if err != nil {
		return err
	}
	content := fmt.Sprintf("pid=%d\ntoken=%s\nts=%s\n", l.pid, l.token, time.Now().UTC().Format(time.RFC3339))
	if _, err := file.WriteString(content); err != nil {
		_ = file.Close()
		_ = os.Remove(lockPath)
		return err
	}
	return file.Close()
}

func (l *Lock) reclaimIfStale(lockPath string) bool {
	data, err := os.ReadFile(lockPath) //nolint:gosec // lockPath is derived from caller-provided base path.
	if err != nil {
		return os.IsNotExist(err)
	}
	pid, _, err := parseLockFile(string(data))
	if err == nil && isPidAlive(pid) {
		return false
	}
	tombstone := lockPath + ".stale." + l.token
	if err := os.Rename(lockPath, tombstone); err != nil {
		return os.IsNotExist(err)
	}
	_ = os.Remove(tombstone)
	return true
}

func parseLockFile(data string) (int, string, error) {
	var pid int
	var token string
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "pid":
			pid, _ = strconv.Atoi(parts[1])
		case "token":
			token = parts[1]
		}
	}
	if pid == 0 || token == "" {
		return 0, "", fmt.Errorf("invalid lock file")
	}
	return pid, token, nil
}

func effectiveMaxRetries() int {
	if options.TimeoutEnvVar != "" {
		if value := os.Getenv(options.TimeoutEnvVar); value != "" {
			duration, err := time.ParseDuration(value)
			if err == nil && duration > 0 {
				if duration < retryInterval && options.WarnBelowMinTimeout {
					_, _ = fmt.Fprintf(stderr(), "warning: %s below minimum %s; using %s\n", options.TimeoutEnvVar, retryInterval, retryInterval)
				}
				retries := int(duration / retryInterval)
				if retries < 1 {
					return 1
				}
				return retries
			}
		}
	}
	return maxRetries
}

func stderr() io.Writer {
	if options.Stderr != nil {
		return options.Stderr
	}
	return os.Stderr
}
