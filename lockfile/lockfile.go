// Package lockfile provides owner-token based local file locking.
package lockfile

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

const (
	maxRetries    = 60
	retryInterval = 100 * time.Millisecond
	maxLockBytes  = 4 * 1024

	inspectBusyRetries = 3
	inspectBusyDelay   = 10 * time.Millisecond

	lockInitializationGrace = 2 * time.Second
)

// Options configures lock acquisition behavior.
type Options struct {
	TimeoutEnvVar        string
	DetailedTimeoutError bool
	WarnBelowMinTimeout  bool
	Stderr               io.Writer
}

var options = Options{TimeoutEnvVar: "OPSKIT_LOCK_TIMEOUT"}

var errLockRemovalBusy = errors.New("lock file removal is busy")

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
		} else if isTransientLockBusy(err) {
			time.Sleep(retryInterval)
			continue
		} else if !isLockExists(err) {
			return fmt.Errorf("lock acquire: %w", err)
		}
		reclaimed, reclaimErr := l.reclaimIfStale(lockPath)
		if reclaimErr != nil {
			return fmt.Errorf("lock acquire: %w", reclaimErr)
		}
		if reclaimed {
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
	for attempt := range inspectBusyRetries {
		data, info, err := readLockFile(lockPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		pid, token, err := parseLockFile(string(data))
		if err != nil || pid != l.pid || token != l.token {
			return nil //nolint:nilerr // A replaced or corrupted lock is no longer owned by this instance.
		}
		removed, err := removeLockFileIfSame(lockPath, info, data)
		if errors.Is(err, errLockRemovalBusy) {
			if attempt < inspectBusyRetries-1 {
				time.Sleep(inspectBusyDelay)
				continue
			}
			return err
		}
		if err != nil {
			return err
		}
		if removed {
			return nil
		}
		return nil
	}
	return errLockRemovalBusy
}

func (l *Lock) tryAcquire(lockPath string) error {
	file, err := createLockFileExclusive(lockPath)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	if err := verifyLockFileHandle(file, info); err != nil {
		cleanupFailedLockFile(lockPath, file, info, nil)
		return err
	}
	content := fmt.Sprintf("pid=%d\ntoken=%s\nts=%s\n", l.pid, l.token, time.Now().UTC().Format(time.RFC3339))
	written, writeErr := file.WriteString(content)
	if writeErr != nil || written != len(content) {
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		if written >= 0 && written <= len(content) {
			cleanupFailedLockFile(lockPath, file, info, []byte(content[:written]))
		} else {
			_ = file.Close()
		}
		return writeErr
	}
	if err := file.Sync(); err != nil {
		cleanupFailedLockFile(lockPath, file, info, []byte(content))
		return err
	}
	if err := file.Close(); err != nil {
		cleanupFailedLockFile(lockPath, file, info, []byte(content))
		return err
	}
	return nil
}

func cleanupFailedLockFile(path string, file *os.File, expected os.FileInfo, expectedData []byte) {
	_ = file.Close()
	// Closing the failed initializer lets another contender reclaim the path.
	// Never unlink by pathname afterward: remove only if the path still names
	// both the file identity and exact partial content created by this initializer.
	_, _ = removeLockFileIfSame(path, expected, expectedData)
}

func (l *Lock) reclaimIfStale(lockPath string) (bool, error) {
	data, info, err := readLockFile(lockPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		if isTransientLockBusy(err) {
			return false, nil
		}
		return false, err
	}
	pid, _, err := parseLockFile(string(data))
	if err != nil && time.Since(info.ModTime()) < lockInitializationGrace {
		return false, nil
	}
	if err == nil && isPidAlive(pid) {
		return false, nil
	}
	removed, err := removeLockFileIfSame(lockPath, info, data)
	if errors.Is(err, errLockRemovalBusy) {
		return false, nil
	}
	if isTransientLockBusy(err) {
		return false, nil
	}
	return removed, err
}

// Inspect returns the bounded, validated content of the lock associated with
// basePath. A present lock that is a link, non-regular file, owned by another
// account, broadly writable, or oversized is rejected.
func Inspect(basePath string) (string, bool, error) {
	var (
		data []byte
		err  error
	)
	for attempt := range inspectBusyRetries {
		data, _, err = readLockFile(basePath + ".lock")
		if !isTransientLockBusy(err) || attempt == inspectBusyRetries-1 {
			break
		}
		time.Sleep(inspectBusyDelay)
	}
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return strings.TrimSpace(string(data)), true, nil
}

func readLockFile(path string) ([]byte, os.FileInfo, error) {
	file, err := openLockFileNoFollow(path)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	data, err := readLockFileHandle(file, info)
	if err != nil {
		return nil, nil, err
	}
	return data, info, nil
}

func readLockFileHandle(file *os.File, info os.FileInfo) ([]byte, error) {
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("lock file must be regular")
	}
	if info.Size() > maxLockBytes {
		return nil, fmt.Errorf("lock file exceeds %d bytes", maxLockBytes)
	}
	if err := verifyLockFileHandle(file, info); err != nil {
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxLockBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxLockBytes {
		return nil, fmt.Errorf("lock file exceeds %d bytes", maxLockBytes)
	}
	return data, nil
}

func removeLockFileIfSame(path string, expected os.FileInfo, expectedData []byte) (bool, error) {
	return removeLockFileIfSameObserved(path, expected, expectedData, nil)
}

func removeLockFileIfSameObserved(
	path string,
	expected os.FileInfo,
	expectedData []byte,
	afterIdentityCheck func(),
) (removed bool, retErr error) {
	file, err := openLockFileNoFollow(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return false, err
	}
	defer func() {
		if err := file.Close(); retErr == nil && err != nil {
			retErr = fmt.Errorf("close reclaimed lock file: %w", err)
		}
	}()

	locked, err := tryLockFileForRemoval(file)
	if err != nil {
		return false, err
	}
	if !locked {
		return false, errLockRemovalBusy
	}
	defer func() {
		if err := unlockFileForRemoval(file); retErr == nil && err != nil {
			retErr = fmt.Errorf("unlock reclaimed lock file: %w", err)
		}
	}()

	opened, err := file.Stat()
	if err != nil {
		return false, err
	}
	if !opened.Mode().IsRegular() {
		return false, fmt.Errorf("lock file must be regular")
	}
	if err := verifyLockFileHandle(file, opened); err != nil {
		return false, err
	}
	openedData, err := readLockFileHandle(file, opened)
	if err != nil {
		return false, err
	}
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if current.Mode()&os.ModeSymlink != 0 ||
		!current.Mode().IsRegular() ||
		!os.SameFile(opened, current) ||
		!os.SameFile(expected, opened) ||
		!bytes.Equal(expectedData, openedData) {
		return false, nil
	}
	if afterIdentityCheck != nil {
		afterIdentityCheck()
		current, err = os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		if current.Mode()&os.ModeSymlink != 0 ||
			!current.Mode().IsRegular() ||
			!os.SameFile(opened, current) {
			return false, nil
		}
		openedData, err = readLockFileHandle(file, opened)
		if err != nil {
			return false, err
		}
		if !bytes.Equal(expectedData, openedData) {
			return false, nil
		}
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return false, err
	}
	return true, nil
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
