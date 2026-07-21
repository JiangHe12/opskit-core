//go:build !windows

package lockfile

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func isLockExists(err error) bool {
	return errors.Is(err, os.ErrExist)
}

func isTransientLockBusy(_ error) bool {
	return false
}

func createLockFileExclusive(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	// The lock path is visible as soon as open(2) succeeds. Hold an advisory
	// inode lock before returning so a reclaimer cannot remove an incomplete
	// lock while its creator is paused between create, write, fsync, and close.
	// A crashed creator releases flock automatically, preserving stale recovery.
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		// Do not unlink by pathname here: another process may have removed this
		// inode and published a new lock at the same path while close ran. The
		// failed initialization remains safely reclaimable after the grace window.
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("failed to wrap lock file descriptor")
	}
	return file, nil
}

func openLockFileNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("failed to wrap lock file descriptor")
	}
	return file, nil
}

func tryLockFileForRemoval(file *os.File) (bool, error) {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return false, nil
	}
	return false, err
}

func unlockFileForRemoval(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}

func verifyLockFileHandle(_ *os.File, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("lock file owner is unavailable")
	}
	if uint64(stat.Uid) != uint64(os.Geteuid()) {
		return fmt.Errorf("lock file is not owned by the current user")
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		return fmt.Errorf("lock file mode is %#o; want 0600", mode)
	}
	return nil
}
