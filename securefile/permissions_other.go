//go:build !windows

package securefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"golang.org/x/sys/unix"
)

func createOwnerOnlyDirectory(path string) error {
	return os.Mkdir(path, 0o700)
}

func validateDirectory(info os.FileInfo, path string, leaf, created bool) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return apperrors.New(
			apperrors.CodeLocalIOError,
			"secure file directory must be a real directory",
			nil,
		)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return apperrors.New(
			apperrors.CodeLocalIOError,
			"secure file directory owner is unavailable",
			nil,
		)
	}
	uid := uint64(stat.Uid)
	currentUID := uint64(os.Geteuid())
	if leaf && uid != currentUID {
		return apperrors.New(
			apperrors.CodeLocalIOError,
			fmt.Sprintf("secure file directory %s is not owned by the current user", path),
			nil,
		)
	}
	if !leaf && uid != 0 && uid != currentUID {
		return apperrors.New(
			apperrors.CodeLocalIOError,
			fmt.Sprintf("secure file ancestor %s has an untrusted owner", path),
			nil,
		)
	}
	if info.Mode().Perm()&0o022 != 0 {
		trustedStickyAncestor := !leaf &&
			info.Mode()&os.ModeSticky != 0 &&
			(uid == 0 || uid == currentUID)
		if !trustedStickyAncestor {
			return apperrors.New(
				apperrors.CodeLocalIOError,
				fmt.Sprintf("secure file directory %s is writable by group or others", path),
				nil,
			)
		}
	}
	if created && info.Mode().Perm() != 0o700 {
		return apperrors.New(
			apperrors.CodeLocalIOError,
			"new secure file directory must have mode 0700",
			nil,
		)
	}
	return nil
}

func createOwnerOnlyExclusive(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600) //nolint:gosec // Exclusive creation applies owner-only mode atomically.
}

func openOwnerOnlyFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("failed to wrap secure file descriptor")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("secure file target must be a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		_ = file.Close()
		return nil, fmt.Errorf("secure file owner is unavailable")
	}
	if uint64(stat.Uid) != uint64(os.Geteuid()) {
		_ = file.Close()
		return nil, fmt.Errorf("secure file is not owned by the current user")
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		_ = file.Close()
		return nil, fmt.Errorf("secure file has mode %#o; want 0600", mode)
	}
	return file, nil
}

func atomicReplaceFile(from, to string) error {
	return os.Rename(from, to)
}

func syncParentDirectory(path string) error {
	directory, err := os.Open(filepath.Dir(path)) //nolint:gosec // Directory is derived from the validated target.
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}

func isPathExistError(err error) bool {
	return errors.Is(err, os.ErrExist)
}
