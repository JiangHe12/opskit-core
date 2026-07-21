//go:build !windows

package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"golang.org/x/sys/unix"
)

func ensureOwnerOnlyDirectory(path string) error {
	chain, err := auditDirectoryChain(path)
	if err != nil {
		return err
	}
	for index, directory := range chain {
		info, inspectErr := os.Lstat(directory)
		wasMissing := errors.Is(inspectErr, os.ErrNotExist)
		if wasMissing {
			if err := os.Mkdir(directory, 0o700); err != nil && !isPathExistError(err) {
				return apperrors.New(apperrors.CodeLocalIOError, "failed to create audit directory", err)
			}
			info, inspectErr = os.Lstat(directory)
		}
		if inspectErr != nil {
			return apperrors.New(apperrors.CodeLocalIOError, "failed to inspect audit directory", inspectErr)
		}
		requireOwner := wasMissing || index == len(chain)-1
		if err := validateExistingAuditDirectory(info, directory, requireOwner); err != nil {
			return err
		}
		if wasMissing && info.Mode().Perm() != 0o700 {
			return apperrors.New(apperrors.CodeLocalIOError, "new audit directory must have mode 0700", nil)
		}
	}
	return nil
}

func validateAuditDirectoryChain(path string, requireLeafOwner bool) error {
	chain, err := auditDirectoryChain(path)
	if err != nil {
		return err
	}
	for index, directory := range chain {
		info, err := os.Lstat(directory)
		if err != nil {
			return apperrors.New(apperrors.CodeLocalIOError, "failed to inspect audit directory", err)
		}
		requireOwner := requireLeafOwner && index == len(chain)-1
		if err := validateExistingAuditDirectory(info, directory, requireOwner); err != nil {
			return err
		}
	}
	return nil
}

func validateExistingAuditDirectory(info os.FileInfo, path string, requireOwner bool) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return apperrors.New(apperrors.CodeLocalIOError, "audit directory must be a real directory", nil)
	}
	if requireOwner {
		if err := checkOwner(info, path); err != nil {
			return err
		}
	} else if err := checkTrustedAncestorOwner(info, path); err != nil {
		return err
	}
	if info.Mode().Perm()&0o022 != 0 {
		if requireOwner || info.Mode()&os.ModeSticky == 0 || !hasTrustedStickyOwner(info) {
			return apperrors.New(
				apperrors.CodeLocalIOError,
				fmt.Sprintf("audit directory %s is writable by group or others", path),
				nil,
			)
		}
	}
	return nil
}

func checkTrustedAncestorOwner(info os.FileInfo, path string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return apperrors.New(apperrors.CodeLocalIOError, "audit ancestor owner is unavailable", nil)
	}
	uid := uint64(stat.Uid)
	if uid != 0 && uid != uint64(os.Geteuid()) {
		return apperrors.New(
			apperrors.CodeLocalIOError,
			fmt.Sprintf("audit ancestor %s is owned by untrusted uid %d", path, stat.Uid),
			nil,
		)
	}
	return nil
}

func hasTrustedStickyOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return stat.Uid == 0 || uint64(stat.Uid) == uint64(os.Geteuid())
}

func secureOwnerOnlyFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to inspect audit file", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return apperrors.New(apperrors.CodeLocalIOError, "audit path must be a regular file", nil)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return apperrors.New(
			apperrors.CodeLocalIOError,
			"audit encryption public key owner is unavailable",
			nil,
		)
	}
	if uint64(stat.Uid) != uint64(os.Geteuid()) {
		return apperrors.New(
			apperrors.CodeLocalIOError,
			fmt.Sprintf(
				"audit encryption public key %s is owned by uid %d, not current user uid %d",
				path,
				stat.Uid,
				os.Geteuid(),
			),
			nil,
		)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to secure audit file", err)
	}
	return nil
}

func createOwnerOnlyExclusive(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600) //nolint:gosec // Exclusive creation applies owner-only mode atomically.
	if err != nil {
		return nil, err
	}
	return file, nil
}

func openAuditRecipientFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("failed to wrap audit recipient file descriptor")
	}
	return file, nil
}

func verifyAuditRecipientFile(_ *os.File, info os.FileInfo, path string) error {
	if !info.Mode().IsRegular() {
		return apperrors.New(
			apperrors.CodeLocalIOError,
			"audit encryption public key must be a regular file",
			nil,
		)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return apperrors.New(
			apperrors.CodeLocalIOError,
			"audit encryption public key owner is unavailable",
			nil,
		)
	}
	if uint64(stat.Uid) != uint64(os.Geteuid()) {
		return apperrors.New(
			apperrors.CodeLocalIOError,
			fmt.Sprintf(
				"audit encryption public key %s is owned by uid %d, not current user uid %d",
				path,
				stat.Uid,
				os.Geteuid(),
			),
			nil,
		)
	}
	if mode := info.Mode().Perm(); mode&0o022 != 0 {
		return apperrors.New(
			apperrors.CodeLocalIOError,
			fmt.Sprintf("audit encryption public key %s is writable by group or others (mode %#o)", path, mode),
			nil,
		)
	}
	return nil
}

func isPathExistError(err error) bool {
	return errors.Is(err, os.ErrExist)
}

func verifyOwnerOnlyFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return apperrors.New(apperrors.CodeLocalIOError, "audit path must be a regular file", nil)
	}
	if err := checkOwner(info, path); err != nil {
		return err
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		return apperrors.New(apperrors.CodeLocalIOError,
			fmt.Sprintf("audit file %s has insecure mode %#o; want 0600", path, mode), nil)
	}
	return nil
}

func checkOwner(info os.FileInfo, path string) error {
	uid := os.Geteuid()
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && uint64(stat.Uid) != uint64(uid) {
		return apperrors.New(apperrors.CodeLocalIOError,
			fmt.Sprintf("audit path %s is owned by uid %d, not current user uid %d", path, stat.Uid, uid), nil)
	}
	return nil
}

func atomicReplaceFile(from, to string) error {
	return os.Rename(from, to)
}

func replaceFile(from, to string) error {
	if err := atomicReplaceFile(from, to); err != nil {
		return err
	}
	return syncParentDirectory(to)
}

func syncParentDirectory(path string) error {
	dir, err := os.Open(filepath.Dir(path)) //nolint:gosec // Directory is derived from a governed audit artifact path.
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

func auditPathEqual(left, right string) bool {
	return left == right
}
