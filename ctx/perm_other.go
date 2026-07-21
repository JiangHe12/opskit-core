//go:build !windows

package ctx

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

func setOwnerOnlyACL(_ string) error    { return nil }
func verifyOwnerOnlyACL(_ string) error { return nil }

func checkFileOwner(info os.FileInfo, path string) error {
	currentUID, err := currentUserUID()
	if err != nil {
		return err
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && uint64(stat.Uid) != currentUID {
		return apperrors.New(apperrors.CodeLocalIOError,
			fmt.Sprintf("context file %s is owned by uid %d, not current user uid %d", path, stat.Uid, currentUID), nil)
	}
	return nil
}

func currentUserUID() (uint64, error) {
	current, err := user.Current()
	if err != nil {
		return 0, apperrors.New(apperrors.CodeLocalIOError, "failed to resolve current user", err)
	}
	uid, err := strconv.ParseUint(current.Uid, 10, 32)
	if err != nil {
		return 0, apperrors.New(apperrors.CodeLocalIOError, "failed to parse current user uid", err)
	}
	return uid, nil
}
