//go:build windows

package trust

import (
	"fmt"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

type testTokenOwner struct {
	owner *windows.SID
}

func TestMain(m *testing.M) {
	if err := useCurrentUserAsTestDefaultOwner(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "configure Windows test token owner: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func useCurrentUserAsTestDefaultOwner() error {
	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT,
		&token,
	); err != nil {
		return err
	}
	defer func() { _ = token.Close() }()

	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	owner := testTokenOwner{owner: user.User.Sid}
	return windows.SetTokenInformation(
		token,
		windows.TokenOwner,
		(*byte)(unsafe.Pointer(&owner)),
		uint32(unsafe.Sizeof(owner)),
	)
}
