//go:build !windows

package trust

import (
	"fmt"
	"os"
)

func setPinFileACL(string) error { return nil }

func verifyPinFileSecurity(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		return fmt.Errorf("mode is %#o, want 0600", mode)
	}
	return nil
}
