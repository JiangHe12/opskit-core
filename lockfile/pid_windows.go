//go:build windows

package lockfile

import "golang.org/x/sys/windows"

func isPidAlive(pid int) bool {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, uint32(pid)) //nolint:gosec // Windows API takes uint32.
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	var exitCode uint32
	if err := windows.GetExitCodeProcess(handle, &exitCode); err != nil {
		return false
	}
	return exitCode == 259
}
