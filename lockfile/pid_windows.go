//go:build windows

package lockfile

import (
	"errors"

	"golang.org/x/sys/windows"
)

const windowsStillActive = 259

type windowsPIDRuntime struct {
	openProcess        func(uint32) (windows.Handle, error)
	getExitCodeProcess func(windows.Handle, *uint32) error
	closeHandle        func(windows.Handle) error
}

var productionWindowsPIDRuntime = windowsPIDRuntime{
	openProcess: func(pid uint32) (windows.Handle, error) {
		return windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	},
	getExitCodeProcess: windows.GetExitCodeProcess,
	closeHandle:        windows.CloseHandle,
}

func isPidAlive(pid int) bool {
	return isPidAliveWithRuntime(pid, productionWindowsPIDRuntime)
}

func isPidAliveWithRuntime(pid int, runtime windowsPIDRuntime) bool {
	if pid <= 0 || uint64(pid) > uint64(^uint32(0)) {
		return false
	}
	handle, err := runtime.openProcess(uint32(pid))
	if err != nil {
		// OpenProcess documents ERROR_INVALID_PARAMETER for a PID that does
		// not exist. Access denied and every other failure are unknown, not
		// proof that the process is dead, so stale-lock reclaim fails closed.
		return !errors.Is(err, windows.ERROR_INVALID_PARAMETER)
	}
	defer func() { _ = runtime.closeHandle(handle) }()
	var exitCode uint32
	if err := runtime.getExitCodeProcess(handle, &exitCode); err != nil {
		return true
	}
	return exitCode == windowsStillActive
}
