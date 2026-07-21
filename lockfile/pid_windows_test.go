//go:build windows

package lockfile

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func TestIsPidAliveWindowsFailsClosedOnUnknownStatus(t *testing.T) {
	unknown := errors.New("unknown process query failure")
	tests := []struct {
		name     string
		pid      int
		openErr  error
		exitErr  error
		exitCode uint32
		want     bool
	}{
		{name: "invalid pid", pid: 0, want: false},
		{name: "process absent", pid: 42, openErr: windows.ERROR_INVALID_PARAMETER, want: false},
		{name: "access denied is unknown", pid: 42, openErr: windows.ERROR_ACCESS_DENIED, want: true},
		{name: "unknown open failure", pid: 42, openErr: unknown, want: true},
		{name: "exit query failure", pid: 42, exitErr: unknown, want: true},
		{name: "still active", pid: 42, exitCode: windowsStillActive, want: true},
		{name: "exited", pid: 42, exitCode: 7, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opened := false
			closed := false
			runtime := windowsPIDRuntime{
				openProcess: func(uint32) (windows.Handle, error) {
					opened = true
					if test.openErr != nil {
						return 0, test.openErr
					}
					return windows.Handle(123), nil
				},
				getExitCodeProcess: func(_ windows.Handle, code *uint32) error {
					*code = test.exitCode
					return test.exitErr
				},
				closeHandle: func(windows.Handle) error {
					closed = true
					return nil
				},
			}
			if got := isPidAliveWithRuntime(test.pid, runtime); got != test.want {
				t.Fatalf("isPidAliveWithRuntime() = %t, want %t", got, test.want)
			}
			if test.pid <= 0 {
				if opened || closed {
					t.Fatal("invalid PID reached Windows process APIs")
				}
				return
			}
			if !opened {
				t.Fatal("valid PID did not call OpenProcess")
			}
			if test.openErr == nil && !closed {
				t.Fatal("opened process handle was not closed")
			}
			if test.openErr != nil && closed {
				t.Fatal("failed OpenProcess closed a nonexistent handle")
			}
		})
	}
}
