//go:build windows

package lockfile

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func isLockExists(err error) bool {
	return errors.Is(err, os.ErrExist) ||
		errors.Is(err, windows.ERROR_FILE_EXISTS) ||
		errors.Is(err, windows.ERROR_ALREADY_EXISTS)
}

func isTransientLockBusy(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_DELETE_PENDING) ||
		errors.Is(err, windows.ERROR_ACCESS_DENIED)
}

func createLockFileExclusive(path string) (*os.File, error) {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	attributes, err := lockSecurityAttributes()
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL,
		0,
		attributes,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("failed to wrap lock file handle")
	}
	return file, nil
}

func openLockFileNoFollow(path string) (*os.File, error) {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.GENERIC_READ|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("failed to wrap lock file handle")
	}
	return file, nil
}

func tryLockFileForRemoval(file *os.File) (bool, error) {
	overlapped := windows.Overlapped{Offset: uint32(maxLockBytes + 1)}
	err := windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		&overlapped,
	)
	if err == nil || errors.Is(err, windows.Errno(0)) {
		return true, nil
	}
	const errorLockViolation windows.Errno = 0x21
	if errors.Is(err, errorLockViolation) || errors.Is(err, windows.ERROR_IO_PENDING) {
		return false, nil
	}
	return false, err
}

func unlockFileForRemoval(file *os.File) error {
	overlapped := windows.Overlapped{Offset: uint32(maxLockBytes + 1)}
	err := windows.UnlockFileEx(
		windows.Handle(file.Fd()),
		0,
		1,
		0,
		&overlapped,
	)
	if errors.Is(err, windows.Errno(0)) {
		return nil
	}
	return err
}

func verifyLockFileHandle(file *os.File, _ os.FileInfo) error {
	handle := windows.Handle(file.Fd())
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fmt.Errorf("inspect lock file handle: %w", err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return fmt.Errorf("lock file must be a regular non-reparse file")
	}
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("read lock file security: %w", err)
	}
	return verifyLockSecurityDescriptor(descriptor)
}

func lockSecurityAttributes() (*windows.SecurityAttributes, error) {
	userSID, systemSID, adminSID, err := trustedLockSIDs()
	if err != nil {
		return nil, err
	}
	sddl := fmt.Sprintf("O:%sD:P", userSID.String())
	for _, sid := range uniqueLockSIDs(userSID, systemSID, adminSID) {
		sddl += fmt.Sprintf("(A;;FA;;;%s)", sid.String())
	}
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}, nil
}

func verifyLockSecurityDescriptor(descriptor *windows.SECURITY_DESCRIPTOR) error {
	userSID, systemSID, adminSID, err := trustedLockSIDs()
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("inspect lock owner: %w", err)
	}
	if owner == nil || !owner.Equals(userSID) {
		return fmt.Errorf("lock file is not owned by the current user")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("inspect lock DACL: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("lock file has no DACL")
	}
	trusted := uniqueLockSIDs(userSID, systemSID, adminSID)
	if int(dacl.AceCount) != len(trusted) {
		return fmt.Errorf("lock file must have exactly one ACE per trusted SID")
	}
	found := make([]bool, len(trusted))
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return fmt.Errorf("inspect lock ACE: %w", err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("lock file has an unexpected ACE type")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // Windows stores the SID in the ACE tail.
		matched := -1
		for trustedIndex, trustedSID := range trusted {
			if sid.Equals(trustedSID) {
				matched = trustedIndex
				break
			}
		}
		if matched < 0 {
			return fmt.Errorf("lock file grants access to an untrusted SID")
		}
		if found[matched] {
			return fmt.Errorf("lock file has a duplicate trusted ACE")
		}
		found[matched] = true
	}
	for _, present := range found {
		if !present {
			return fmt.Errorf("lock file is missing a trusted ACE")
		}
	}
	return nil
}

func trustedLockSIDs() (*windows.SID, *windows.SID, *windows.SID, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return nil, nil, nil, err
	}
	defer func() { _ = token.Close() }()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, nil, nil, err
	}
	userSID, err := user.User.Sid.Copy()
	if err != nil {
		return nil, nil, nil, err
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, nil, nil, err
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, nil, nil, err
	}
	return userSID, systemSID, adminSID, nil
}

func uniqueLockSIDs(candidates ...*windows.SID) []*windows.SID {
	result := make([]*windows.SID, 0, len(candidates))
	for _, candidate := range candidates {
		duplicate := false
		for _, existing := range result {
			if candidate.Equals(existing) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			result = append(result, candidate)
		}
	}
	return result
}
