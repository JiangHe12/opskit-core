//go:build windows

package securefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"golang.org/x/sys/windows"
)

func createOwnerOnlyDirectory(path string) error {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes, err := ownerOnlySecurityAttributes(true)
	if err != nil {
		return err
	}
	return windows.CreateDirectory(pathPtr, attributes)
}

func validateDirectory(info os.FileInfo, path string, leaf, created bool) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return apperrors.New(
			apperrors.CodeLocalIOError,
			"secure file directory must be a real directory",
			nil,
		)
	}
	if err := rejectReparsePoint(path); err != nil {
		return err
	}
	if created {
		return verifyOwnerOnlyPath(path)
	}
	if leaf {
		if err := verifyCurrentOwner(path); err != nil {
			return err
		}
		return verifyDirectoryACL(path, false, true)
	}
	if isWindowsTrustBoundaryAncestor(path) {
		return nil
	}
	return verifyDirectoryACL(path, true, false)
}

func createOwnerOnlyExclusive(path string) (*os.File, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	attributes, err := ownerOnlySecurityAttributes(false)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pathPtr,
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
		return nil, fmt.Errorf("failed to wrap secure file handle")
	}
	return file, nil
}

func openOwnerOnlyFile(path string) (*os.File, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pathPtr,
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
	if err := verifyRegularHandle(handle); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	if err := verifyOwnerOnlyHandle(handle); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("failed to wrap secure file handle")
	}
	return file, nil
}

func verifyRegularHandle(handle windows.Handle) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return fmt.Errorf("secure file target must be a regular non-reparse file")
	}
	return nil
}

func ownerOnlySecurityAttributes(container bool) (*windows.SecurityAttributes, error) {
	userSID, systemSID, adminSID, err := trustedSIDs()
	if err != nil {
		return nil, err
	}
	flags := ""
	if container {
		flags = "OICI"
	}
	sddl := fmt.Sprintf("O:%sD:P", userSID.String())
	for _, sid := range uniqueSIDs(userSID, systemSID, adminSID) {
		sddl += fmt.Sprintf("(A;%s;FA;;;%s)", flags, sid.String())
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

func rejectReparsePoint(path string) error {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(pathPtr)
	if err != nil {
		return err
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return apperrors.New(
			apperrors.CodeLocalIOError,
			"secure file path must not be a reparse point",
			nil,
		)
	}
	return nil
}

func verifyOwnerOnlyPath(path string) error {
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	err = verifyOwnerOnlyDescriptor(descriptor)
	runtime.KeepAlive(descriptor)
	return err
}

func verifyOwnerOnlyHandle(handle windows.Handle) error {
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	err = verifyOwnerOnlyDescriptor(descriptor)
	runtime.KeepAlive(descriptor)
	return err
}

func verifyOwnerOnlyDescriptor(descriptor *windows.SECURITY_DESCRIPTOR) error {
	userSID, systemSID, adminSID, err := trustedSIDs()
	if err != nil {
		return err
	}
	if err := verifyDescriptorOwner(descriptor, userSID); err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return fmt.Errorf("secure file path has no DACL")
	}
	trusted := uniqueSIDs(userSID, systemSID, adminSID)
	if int(dacl.AceCount) != len(trusted) {
		return fmt.Errorf("secure file path must have exactly one ACE per trusted SID")
	}
	found := make([]bool, len(trusted))
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("secure file path has an unexpected ACE type")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // Windows stores the SID in the ACE tail.
		match := -1
		for trustedIndex, candidate := range trusted {
			if sid.Equals(candidate) {
				match = trustedIndex
				break
			}
		}
		if match < 0 || found[match] {
			return fmt.Errorf("secure file path has an invalid trusted ACE set")
		}
		found[match] = true
	}
	for _, present := range found {
		if !present {
			return fmt.Errorf("secure file path is missing a trusted ACE")
		}
	}
	return nil
}

func verifyCurrentOwner(path string) error {
	userSID, _, _, err := trustedSIDs()
	if err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	err = verifyDescriptorOwner(descriptor, userSID)
	runtime.KeepAlive(descriptor)
	return err
}

func verifyDescriptorOwner(descriptor *windows.SECURITY_DESCRIPTOR, userSID *windows.SID) error {
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	defer runtime.KeepAlive(descriptor)
	if owner == nil || !owner.Equals(userSID) {
		return fmt.Errorf("secure file path is not owned by the current user")
	}
	return nil
}

func verifyDirectoryACL(path string, requireTrustedOwner, leaf bool) error {
	userSID, systemSID, adminSID, err := trustedSIDs()
	if err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	defer runtime.KeepAlive(descriptor)
	if requireTrustedOwner {
		owner, _, err := descriptor.Owner()
		if err != nil {
			return err
		}
		if owner == nil ||
			(!owner.Equals(userSID) && !owner.Equals(systemSID) && !owner.Equals(adminSID)) {
			return fmt.Errorf("secure file ancestor is not owned by a trusted principal")
		}
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return fmt.Errorf("secure file directory has no DACL")
	}
	const fileDeleteChild windows.ACCESS_MASK = 0x00000040
	dangerous := windows.ACCESS_MASK(
		fileDeleteChild |
			windows.DELETE |
			windows.WRITE_DAC |
			windows.WRITE_OWNER |
			windows.GENERIC_WRITE |
			windows.GENERIC_ALL,
	)
	if leaf {
		dangerous |= windows.FILE_WRITE_DATA |
			windows.FILE_APPEND_DATA |
			windows.FILE_WRITE_EA |
			windows.FILE_WRITE_ATTRIBUTES
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return err
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE ||
			ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("secure file directory has an unsupported ACE type")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // Windows stores the SID in the ACE tail.
		if sid.Equals(userSID) || sid.Equals(systemSID) || sid.Equals(adminSID) {
			continue
		}
		if ace.Mask&dangerous != 0 {
			return fmt.Errorf(
				"secure file directory %s grants replacement rights to an untrusted SID",
				path,
			)
		}
	}
	return nil
}

func trustedSIDs() (*windows.SID, *windows.SID, *windows.SID, error) {
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

func uniqueSIDs(candidates ...*windows.SID) []*windows.SID {
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

func explicitAccess(
	sid *windows.SID,
	trusteeType windows.TRUSTEE_TYPE,
	permissions windows.ACCESS_MASK,
	inheritance uint32,
) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: permissions,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
			TrusteeForm:              windows.TRUSTEE_IS_SID,
			TrusteeType:              trusteeType,
			TrusteeValue:             windows.TrusteeValueFromSID(sid),
		},
	}
}

func isWindowsTrustBoundaryAncestor(path string) bool {
	boundaries := []string{os.TempDir()}
	if home, err := os.UserHomeDir(); err == nil {
		boundaries = append(boundaries, home)
	}
	for _, boundary := range boundaries {
		relative, err := filepath.Rel(filepath.Clean(path), filepath.Clean(boundary))
		if err != nil {
			continue
		}
		if relative == "." ||
			(relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
			return true
		}
	}
	return false
}

func atomicReplaceFile(from, to string) error {
	fromPtr, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	toPtr, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(
		fromPtr,
		toPtr,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH,
	)
}

func syncParentDirectory(string) error {
	// File.Sync plus MOVEFILE_WRITE_THROUGH is the Windows durability boundary.
	return nil
}

func isPathExistError(err error) bool {
	return errors.Is(err, os.ErrExist) ||
		errors.Is(err, windows.ERROR_FILE_EXISTS) ||
		errors.Is(err, windows.ERROR_ALREADY_EXISTS)
}
