//go:build windows

package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"golang.org/x/sys/windows"
)

func ensureOwnerOnlyDirectory(path string) error {
	chain, err := auditDirectoryChain(path)
	if err != nil {
		return err
	}
	for index, directory := range chain {
		info, inspectErr := os.Lstat(directory)
		wasMissing := os.IsNotExist(inspectErr)
		if wasMissing {
			if err := createOwnerOnlyDirectory(directory); err != nil && !isPathExistError(err) {
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
		if wasMissing {
			if err := verifyOwnerOnlyACL(directory); err != nil {
				return err
			}
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
	if err := rejectReparsePoint(path); err != nil {
		return err
	}
	if requireOwner {
		if err := verifyCurrentOwner(path); err != nil {
			return err
		}
		return verifyExistingDirectoryACL(path)
	}
	return verifyAncestorDirectoryACL(path)
}

func createOwnerOnlyDirectory(path string) error {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes, err := ownerOnlySecurityAttributes(true)
	if err != nil {
		return err
	}
	return windows.CreateDirectory(ptr, attributes)
}

func createOwnerOnlyExclusive(path string) (*os.File, error) {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	attributes, err := ownerOnlySecurityAttributes(false)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
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
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to wrap audit file handle", nil)
	}
	return file, nil
}

func openAuditRecipientFile(path string) (*os.File, error) {
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
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("audit encryption public key must be a regular file")
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("failed to wrap audit recipient file handle")
	}
	return file, nil
}

func verifyAuditRecipientFile(file *os.File, _ os.FileInfo, _ string) error {
	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return apperrors.New(
			apperrors.CodeLocalIOError,
			"failed to read audit encryption public key security",
			err,
		)
	}
	userSID, systemSID, adminSID, err := trustedAuditSIDs()
	if err != nil {
		return err
	}
	if err := verifyDescriptorOwner(descriptor, userSID); err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return apperrors.New(
			apperrors.CodeLocalIOError,
			"failed to inspect audit encryption public key DACL",
			err,
		)
	}
	if dacl == nil {
		return apperrors.New(
			apperrors.CodeLocalIOError,
			"audit encryption public key has no DACL",
			nil,
		)
	}
	trusted := uniqueAuditSIDs(userSID, systemSID, adminSID)
	dangerous := windows.ACCESS_MASK(
		windows.FILE_WRITE_DATA |
			windows.FILE_APPEND_DATA |
			windows.FILE_WRITE_EA |
			windows.FILE_WRITE_ATTRIBUTES |
			windows.DELETE |
			windows.WRITE_DAC |
			windows.WRITE_OWNER |
			windows.GENERIC_WRITE |
			windows.GENERIC_ALL,
	)
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return apperrors.New(
				apperrors.CodeLocalIOError,
				"failed to inspect audit encryption public key ACE",
				err,
			)
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE ||
			ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return apperrors.New(
				apperrors.CodeLocalIOError,
				"audit encryption public key has an unsupported ACE type",
				nil,
			)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // Windows stores the SID in the ACE tail.
		trustedSID := false
		for _, candidate := range trusted {
			if sid.Equals(candidate) {
				trustedSID = true
				break
			}
		}
		if !trustedSID && ace.Mask&dangerous != 0 {
			return apperrors.New(
				apperrors.CodeLocalIOError,
				"audit encryption public key grants write access to an untrusted SID",
				nil,
			)
		}
	}
	return nil
}

func isPathExistError(err error) bool {
	return errors.Is(err, os.ErrExist) ||
		errors.Is(err, windows.ERROR_FILE_EXISTS) ||
		errors.Is(err, windows.ERROR_ALREADY_EXISTS)
}

func ownerOnlySecurityAttributes(container bool) (*windows.SecurityAttributes, error) {
	userSID, systemSID, adminSID, err := trustedAuditSIDs()
	if err != nil {
		return nil, err
	}
	flags := ""
	if container {
		flags = "OICI"
	}
	sddl := fmt.Sprintf("O:%sD:P", userSID.String())
	for _, sid := range uniqueAuditSIDs(userSID, systemSID, adminSID) {
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

func secureOwnerOnlyFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to inspect audit file", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return apperrors.New(apperrors.CodeLocalIOError, "audit path must be a regular file", nil)
	}
	if err := rejectReparsePoint(path); err != nil {
		return err
	}
	if err := setOwnerOnlyACL(path, windows.NO_INHERITANCE); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to secure audit file", err)
	}
	return verifyOwnerOnlyACL(path)
}

func verifyOwnerOnlyFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return apperrors.New(apperrors.CodeLocalIOError, "audit path must be a regular file", nil)
	}
	if err := rejectReparsePoint(path); err != nil {
		return err
	}
	return verifyOwnerOnlyACL(path)
}

func rejectReparsePoint(path string) error {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to encode audit path", err)
	}
	attrs, err := windows.GetFileAttributes(ptr)
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to inspect audit path attributes", err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return apperrors.New(apperrors.CodeLocalIOError, "audit path must not be a reparse point", nil)
	}
	return nil
}

func setOwnerOnlyACL(path string, inheritance uint32) error {
	userSID, systemSID, adminSID, err := trustedAuditSIDs()
	if err != nil {
		return err
	}
	fullControl := windows.ACCESS_MASK(
		windows.STANDARD_RIGHTS_ALL |
			windows.FILE_GENERIC_READ |
			windows.FILE_GENERIC_WRITE |
			windows.FILE_GENERIC_EXECUTE |
			windows.DELETE,
	)
	trusted := uniqueAuditSIDs(userSID, systemSID, adminSID)
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(trusted))
	for _, sid := range trusted {
		trusteeType := windows.TRUSTEE_TYPE(windows.TRUSTEE_IS_GROUP)
		if sid.Equals(userSID) {
			trusteeType = windows.TRUSTEE_IS_USER
		} else if sid.Equals(systemSID) {
			trusteeType = windows.TRUSTEE_IS_WELL_KNOWN_GROUP
		}
		entries = append(entries, auditExplicitAccess(sid, trusteeType, fullControl, inheritance))
	}
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("create DACL: %w", err)
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)
}

func verifyOwnerOnlyACL(path string) error {
	userSID, systemSID, adminSID, err := trustedAuditSIDs()
	if err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to read audit path DACL", err)
	}
	if err := verifyDescriptorOwner(descriptor, userSID); err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to inspect audit path DACL", err)
	}
	if dacl == nil {
		return apperrors.New(apperrors.CodeLocalIOError, "audit path has no DACL", nil)
	}
	trusted := uniqueAuditSIDs(userSID, systemSID, adminSID)
	if int(dacl.AceCount) != len(trusted) {
		return apperrors.New(apperrors.CodeLocalIOError, "audit path must have exactly one ACE per trusted SID", nil)
	}
	found := make([]bool, len(trusted))
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return apperrors.New(apperrors.CodeLocalIOError, "failed to inspect audit path ACE", err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return apperrors.New(apperrors.CodeLocalIOError, "audit path has an unexpected ACE type", nil)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // Windows stores the SID in the ACE tail.
		matched := -1
		for index, trustedSID := range trusted {
			if sid.Equals(trustedSID) {
				matched = index
				break
			}
		}
		if matched < 0 {
			return apperrors.New(apperrors.CodeLocalIOError, "audit path grants access to an untrusted SID", nil)
		}
		if found[matched] {
			return apperrors.New(apperrors.CodeLocalIOError, "audit path has a duplicate trusted ACE", nil)
		}
		found[matched] = true
	}
	for _, present := range found {
		if !present {
			return apperrors.New(apperrors.CodeLocalIOError, "audit path is missing a trusted ACE", nil)
		}
	}
	return nil
}

func verifyCurrentOwner(path string) error {
	userSID, _, _, err := trustedAuditSIDs()
	if err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to read audit path owner", err)
	}
	return verifyDescriptorOwner(descriptor, userSID)
}

func verifyExistingDirectoryACL(path string) error {
	userSID, systemSID, adminSID, err := trustedAuditSIDs()
	if err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to read audit directory DACL", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to inspect audit directory DACL", err)
	}
	if dacl == nil {
		return apperrors.New(apperrors.CodeLocalIOError, "audit directory has no DACL", nil)
	}
	const fileDeleteChild windows.ACCESS_MASK = 0x00000040
	dangerous := windows.ACCESS_MASK(
		windows.FILE_WRITE_DATA |
			windows.FILE_APPEND_DATA |
			windows.FILE_WRITE_EA |
			windows.FILE_WRITE_ATTRIBUTES |
			fileDeleteChild |
			windows.DELETE |
			windows.WRITE_DAC |
			windows.WRITE_OWNER |
			windows.GENERIC_WRITE |
			windows.GENERIC_ALL,
	)
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return apperrors.New(apperrors.CodeLocalIOError, "failed to inspect audit directory ACE", err)
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE ||
			ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return apperrors.New(apperrors.CodeLocalIOError, "audit directory has an unsupported ACE type", nil)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // Windows stores the SID in the ACE tail.
		if sid.Equals(userSID) || sid.Equals(systemSID) || sid.Equals(adminSID) {
			continue
		}
		if ace.Mask&dangerous != 0 {
			return apperrors.New(
				apperrors.CodeLocalIOError,
				"audit directory grants write or replacement rights to an untrusted SID",
				nil,
			)
		}
	}
	return nil
}

func verifyAncestorDirectoryACL(path string) error {
	userSID, systemSID, adminSID, err := trustedAuditSIDs()
	if err != nil {
		return err
	}
	// The account's profile and OS temp root are documented local-account trust
	// boundaries. Every component below them is still checked, so a writable
	// intermediate directory cannot replace audit artifacts.
	if isWindowsTrustBoundaryAncestor(path) {
		return nil
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to read audit ancestor DACL", err)
	}
	if err := verifyTrustedAncestorOwner(descriptor, userSID, systemSID, adminSID, path); err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to inspect audit ancestor DACL", err)
	}
	if dacl == nil {
		return apperrors.New(apperrors.CodeLocalIOError, "audit ancestor has no DACL", nil)
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
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return apperrors.New(apperrors.CodeLocalIOError, "failed to inspect audit ancestor ACE", err)
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE ||
			ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return apperrors.New(apperrors.CodeLocalIOError, "audit ancestor has an unsupported ACE type", nil)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // Windows stores the SID in the ACE tail.
		if sid.Equals(userSID) || sid.Equals(systemSID) || sid.Equals(adminSID) {
			continue
		}
		if ace.Mask&dangerous != 0 {
			return apperrors.New(
				apperrors.CodeLocalIOError,
				fmt.Sprintf("audit ancestor %s grants replacement rights to an untrusted SID", path),
				nil,
			)
		}
	}
	return nil
}

func verifyTrustedAncestorOwner(
	descriptor *windows.SECURITY_DESCRIPTOR,
	userSID, systemSID, adminSID *windows.SID,
	path string,
) error {
	owner, _, err := descriptor.Owner()
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to inspect audit ancestor owner", err)
	}
	if owner == nil ||
		(!owner.Equals(userSID) && !owner.Equals(systemSID) && !owner.Equals(adminSID)) {
		return apperrors.New(
			apperrors.CodeLocalIOError,
			fmt.Sprintf("audit ancestor %s is not owned by a trusted principal", path),
			nil,
		)
	}
	return nil
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

func verifyDescriptorOwner(descriptor *windows.SECURITY_DESCRIPTOR, userSID *windows.SID) error {
	owner, _, err := descriptor.Owner()
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to inspect audit path owner", err)
	}
	if owner == nil || !owner.Equals(userSID) {
		return apperrors.New(apperrors.CodeLocalIOError, "audit path is not owned by the current user", nil)
	}
	return nil
}

func trustedAuditSIDs() (*windows.SID, *windows.SID, *windows.SID, error) {
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

func uniqueAuditSIDs(candidates ...*windows.SID) []*windows.SID {
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

func auditExplicitAccess(
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

func atomicReplaceFile(from, to string) error {
	fromPtr, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	toPtr, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(fromPtr, toPtr, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func replaceFile(from, to string) error {
	if err := atomicReplaceFile(from, to); err != nil {
		return err
	}
	return syncParentDirectory(to)
}

func syncParentDirectory(string) error {
	// File.Sync flushes the newly created key handle on Windows. Directory
	// handles do not support the Unix fsync contract.
	return nil
}

func auditPathEqual(left, right string) bool {
	return strings.EqualFold(left, right)
}
