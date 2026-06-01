//go:build windows

package ctx

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func currentUserSID() (*windows.SID, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return nil, fmt.Errorf("open process token: %w", err)
	}
	defer func() { _ = token.Close() }()

	user, err := token.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("get token user: %w", err)
	}
	return user.User.Sid, nil
}

// setOwnerOnlyACL replaces the file DACL with owner, SYSTEM, and Administrators.
func setOwnerOnlyACL(path string) error {
	sid, err := currentUserSID()
	if err != nil {
		return err
	}
	systemSID, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	adminSID, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	fullControl := windows.ACCESS_MASK(windows.STANDARD_RIGHTS_ALL | windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE | windows.FILE_GENERIC_EXECUTE | windows.DELETE)

	explicitAccess := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: fullControl,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
				TrusteeForm:              windows.TRUSTEE_IS_SID,
				TrusteeType:              windows.TRUSTEE_IS_USER,
				TrusteeValue:             windows.TrusteeValueFromSID(sid),
			},
		},
		{
			AccessPermissions: fullControl,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
				TrusteeForm:              windows.TRUSTEE_IS_SID,
				TrusteeType:              windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue:             windows.TrusteeValueFromSID(systemSID),
			},
		},
		{
			AccessPermissions: fullControl,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
				TrusteeForm:              windows.TRUSTEE_IS_SID,
				TrusteeType:              windows.TRUSTEE_IS_GROUP,
				TrusteeValue:             windows.TrusteeValueFromSID(adminSID),
			},
		},
	}

	dacl, err := windows.ACLFromEntries(explicitAccess, nil)
	if err != nil {
		return fmt.Errorf("create DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("set named security info: %w", err)
	}
	return nil
}

// verifyOwnerOnlyACL checks that only owner, SYSTEM, and Administrators have access.
func verifyOwnerOnlyACL(path string) error {
	sid, err := currentUserSID()
	if err != nil {
		return err
	}
	systemSID, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	adminSID, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("get named security info: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("get DACL: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("insecure file permissions on %s: no DACL present", path)
	}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var acePtr *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &acePtr); err != nil {
			return fmt.Errorf("get ace %d: %w", i, err)
		}
		if acePtr.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("insecure file permissions on %s: unexpected ACE type %d", path, acePtr.Header.AceType)
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&acePtr.SidStart)) //nolint:gosec // Windows ACL APIs expose ACE SID data through this documented struct tail pointer.
		if !aceSID.Equals(sid) && !aceSID.Equals(systemSID) && !aceSID.Equals(adminSID) {
			return fmt.Errorf("insecure file permissions on %s: access granted to untrusted SID", path)
		}
	}
	return nil
}

func checkFileOwner(_ os.FileInfo, _ string) error { return nil }
