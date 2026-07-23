//go:build windows

package credstore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestEncryptedFileWindowsRejectsInsecureACL(t *testing.T) {
	backend := newTestEncryptedFileBackend(t)
	if err := backend.Put(context.Background(), "dev", "old"); err != nil {
		t.Fatalf("Put(old) error = %v", err)
	}
	if err := grantWorldReadCredentialACL(backend.path); err != nil {
		t.Fatalf("grantWorldReadCredentialACL() error = %v", err)
	}
	if _, err := backend.Get(context.Background(), "dev"); err == nil {
		t.Fatal("Get() error = nil, want insecure ACL rejection")
	}
	if err := backend.Put(context.Background(), "dev", "new"); err == nil {
		t.Fatal("Put(new) error = nil, want insecure ACL rejection")
	}
}

func secureCredstoreTestRoot(t *testing.T, path string) {
	t.Helper()
	userSID, systemSID, adminSID, err := credentialTestSIDs()
	if err != nil {
		t.Fatal(err)
	}
	fullControl := windows.ACCESS_MASK(
		windows.STANDARD_RIGHTS_ALL |
			windows.FILE_GENERIC_READ |
			windows.FILE_GENERIC_WRITE |
			windows.FILE_GENERIC_EXECUTE |
			windows.DELETE,
	)
	entries := []windows.EXPLICIT_ACCESS{
		credentialTestAccess(userSID, windows.TRUSTEE_IS_USER, fullControl, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT),
		credentialTestAccess(systemSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, fullControl, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT),
		credentialTestAccess(adminSID, windows.TRUSTEE_IS_GROUP, fullControl, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT),
	}
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	for current := path; !strings.EqualFold(current, os.TempDir()); current = filepath.Dir(current) {
		if err := windows.SetNamedSecurityInfo(
			current,
			windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil,
			nil,
			dacl,
			nil,
		); err != nil {
			t.Fatal(err)
		}
	}
}

func grantWorldReadCredentialACL(path string) error {
	userSID, _, _, err := credentialTestSIDs()
	if err != nil {
		return err
	}
	worldSID, err := windows.CreateWellKnownSid(windows.WinWorldSid)
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
	entries := []windows.EXPLICIT_ACCESS{
		credentialTestAccess(userSID, windows.TRUSTEE_IS_USER, fullControl, windows.NO_INHERITANCE),
		credentialTestAccess(worldSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, windows.FILE_GENERIC_READ, windows.NO_INHERITANCE),
	}
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
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

func credentialTestSIDs() (*windows.SID, *windows.SID, *windows.SID, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return nil, nil, nil, fmt.Errorf("open process token: %w", err)
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

func credentialTestAccess(
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
