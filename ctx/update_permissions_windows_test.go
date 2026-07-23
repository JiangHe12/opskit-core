//go:build windows

package ctx

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestStoreUpdateRejectsInsecureExistingFileACLBeforeCallback(t *testing.T) {
	configureTestStore(t)

	path := privateTestPath(t, "config.yaml")
	content := []byte("apiVersion: test.io/context/v1\ncurrent-context: \"\"\ncontexts: {}\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := grantWorldReadACL(path); err != nil {
		t.Fatalf("grantWorldReadACL() error = %v", err)
	}
	SetConfigPath(path)

	called := false
	err := testStore.Update(func(_ *Config[testContext]) error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("Update() error = nil, want insecure ACL rejection")
	}
	if called {
		t.Fatal("Update() called callback before rejecting insecure ACL")
	}
}

func grantWorldReadACL(path string) error {
	ownerSID, err := testCurrentUserSID()
	if err != nil {
		return err
	}
	worldSID, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return err
	}
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
				TrusteeValue:             windows.TrusteeValueFromSID(ownerSID),
			},
		},
		{
			AccessPermissions: windows.FILE_GENERIC_READ,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
				TrusteeForm:              windows.TRUSTEE_IS_SID,
				TrusteeType:              windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue:             windows.TrusteeValueFromSID(worldSID),
			},
		},
	}
	dacl, err := windows.ACLFromEntries(explicitAccess, nil)
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

func secureTestRoot(t *testing.T, path string) {
	t.Helper()
	userSID, err := testCurrentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
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
		testExplicitAccess(userSID, windows.TRUSTEE_IS_USER, fullControl, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT),
		testExplicitAccess(systemSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, fullControl, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT),
		testExplicitAccess(adminSID, windows.TRUSTEE_IS_GROUP, fullControl, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT),
	}
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	for current := path; !strings.EqualFold(current, os.TempDir()); current = filepath.Dir(current) {
		if err := windows.SetNamedSecurityInfo(
			current,
			windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|
				windows.DACL_SECURITY_INFORMATION|
				windows.PROTECTED_DACL_SECURITY_INFORMATION,
			userSID,
			nil,
			dacl,
			nil,
		); err != nil {
			t.Fatal(err)
		}
	}
}

func testCurrentUserSID() (*windows.SID, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return nil, fmt.Errorf("open process token: %w", err)
	}
	defer func() { _ = token.Close() }()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("get token user: %w", err)
	}
	return user.User.Sid.Copy()
}

func testExplicitAccess(
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
