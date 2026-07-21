//go:build windows

package ctx

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestStoreUpdateRepairsInsecureExistingFileACLBeforeCallback(t *testing.T) {
	configureTestStore(t)

	path := filepath.Join(t.TempDir(), "config.yaml")
	content := []byte("apiVersion: test.io/context/v1\ncurrent-context: \"\"\ncontexts: {}\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := grantWorldReadACL(path); err != nil {
		t.Fatalf("grantWorldReadACL() error = %v", err)
	}
	if err := verifyOwnerOnlyACL(path); err == nil {
		t.Fatal("test setup produced an owner-only ACL, want insecure ACL")
	}
	SetConfigPath(path)

	called := false
	err := testStore.Update(func(_ *Config[testContext]) error {
		called = true
		return verifyOwnerOnlyACL(path)
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if !called {
		t.Fatal("Update() did not call callback")
	}
}

func grantWorldReadACL(path string) error {
	ownerSID, err := currentUserSID()
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
