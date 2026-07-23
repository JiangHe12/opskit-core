//go:build windows

package securefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsFilePermissionChecksAreEnforced(t *testing.T) {
	path := secureTestPath(t, "state")
	if err := WriteFile(path, []byte("old")); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := grantWorldAccessForTest(path, windows.FILE_GENERIC_READ, false); err != nil {
		t.Fatalf("grantWorldAccessForTest() error = %v", err)
	}
	if _, err := CheckFile(path); err == nil {
		t.Fatal("CheckFile() error = nil, want insecure ACL rejection")
	}
	if _, err := ReadFile(path); err == nil {
		t.Fatal("ReadFile() error = nil, want insecure ACL rejection")
	}
	if err := WriteFile(path, []byte("new")); err == nil {
		t.Fatal("WriteFile() error = nil, want insecure ACL rejection")
	}
}

func TestWindowsWritableParentIsRejected(t *testing.T) {
	root := t.TempDir()
	secureTestRoot(t, root)
	parent := filepath.Join(root, "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := grantWorldAccessForTest(parent, windows.FILE_GENERIC_WRITE, true); err != nil {
		t.Fatalf("grantWorldAccessForTest() error = %v", err)
	}
	if err := WriteFile(filepath.Join(parent, "state"), []byte("value")); err == nil {
		t.Fatal("WriteFile() error = nil, want writable parent rejection")
	}
}

func TestWindowsReparseTargetIsRejected(t *testing.T) {
	dir := filepath.Dir(secureTestPath(t, "state"))
	target := filepath.Join(dir, "target")
	path := filepath.Join(dir, "state")
	if err := WriteFile(target, []byte("old")); err != nil {
		t.Fatalf("WriteFile(target) error = %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}
	if _, err := ReadFile(path); err == nil {
		t.Fatal("ReadFile() error = nil, want reparse rejection")
	}
	if err := WriteFile(path, []byte("new")); err == nil {
		t.Fatal("WriteFile() error = nil, want reparse rejection")
	}
}

func secureTestRoot(t *testing.T, path string) {
	t.Helper()
	userSID, systemSID, adminSID, err := trustedSIDs()
	if err != nil {
		t.Fatal(err)
	}
	trusted := uniqueSIDs(userSID, systemSID, adminSID)
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(trusted))
	fullControl := windows.ACCESS_MASK(
		windows.STANDARD_RIGHTS_ALL |
			windows.FILE_GENERIC_READ |
			windows.FILE_GENERIC_WRITE |
			windows.FILE_GENERIC_EXECUTE |
			windows.DELETE,
	)
	for _, sid := range trusted {
		trusteeType := windows.TRUSTEE_TYPE(windows.TRUSTEE_IS_GROUP)
		if sid.Equals(userSID) {
			trusteeType = windows.TRUSTEE_IS_USER
		} else if sid.Equals(systemSID) {
			trusteeType = windows.TRUSTEE_IS_WELL_KNOWN_GROUP
		}
		entries = append(entries, explicitAccess(
			sid,
			trusteeType,
			fullControl,
			windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		))
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
		if err := verifyOwnerOnlyPath(current); err != nil {
			t.Fatalf("secure test root ACL: %v", err)
		}
	}
}

func grantWorldAccessForTest(path string, access windows.ACCESS_MASK, container bool) error {
	userSID, _, _, err := trustedSIDs()
	if err != nil {
		return err
	}
	worldSID, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return err
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if container {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	entries := []windows.EXPLICIT_ACCESS{
		explicitAccess(userSID, windows.TRUSTEE_IS_USER, windows.GENERIC_ALL, inheritance),
		explicitAccess(worldSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, access, inheritance),
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
