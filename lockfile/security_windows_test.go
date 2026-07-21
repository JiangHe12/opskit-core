//go:build windows

package lockfile

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestUniqueLockSIDsDeduplicatesLocalSystemOwner(t *testing.T) {
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	trusted := uniqueLockSIDs(systemSID, systemSID, adminSID)
	if len(trusted) != 2 || !trusted[0].Equals(systemSID) || !trusted[1].Equals(adminSID) {
		t.Fatalf("uniqueLockSIDs() returned %d unexpected SIDs", len(trusted))
	}
}

func TestInspectRejectsReparseAndBroadACL(t *testing.T) {
	t.Run("reparse", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		if err := os.WriteFile(target, []byte("pid=1\ntoken=x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		base := filepath.Join(dir, "config")
		if err := os.Symlink(target, base+".lock"); err != nil {
			t.Skipf("file symlink is unavailable: %v", err)
		}
		if _, _, err := Inspect(base); err == nil {
			t.Fatal("Inspect() error = nil, want reparse rejection")
		}
	})

	t.Run("broad ACL", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "config")
		path := base + ".lock"
		file, err := createLockFileExclusive(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteString("pid=1\ntoken=x\n"); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		addUntrustedLockACE(t, path)
		if _, _, err := Inspect(base); err == nil {
			t.Fatal("Inspect() error = nil, want ACL rejection")
		}
	})
}

func addUntrustedLockACE(t *testing.T, path string) {
	t.Helper()
	userSID, systemSID, adminSID, err := trustedLockSIDs()
	if err != nil {
		t.Fatal(err)
	}
	usersSID, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
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
		lockExplicitAccess(userSID, windows.TRUSTEE_IS_USER, fullControl),
		lockExplicitAccess(systemSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, fullControl),
		lockExplicitAccess(adminSID, windows.TRUSTEE_IS_GROUP, fullControl),
		lockExplicitAccess(usersSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, windows.FILE_GENERIC_WRITE),
	}
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
}

func lockExplicitAccess(
	sid *windows.SID,
	trusteeType windows.TRUSTEE_TYPE,
	permissions windows.ACCESS_MASK,
) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: permissions,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
			TrusteeForm:              windows.TRUSTEE_IS_SID,
			TrusteeType:              trusteeType,
			TrusteeValue:             windows.TrusteeValueFromSID(sid),
		},
	}
}

func TestCreatedLockHasProtectedOwnerOnlyACL(t *testing.T) {
	base := filepath.Join(t.TempDir(), "config")
	lock := New(base)
	if err := lock.Acquire(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Release() }()
	content, present, err := Inspect(base)
	if err != nil || !present {
		t.Fatalf("Inspect() = (%q, %t, %v)", content, present, err)
	}
	if content == "" {
		t.Fatal("created lock content is empty")
	}
}

func TestLockOpenRejectsExistingWindowsJunction(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(home, "Application Data")
	junctionPtr, err := windows.UTF16PtrFromString(junction)
	if err != nil {
		t.Fatal(err)
	}
	attributes, err := windows.GetFileAttributes(junctionPtr)
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		t.Skipf("standard profile junction is unavailable: %v", err)
	}
	file, err := openLockFileNoFollow(junction)
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return
	}
	if err := verifyLockFileHandle(file, info); err == nil {
		t.Fatal("lock file validation accepted a directory junction")
	}
}
