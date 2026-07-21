//go:build windows

package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"golang.org/x/sys/windows"
)

func TestLoadAgeRecipientWindowsACLTrust(t *testing.T) {
	t.Run("public read is allowed", func(t *testing.T) {
		path := writeWindowsRecipientPermissionTestKey(t, privateTestDir(t))
		setTestRecipientACL(t, path, windows.FILE_GENERIC_READ)
		if _, err := loadAgeRecipient(path); err != nil {
			t.Fatalf("loadAgeRecipient() error = %v", err)
		}
	})

	t.Run("untrusted file write is rejected", func(t *testing.T) {
		path := writeWindowsRecipientPermissionTestKey(t, privateTestDir(t))
		setTestRecipientACL(t, path, windows.FILE_GENERIC_WRITE)
		if _, err := loadAgeRecipient(path); err == nil {
			t.Fatal("loadAgeRecipient() accepted an untrusted write ACE")
		}
	})

	t.Run("untrusted parent replacement is rejected", func(t *testing.T) {
		parent := filepath.Join(privateTestDir(t), "recipient-parent")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := setOwnerOnlyACL(parent, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT); err != nil {
			t.Fatal(err)
		}
		path := writeWindowsRecipientPermissionTestKey(t, parent)
		const fileDeleteChild windows.ACCESS_MASK = 0x00000040
		setTestDirectoryACL(t, parent, windows.FILE_GENERIC_WRITE|fileDeleteChild)
		if _, err := loadAgeRecipient(path); err == nil {
			t.Fatal("loadAgeRecipient() accepted a replaceable recipient parent")
		}
	})
}

func TestVerifyTrustedAncestorOwnerRejectsForeignOwnerWithSafeACL(t *testing.T) {
	userSID, systemSID, adminSID, err := trustedAuditSIDs()
	if err != nil {
		t.Fatal(err)
	}
	usersSID, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf(
		"O:%sD:P(A;;FRFX;;;%s)",
		usersSID.String(),
		userSID.String(),
	))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyTrustedAncestorOwner(
		descriptor,
		userSID,
		systemSID,
		adminSID,
		`C:\\safe-looking-foreign-owner`,
	); err == nil {
		t.Fatal("verifyTrustedAncestorOwner() accepted a foreign owner with a read-only ACL")
	}
}

func writeWindowsRecipientPermissionTestKey(t *testing.T, directory string) string {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "audit-recipient.pub")
	if err := os.WriteFile(path, []byte(identity.Recipient().String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func setTestRecipientACL(
	t *testing.T,
	path string,
	untrustedPermissions windows.ACCESS_MASK,
) {
	t.Helper()
	userSID, systemSID, adminSID, err := trustedAuditSIDs()
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
	entries := make([]windows.EXPLICIT_ACCESS, 0, 4)
	for _, sid := range uniqueAuditSIDs(userSID, systemSID, adminSID) {
		trusteeType := windows.TRUSTEE_TYPE(windows.TRUSTEE_IS_GROUP)
		if sid.Equals(userSID) {
			trusteeType = windows.TRUSTEE_IS_USER
		} else if sid.Equals(systemSID) {
			trusteeType = windows.TRUSTEE_IS_WELL_KNOWN_GROUP
		}
		entries = append(entries, auditExplicitAccess(sid, trusteeType, fullControl, windows.NO_INHERITANCE))
	}
	entries = append(entries, auditExplicitAccess(
		usersSID,
		windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
		untrustedPermissions,
		windows.NO_INHERITANCE,
	))
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
