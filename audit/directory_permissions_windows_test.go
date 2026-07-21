//go:build windows

package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

type testTokenOwner struct {
	owner *windows.SID
}

func TestMain(m *testing.M) {
	if err := useCurrentUserAsTestDefaultOwner(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "configure Windows test token owner: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func useCurrentUserAsTestDefaultOwner() error {
	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT,
		&token,
	); err != nil {
		return err
	}
	defer func() { _ = token.Close() }()

	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	owner := testTokenOwner{owner: user.User.Sid}
	return windows.SetTokenInformation(
		token,
		windows.TokenOwner,
		(*byte)(unsafe.Pointer(&owner)),
		uint32(unsafe.Sizeof(owner)),
	)
}

func TestUniqueAuditSIDsDeduplicatesLocalSystemOwner(t *testing.T) {
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	trusted := uniqueAuditSIDs(systemSID, systemSID, adminSID)
	if len(trusted) != 2 || !trusted[0].Equals(systemSID) || !trusted[1].Equals(adminSID) {
		t.Fatalf("uniqueAuditSIDs() returned %d unexpected SIDs", len(trusted))
	}
}

func TestAppendPreservesExistingDirectoryPermissions(t *testing.T) {
	t.Run("relative audit path preserves working directory", func(t *testing.T) {
		dir := privateTestDir(t)
		before := directorySecurityDescriptor(t, dir)
		t.Chdir(dir)
		if err := Append("audit.log", Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess}); err != nil {
			t.Fatalf("Append() error = %v", err)
		}
		if after := directorySecurityDescriptor(t, dir); after != before {
			t.Fatalf("working directory security changed:\nbefore: %s\nafter:  %s", before, after)
		}
	})

	t.Run("custom key preserves shared parent", func(t *testing.T) {
		dir := privateTestDir(t)
		shared := filepath.Join(dir, "shared")
		if err := os.Mkdir(shared, 0o755); err != nil {
			t.Fatal(err)
		}
		before := directorySecurityDescriptor(t, shared)
		path := filepath.Join(dir, "audit.log")
		keyPath := filepath.Join(shared, "audit.key")
		if err := AppendWithOptions(
			path,
			Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess},
			Options{IntegrityKeyPath: keyPath},
		); err != nil {
			t.Fatalf("AppendWithOptions() error = %v", err)
		}
		if after := directorySecurityDescriptor(t, shared); after != before {
			t.Fatalf("custom key parent security changed:\nbefore: %s\nafter:  %s", before, after)
		}
	})

	t.Run("nested creation preserves existing ancestor", func(t *testing.T) {
		dir := privateTestDir(t)
		ancestor := filepath.Join(dir, "existing")
		if err := os.Mkdir(ancestor, 0o755); err != nil {
			t.Fatal(err)
		}
		before := directorySecurityDescriptor(t, ancestor)
		firstNew := filepath.Join(ancestor, "new-one")
		secondNew := filepath.Join(firstNew, "new-two")
		if err := AppendWithOptions(
			filepath.Join(dir, "audit.log"),
			Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess},
			Options{IntegrityKeyPath: filepath.Join(secondNew, "audit.key")},
		); err != nil {
			t.Fatalf("AppendWithOptions() error = %v", err)
		}
		if after := directorySecurityDescriptor(t, ancestor); after != before {
			t.Fatalf("existing ancestor security changed:\nbefore: %s\nafter:  %s", before, after)
		}
		for _, created := range []string{firstNew, secondNew} {
			if err := verifyOwnerOnlyACL(created); err != nil {
				t.Fatalf("verifyOwnerOnlyACL(%s) error = %v", created, err)
			}
		}
	})

	t.Run("untrusted read-only ACE is preserved", func(t *testing.T) {
		dir := privateTestDir(t)
		shared := filepath.Join(dir, "read-only-shared")
		if err := os.Mkdir(shared, 0o755); err != nil {
			t.Fatal(err)
		}
		setTestDirectoryACL(t, shared, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_EXECUTE)
		before := directorySecurityDescriptor(t, shared)
		if err := Append(
			filepath.Join(shared, "audit.log"),
			Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess},
		); err != nil {
			t.Fatalf("Append() error = %v", err)
		}
		if after := directorySecurityDescriptor(t, shared); after != before {
			t.Fatalf("read-only shared directory security changed:\nbefore: %s\nafter:  %s", before, after)
		}
	})

	t.Run("untrusted write ACE fails closed", func(t *testing.T) {
		dir := privateTestDir(t)
		shared := filepath.Join(dir, "writable-shared")
		if err := os.Mkdir(shared, 0o755); err != nil {
			t.Fatal(err)
		}
		const fileDeleteChild windows.ACCESS_MASK = 0x00000040
		setTestDirectoryACL(t, shared, windows.FILE_GENERIC_WRITE|fileDeleteChild)
		before := directorySecurityDescriptor(t, shared)
		if err := Append(
			filepath.Join(shared, "audit.log"),
			Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess},
		); err == nil {
			t.Fatal("Append() error = nil, want insecure-directory rejection")
		}
		if after := directorySecurityDescriptor(t, shared); after != before {
			t.Fatalf("writable shared directory security changed:\nbefore: %s\nafter:  %s", before, after)
		}
	})

	t.Run("missing child under unsafe ancestor fails closed", func(t *testing.T) {
		dir := privateTestDir(t)
		unsafe := filepath.Join(dir, "unsafe")
		if err := os.Mkdir(unsafe, 0o755); err != nil {
			t.Fatal(err)
		}
		const fileDeleteChild windows.ACCESS_MASK = 0x00000040
		setTestDirectoryACL(t, unsafe, windows.FILE_GENERIC_WRITE|fileDeleteChild)
		before := directorySecurityDescriptor(t, unsafe)
		missing := filepath.Join(unsafe, "missing")
		if err := AppendWithOptions(
			filepath.Join(dir, "audit.log"),
			Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess},
			Options{IntegrityKeyPath: filepath.Join(missing, "audit.key")},
		); err == nil {
			t.Fatal("AppendWithOptions() error = nil, want unsafe-ancestor rejection")
		}
		if after := directorySecurityDescriptor(t, unsafe); after != before {
			t.Fatalf("unsafe ancestor security changed:\nbefore: %s\nafter:  %s", before, after)
		}
		if _, err := os.Stat(missing); !os.IsNotExist(err) {
			t.Fatalf("missing child was created: %v", err)
		}
	})

	t.Run("secure leaf under unsafe grandparent fails closed", func(t *testing.T) {
		dir := privateTestDir(t)
		unsafe := filepath.Join(dir, "unsafe-grandparent")
		if err := os.Mkdir(unsafe, 0o755); err != nil {
			t.Fatal(err)
		}
		const fileDeleteChild windows.ACCESS_MASK = 0x00000040
		setTestDirectoryACL(t, unsafe, windows.FILE_GENERIC_WRITE|fileDeleteChild)
		leaf := filepath.Join(unsafe, "secure-leaf")
		if err := os.Mkdir(leaf, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := setOwnerOnlyACL(leaf, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT); err != nil {
			t.Fatal(err)
		}
		if err := Append(
			filepath.Join(leaf, "audit.log"),
			Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess},
		); err == nil {
			t.Fatal("Append() error = nil, want unsafe-grandparent rejection")
		}
	})

	t.Run("reparse ancestor fails closed", func(t *testing.T) {
		dir := privateTestDir(t)
		target := filepath.Join(dir, "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("directory symlink is unavailable: %v", err)
		}
		if err := Append(
			filepath.Join(link, "audit.log"),
			Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess},
		); err == nil {
			t.Fatal("Append() error = nil, want reparse-ancestor rejection")
		}
	})

	t.Run("existing key parent becoming unsafe fails closed", func(t *testing.T) {
		dir := privateTestDir(t)
		keyDir := filepath.Join(dir, "keys")
		if err := os.Mkdir(keyDir, 0o755); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "audit.log")
		keyPath := filepath.Join(keyDir, "audit.key")
		options := Options{IntegrityKeyPath: keyPath}
		if err := AppendWithOptions(
			path,
			Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess},
			options,
		); err != nil {
			t.Fatalf("initial AppendWithOptions() error = %v", err)
		}
		beforeLog := mustReadFile(t, path)
		beforeKey := mustReadFile(t, keyPath)
		beforeCheckpoint := mustReadFile(t, checkpointPath(path))
		const fileDeleteChild windows.ACCESS_MASK = 0x00000040
		setTestDirectoryACL(t, keyDir, windows.FILE_GENERIC_WRITE|fileDeleteChild)

		if err := AppendWithOptions(
			path,
			Event{EventType: "resource.update", Operator: "bob", Status: StatusSuccess},
			options,
		); err == nil {
			t.Fatal("AppendWithOptions() error = nil, want unsafe key-parent rejection")
		}
		if _, err := Query(path, Filter{IntegrityKeyPath: keyPath}); err == nil {
			t.Fatal("Query() error = nil, want unsafe key-parent rejection")
		}
		if _, err := Verify(path, VerifyOptions{IntegrityKeyPath: keyPath}); err == nil {
			t.Fatal("Verify() error = nil, want unsafe key-parent rejection")
		}
		if got := mustReadFile(t, path); string(got) != string(beforeLog) {
			t.Fatal("unsafe key parent changed audit log")
		}
		if got := mustReadFile(t, keyPath); string(got) != string(beforeKey) {
			t.Fatal("unsafe key parent changed integrity key")
		}
		if got := mustReadFile(t, checkpointPath(path)); string(got) != string(beforeCheckpoint) {
			t.Fatal("unsafe key parent changed checkpoint")
		}
	})

	t.Run("existing log parent becoming unsafe fails closed", func(t *testing.T) {
		dir := privateTestDir(t)
		path := filepath.Join(dir, "audit.log")
		if err := Append(path, Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess}); err != nil {
			t.Fatalf("initial Append() error = %v", err)
		}
		beforeLog := mustReadFile(t, path)
		beforeKey := mustReadFile(t, defaultIntegrityKeyPath(path))
		beforeCheckpoint := mustReadFile(t, checkpointPath(path))
		const fileDeleteChild windows.ACCESS_MASK = 0x00000040
		setTestDirectoryACL(t, dir, windows.FILE_GENERIC_WRITE|fileDeleteChild)

		if err := Append(path, Event{EventType: "resource.update", Operator: "bob", Status: StatusSuccess}); err == nil {
			t.Fatal("Append() error = nil, want unsafe log-parent rejection")
		}
		if _, err := Query(path, Filter{}); err == nil {
			t.Fatal("Query() error = nil, want unsafe log-parent rejection")
		}
		if _, err := Verify(path, VerifyOptions{}); err == nil {
			t.Fatal("Verify() error = nil, want unsafe log-parent rejection")
		}
		if got := mustReadFile(t, path); string(got) != string(beforeLog) {
			t.Fatal("unsafe log parent changed audit log")
		}
		if got := mustReadFile(t, defaultIntegrityKeyPath(path)); string(got) != string(beforeKey) {
			t.Fatal("unsafe log parent changed integrity key")
		}
		if got := mustReadFile(t, checkpointPath(path)); string(got) != string(beforeCheckpoint) {
			t.Fatal("unsafe log parent changed checkpoint")
		}
	})
}

func TestAuditDirectoryChainRejectsExistingWindowsJunction(t *testing.T) {
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
	if err := ensureOwnerOnlyDirectory(filepath.Join(junction, "opskit-audit-must-not-be-created")); err == nil {
		t.Fatal("ensureOwnerOnlyDirectory() error = nil, want junction rejection")
	}
}

func directorySecurityDescriptor(t *testing.T, path string) string {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%s) error = %v", path, err)
	}
	return descriptor.String()
}

func secureTestDirectory(t testing.TB, path string) {
	t.Helper()
	for parent := filepath.Dir(path); !strings.EqualFold(parent, os.TempDir()); parent = filepath.Dir(parent) {
		if err := setOwnerOnlyACL(parent, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT); err != nil {
			t.Fatalf("setOwnerOnlyACL(%s) error = %v", parent, err)
		}
	}
	if err := createOwnerOnlyDirectory(path); err != nil {
		t.Fatalf("createOwnerOnlyDirectory(%s) error = %v", path, err)
	}
	if err := setOwnerOnlyACL(path, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT); err != nil {
		t.Fatalf("setOwnerOnlyACL(%s) error = %v", path, err)
	}
	if err := verifyOwnerOnlyACL(path); err != nil {
		t.Fatalf("verifyOwnerOnlyACL(%s) error = %v", path, err)
	}
}

func makeTestAuditFileInsecure(t testing.TB, path string) {
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
	entries := []windows.EXPLICIT_ACCESS{
		auditExplicitAccess(userSID, windows.TRUSTEE_IS_USER, fullControl, windows.NO_INHERITANCE),
		auditExplicitAccess(systemSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, fullControl, windows.NO_INHERITANCE),
		auditExplicitAccess(adminSID, windows.TRUSTEE_IS_GROUP, fullControl, windows.NO_INHERITANCE),
		auditExplicitAccess(usersSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, windows.FILE_GENERIC_WRITE, windows.NO_INHERITANCE),
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

func setTestDirectoryACL(t *testing.T, path string, untrustedPermissions windows.ACCESS_MASK) {
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
	inheritance := uint32(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	entries := []windows.EXPLICIT_ACCESS{
		auditExplicitAccess(userSID, windows.TRUSTEE_IS_USER, fullControl, inheritance),
		auditExplicitAccess(systemSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, fullControl, inheritance),
		auditExplicitAccess(adminSID, windows.TRUSTEE_IS_GROUP, fullControl, inheritance),
		auditExplicitAccess(usersSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, untrustedPermissions, inheritance),
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
