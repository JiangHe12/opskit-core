//go:build !windows

package audit

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
)

func TestLoadAgeRecipientPOSIXPermissionTrust(t *testing.T) {
	t.Run("public read is allowed", func(t *testing.T) {
		path := writeRecipientPermissionTestKey(t, privateTestDir(t), 0o644)
		if _, err := loadAgeRecipient(path); err != nil {
			t.Fatalf("loadAgeRecipient() error = %v", err)
		}
	})

	for _, mode := range []os.FileMode{0o660, 0o606, 0o666} {
		t.Run("untrusted write mode "+mode.String(), func(t *testing.T) {
			path := writeRecipientPermissionTestKey(t, privateTestDir(t), mode)
			if _, err := loadAgeRecipient(path); err == nil {
				t.Fatalf("loadAgeRecipient() accepted writable recipient mode %#o", mode)
			}
		})
	}

	t.Run("writable leaf parent", func(t *testing.T) {
		parent := filepath.Join(privateTestDir(t), "writable")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		path := writeRecipientPermissionTestKey(t, parent, 0o644)
		if err := os.Chmod(parent, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := loadAgeRecipient(path); err == nil {
			t.Fatal("loadAgeRecipient() accepted writable recipient parent")
		}
	})

	t.Run("writable ancestor", func(t *testing.T) {
		ancestor := filepath.Join(privateTestDir(t), "writable-ancestor")
		if err := os.Mkdir(ancestor, 0o700); err != nil {
			t.Fatal(err)
		}
		leaf := filepath.Join(ancestor, "leaf")
		if err := os.Mkdir(leaf, 0o700); err != nil {
			t.Fatal(err)
		}
		path := writeRecipientPermissionTestKey(t, leaf, 0o644)
		if err := os.Chmod(ancestor, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := loadAgeRecipient(path); err == nil {
			t.Fatal("loadAgeRecipient() accepted writable recipient ancestor")
		}
	})
}

func TestValidateExistingAuditDirectoryRejectsForeignOwnerWithSafeMode(t *testing.T) {
	foreignUID := uint32(os.Geteuid() + 1)
	if foreignUID == 0 {
		foreignUID = 1
	}
	info := recipientTestFileInfo{
		mode: os.ModeDir | 0o755,
		stat: &syscall.Stat_t{Uid: foreignUID},
	}
	if err := validateExistingAuditDirectory(info, "/safe-looking-foreign-owner", false); err == nil {
		t.Fatal("validateExistingAuditDirectory() accepted a foreign-owned ancestor with mode 0755")
	}
}

type recipientTestFileInfo struct {
	mode os.FileMode
	stat *syscall.Stat_t
}

func (info recipientTestFileInfo) Name() string       { return "recipient-parent" }
func (info recipientTestFileInfo) Size() int64        { return 0 }
func (info recipientTestFileInfo) Mode() os.FileMode  { return info.mode }
func (info recipientTestFileInfo) ModTime() time.Time { return time.Time{} }
func (info recipientTestFileInfo) IsDir() bool        { return info.mode.IsDir() }
func (info recipientTestFileInfo) Sys() any           { return info.stat }

func writeRecipientPermissionTestKey(
	t *testing.T,
	directory string,
	mode os.FileMode,
) string {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "audit-recipient.pub")
	if err := os.WriteFile(path, []byte(identity.Recipient().String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}
