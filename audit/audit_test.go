package audit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestAppendWritesJSONL(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	err := Append(path, Event{EventType: EventType("resource.create"), Operator: "me", Status: "pending"})
	if err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(data), `"eventType":"resource.create"`) {
		t.Fatalf("audit data = %s", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %#o, want 0600", info.Mode().Perm())
	}
}

func TestAppendRotatesOversizedActiveLog(t *testing.T) {
	dir := privateTestDir(t)
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 32)), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := AppendWithOptions(path, Event{EventType: EventType("resource.create"), Status: StatusSuccess}, Options{MaxSizeBytes: 1}); err != nil {
		t.Fatalf("AppendWithOptions() error = %v", err)
	}
	rotated, err := RotatedFiles(path)
	if err != nil {
		t.Fatalf("RotatedFiles() error = %v", err)
	}
	if len(rotated) != 1 {
		t.Fatalf("rotated files = %v, want 1", rotated)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(active) error = %v", err)
	}
	if !strings.Contains(string(data), `"eventType":"resource.create"`) {
		t.Fatalf("active audit data = %s", data)
	}
}

func TestRotatedFileTimestamp(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	rotated := path + ".20260524-010203.log"
	got, ok := RotatedFileTimestamp(path, rotated)
	if !ok {
		t.Fatal("RotatedFileTimestamp() ok = false")
	}
	if got.Format("20060102-150405") != "20260524-010203" {
		t.Fatalf("timestamp = %s", got)
	}
}

func TestAppendEncryptsAndQueryDecrypts(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	identity, publicKeyPath := writeTestAgePublicKey(t)
	if err := AppendWithOptions(path, Event{EventType: EventType("resource.create"), Operator: "alice", Status: StatusSuccess},
		Options{EncryptPublicKeyPath: publicKeyPath}); err != nil {
		t.Fatalf("AppendWithOptions() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if strings.Contains(string(data), `"operator":"alice"`) {
		t.Fatalf("encrypted audit line leaked plaintext: %s", data)
	}
	result, err := Query(path, Filter{PrivateKey: identity.String()})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(result.Events) != 1 || result.Events[0].Operator != "alice" {
		t.Fatalf("Query() events = %#v, want decrypted alice event", result.Events)
	}
}

func TestQueryEncryptedWithoutPrivateKeyErrors(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	_, publicKeyPath := writeTestAgePublicKey(t)
	if err := AppendWithOptions(path, Event{EventType: EventType("resource.create"), Status: StatusSuccess},
		Options{EncryptPublicKeyPath: publicKeyPath}); err != nil {
		t.Fatalf("AppendWithOptions() error = %v", err)
	}
	_, err := Query(path, Filter{})
	if err == nil || !strings.Contains(err.Error(), "OPSKIT_AUDIT_PRIVATE_KEY") {
		t.Fatalf("Query() error = %v, want missing private key error", err)
	}
}

func TestQueryMixedPlainAndEncryptedRotatedLogs(t *testing.T) {
	dir := privateTestDir(t)
	path := filepath.Join(dir, "audit.log")
	for range 100 {
		if err := Append(path, Event{EventType: EventType("resource.create"), Operator: "plain", Status: StatusSuccess}); err != nil {
			t.Fatalf("Append() error = %v", err)
		}
	}
	identity, publicKeyPath := writeTestAgePublicKey(t)
	for range 100 {
		if err := AppendWithOptions(path, Event{EventType: EventType("resource.update"), Operator: "encrypted", Status: StatusSuccess},
			Options{MaxSizeBytes: 1, EncryptPublicKeyPath: publicKeyPath}); err != nil {
			t.Fatalf("AppendWithOptions() error = %v", err)
		}
	}
	result, err := Query(path, Filter{PrivateKey: identity.String()})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(result.Events) != 200 {
		t.Fatalf("event count = %d, want 200", len(result.Events))
	}
}

func writeTestAgePublicKey(t *testing.T) (*age.X25519Identity, string) {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity() error = %v", err)
	}
	path := filepath.Join(privateTestDir(t), "audit.pub")
	if err := os.WriteFile(path, []byte(identity.Recipient().String()+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return identity, path
}

func privateTestDir(t testing.TB) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private")
	secureTestDirectory(t, path)
	return path
}
