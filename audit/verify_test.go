package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVerifyReportsMalformedEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	event := Event{Timestamp: time.Now().UTC(), EventType: EventType("resource.create"), Operator: "alice", Status: StatusSuccess}
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(append(data, '\n'), []byte("not json\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Verify(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Valid != 1 || result.Malformed != 1 || result.Total != 2 {
		t.Fatalf("Verify() = %+v, want one valid and one malformed", result)
	}
}

func TestVerifyReportsSchemaMismatchAsMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	valid := Event{Timestamp: time.Now().UTC(), EventType: EventType("resource.create"), Operator: "alice", Status: StatusSuccess}
	validData, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	// Syntactically valid JSON but does not match Event struct (context is string, not EventContext).
	badSchema := []byte(`{"timestamp":"2026-05-26T00:00:01Z","type":"resource.create","context":"not-a-struct"}` + "\n")
	contents := append(append(validData, '\n'), badSchema...)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Verify(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Valid != 1 || result.Malformed != 1 || result.Total != 2 {
		t.Fatalf("Verify() = %+v, want one valid and one malformed", result)
	}
}

func TestVerifyRepairQuarantinesSchemaMismatchEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	valid := Event{Timestamp: time.Now().UTC(), EventType: EventType("resource.create"), Operator: "alice", Status: StatusSuccess}
	validData, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	badSchema := []byte(`{"timestamp":"2026-05-26T00:00:01Z","type":"resource.create","context":"not-a-struct"}` + "\n")
	contents := append(append(validData, '\n'), badSchema...)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Verify(path, VerifyOptions{Repair: true, Confirm: true})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if len(result.Files) != 1 || !result.Files[0].Repaired || result.Files[0].Quarantine == "" {
		t.Fatalf("Verify() files = %+v, want repaired quarantine", result.Files)
	}
	repaired, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(repaired), `"not-a-struct"`) {
		t.Fatalf("repaired audit still contains schema-mismatch line: %s", repaired)
	}
	quarantine, err := os.ReadFile(result.Files[0].Quarantine)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(quarantine), `"not-a-struct"`) {
		t.Fatalf("quarantine = %s, want schema-mismatch line", quarantine)
	}
}

func TestVerifyRepairQuarantinesMalformedEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	event := Event{Timestamp: time.Now().UTC(), EventType: EventType("resource.create"), Operator: "alice", Status: StatusSuccess}
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(append(data, '\n'), []byte("not json\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Verify(path, VerifyOptions{Repair: true, Confirm: true})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if len(result.Files) != 1 || !result.Files[0].Repaired || result.Files[0].Quarantine == "" {
		t.Fatalf("Verify() files = %+v, want repaired quarantine", result.Files)
	}
	repaired, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(repaired), "not json") {
		t.Fatalf("repaired audit still contains malformed line: %s", repaired)
	}
	quarantine, err := os.ReadFile(result.Files[0].Quarantine)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(quarantine), "not json") {
		t.Fatalf("quarantine = %s, want malformed line", quarantine)
	}
}

func TestVerifyDecryptsEncryptedEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	identity, publicKeyPath := writeTestAgePublicKey(t)
	if err := AppendWithOptions(path, Event{EventType: EventType("resource.create"), Operator: "alice", Status: StatusSuccess},
		Options{EncryptPublicKeyPath: publicKeyPath}); err != nil {
		t.Fatalf("AppendWithOptions() error = %v", err)
	}
	result, err := Verify(path, VerifyOptions{Decrypt: true, PrivateKey: identity.String()})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Valid != 1 || result.Malformed != 0 {
		t.Fatalf("Verify() = %+v, want decrypted valid entry", result)
	}
}
