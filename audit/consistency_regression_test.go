package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/lockfile"
)

func TestQueryAndQueryRawAcquireAuditLock(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	if err := Append(path, Event{
		EventType: "resource.create",
		Operator:  "alice",
		Status:    StatusSuccess,
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	lock := lockfile.New(path)
	if err := lock.Acquire(); err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer func() { _ = lock.Release() }()
	t.Setenv("OPSKIT_LOCK_TIMEOUT", "100ms")

	for name, query := range map[string]func() error{
		"Query": func() error {
			_, err := Query(path, Filter{})
			return err
		},
		"QueryRaw": func() error {
			_, err := QueryRaw(path, Filter{})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := query()
			if err == nil {
				t.Fatalf("%s() error = nil, want lock timeout", name)
			}
			if code := apperrors.AsAppError(err).Code; code != apperrors.CodeLocalIOError {
				t.Fatalf("%s() error code = %s, want %s: %v", name, code, apperrors.CodeLocalIOError, err)
			}
		})
	}
}

func TestNextRotatedPathStaysMonotonicWhenClockMovesBackward(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	future := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	for _, suffix := range []string{"", ".1", ".2"} {
		candidate := fmt.Sprintf("%s.%s%s.log", path, future.Format("20060102-150405"), suffix)
		if err := os.WriteFile(candidate, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got, err := nextRotatedPath(path, future.Add(-time.Hour))
	if err != nil {
		t.Fatalf("nextRotatedPath() error = %v", err)
	}
	want := fmt.Sprintf("%s.%s.3.log", path, future.Format("20060102-150405"))
	if got != want {
		t.Fatalf("nextRotatedPath() = %s, want %s", got, want)
	}
}

func TestSingleEnvelopeIdentityFieldRemainsLegacy(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	lines := []string{
		`{"apiVersion":"opskit-core.io/audit/v2","kind":"ForeignEvent","timestamp":"2026-07-20T01:00:00Z","eventType":"foreign.one","operator":"alice"}`,
		`{"apiVersion":"foreign.io/audit/v1","kind":"AuditEnvelope","timestamp":"2026-07-20T01:00:01Z","eventType":"foreign.two","operator":"bob"}`,
	}
	for _, line := range lines {
		if looksLikeEnvelope([]byte(line)) {
			t.Fatalf("looksLikeEnvelope(%s) = true, want legacy record", line)
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	raw, err := QueryRaw(path, Filter{})
	if err != nil {
		t.Fatalf("QueryRaw() error = %v", err)
	}
	if len(raw.Records) != len(lines) || raw.MalformedEntries != 0 {
		t.Fatalf("QueryRaw() = %+v, want %d legacy records", raw, len(lines))
	}
	verified, err := Verify(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if verified.LegacyUnauthenticated != len(lines) || verified.HasProblems() {
		t.Fatalf("Verify() = %+v, want clean legacy records", verified)
	}
}

func TestAppendRejectsLinesAboveReaderLimit(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		padding int
	}{
		{name: "plain payload exceeds limit", padding: maxAuditLineBytes + 1},
		{name: "envelope overhead exceeds limit", padding: maxAuditLineBytes - 128},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(privateTestDir(t), "audit.log")
			record := map[string]string{"payload": strings.Repeat("x", testCase.padding)}
			if testCase.padding < maxAuditLineBytes {
				plain, err := json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				if len(plain) > maxAuditLineBytes {
					t.Fatalf("test payload length = %d, want <= %d", len(plain), maxAuditLineBytes)
				}
			}

			err := AppendRecord(path, record, Options{})
			if err == nil {
				t.Fatal("AppendRecord() error = nil, want line-size rejection")
			}
			if code := apperrors.AsAppError(err).Code; code != apperrors.CodeValidationFailed {
				t.Fatalf("AppendRecord() error code = %s, want %s: %v", code, apperrors.CodeValidationFailed, err)
			}
			if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
				t.Fatalf("oversized AppendRecord() created active log: %v", statErr)
			}
			if _, statErr := os.Stat(checkpointPath(path)); !os.IsNotExist(statErr) {
				t.Fatalf("oversized AppendRecord() created checkpoint: %v", statErr)
			}
		})
	}
}

func TestIntegrityKeyPathRejectsAuditArtifactNamespace(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		keyPath func(string) string
	}{
		{name: "active", keyPath: func(path string) string { return path }},
		{name: "checkpoint", keyPath: checkpointPath},
		{name: "lock", keyPath: func(path string) string { return path + ".lock" }},
		{name: "rotation", keyPath: func(path string) string { return path + ".20260720-010203.log" }},
		{name: "quarantine", keyPath: func(path string) string { return path + ".quarantine.20260720-010203.log" }},
		{name: "temporary artifact", keyPath: func(path string) string { return path + ".checkpoint.tmp-manual" }},
		{
			name: "lexical alias",
			keyPath: func(path string) string {
				return filepath.Join(filepath.Dir(path), "missing", "..", filepath.Base(path)+".checkpoint")
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(privateTestDir(t), "audit.log")
			err := AppendWithOptions(
				path,
				Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess},
				Options{IntegrityKeyPath: testCase.keyPath(path)},
			)
			if err == nil {
				t.Fatal("AppendWithOptions() error = nil, want key-path conflict")
			}
			if code := apperrors.AsAppError(err).Code; code != apperrors.CodeValidationFailed {
				t.Fatalf("AppendWithOptions() error code = %s, want %s: %v", code, apperrors.CodeValidationFailed, err)
			}
			if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
				t.Fatalf("conflicting key path created active log: %v", statErr)
			}
		})
	}
}

func TestIntegrityKeyPathConflictIsRejectedByReaders(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	if err := Append(path, Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	for name, read := range map[string]func() error{
		"Query": func() error {
			_, err := Query(path, Filter{IntegrityKeyPath: path})
			return err
		},
		"QueryRaw": func() error {
			_, err := QueryRaw(path, Filter{IntegrityKeyPath: checkpointPath(path)})
			return err
		},
		"Verify": func() error {
			_, err := Verify(path, VerifyOptions{IntegrityKeyPath: path + ".lock"})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := read()
			if err == nil {
				t.Fatalf("%s() error = nil, want key-path conflict", name)
			}
			if code := apperrors.AsAppError(err).Code; code != apperrors.CodeValidationFailed {
				t.Fatalf("%s() error code = %s, want %s: %v", name, code, apperrors.CodeValidationFailed, err)
			}
		})
	}
}

func TestIntegrityKeyPathRejectsHardLinkAlias(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	if err := os.WriteFile(path, []byte("existing audit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := defaultIntegrityKeyPath(path)
	if err := os.Link(path, keyPath); err != nil {
		t.Fatalf("Link() error = %v", err)
	}
	err := validateIntegrityKeyPath(path, keyPath)
	if err == nil {
		t.Fatal("validateIntegrityKeyPath() error = nil, want hard-link conflict")
	}
	if code := apperrors.AsAppError(err).Code; code != apperrors.CodeValidationFailed {
		t.Fatalf("error code = %s, want %s: %v", code, apperrors.CodeValidationFailed, err)
	}
}

func TestVerifyRepairDoesNotOverwriteExistingQuarantine(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	valid, err := json.Marshal(Event{
		Timestamp: time.Now().UTC(),
		EventType: "resource.create",
		Operator:  "alice",
		Status:    StatusSuccess,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(append(valid, '\n'), []byte("not json\n")...), 0o600); err != nil {
		t.Fatal(err)
	}

	const sentinel = "existing evidence\n"
	now := time.Now().UTC()
	existing := make([]string, 0, 61)
	for offset := -30; offset <= 30; offset++ {
		candidate := fmt.Sprintf(
			"%s.quarantine.%s.log",
			path,
			now.Add(time.Duration(offset)*time.Second).Format("20060102-150405"),
		)
		if err := os.WriteFile(candidate, []byte(sentinel), 0o600); err != nil {
			t.Fatal(err)
		}
		existing = append(existing, candidate)
	}

	result, err := Verify(path, VerifyOptions{Repair: true, Confirm: true})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if len(result.Files) != 1 || !result.Files[0].Repaired {
		t.Fatalf("Verify() files = %+v, want repaired file", result.Files)
	}
	for _, candidate := range existing {
		if got := mustReadFile(t, candidate); !bytes.Equal(got, []byte(sentinel)) {
			t.Fatalf("Verify() overwrote existing evidence %s: %q", candidate, got)
		}
	}
	if result.Files[0].Quarantine == "" {
		t.Fatal("Verify() quarantine path is empty")
	}
	if got := mustReadFile(t, result.Files[0].Quarantine); !bytes.Contains(got, []byte("not json")) {
		t.Fatalf("new quarantine = %q, want malformed line", got)
	}
}

func TestVerifyWithoutConfirmedRepairCreatesNoRepairArtifacts(t *testing.T) {
	for _, opts := range []VerifyOptions{{}, {Repair: true}} {
		path := filepath.Join(privateTestDir(t), "audit.log")
		before := []byte("not json\n")
		if err := os.WriteFile(path, before, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(path, opts); err != nil {
			t.Fatalf("Verify(%+v) error = %v", opts, err)
		}
		after := mustReadFile(t, path)
		if !bytes.Equal(after, before) {
			t.Fatalf("Verify(%+v) changed active log", opts)
		}
		matches, err := filepath.Glob(path + ".quarantine.*.log")
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 0 {
			t.Fatalf("Verify(%+v) created repair artifacts: %v", opts, matches)
		}
	}
}

func TestAuditScannerAcceptsMaximumSizedLine(t *testing.T) {
	const prefix = `{"value":"`
	const suffix = `"}`
	line := prefix + strings.Repeat("x", maxAuditLineBytes-len(prefix)-len(suffix)) + suffix
	scanner := newAuditScanner(strings.NewReader(line + "\n"))
	if !scanner.Scan() {
		t.Fatalf("Scan() = false, error = %v", scanner.Err())
	}
	if got := len(scanner.Bytes()); got != maxAuditLineBytes {
		t.Fatalf("scanned line size = %d, want %d", got, maxAuditLineBytes)
	}
	scannedAgain := scanner.Scan()
	if scannedAgain || scanner.Err() != nil {
		t.Fatalf("second Scan() = %t, error = %v", scannedAgain, scanner.Err())
	}
}
