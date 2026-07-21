package audit

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

func TestAppendCreatesAuthenticatedV2ChainAndCheckpoint(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	events := []Event{
		{Timestamp: time.Date(2026, 7, 20, 1, 0, 0, 0, time.UTC), EventType: "resource.create", Operator: "alice", Status: StatusSuccess},
		{Timestamp: time.Date(2026, 7, 20, 1, 1, 0, 0, time.UTC), EventType: "resource.update", Operator: "bob", Status: StatusSuccess},
	}
	for _, event := range events {
		if err := Append(path, event); err != nil {
			t.Fatalf("Append() error = %v", err)
		}
	}

	lines := readAuditLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(lines))
	}
	key, err := loadIntegrityKey(defaultIntegrityKeyPath(path))
	if err != nil {
		t.Fatalf("loadIntegrityKey() error = %v", err)
	}
	var previousMAC []byte
	for index, line := range lines {
		env, payload, isEnvelope, parseErr := parseEnvelope([]byte(line))
		if parseErr != nil || !isEnvelope {
			t.Fatalf("parseEnvelope(%d) = (%+v, %t, %v)", index, env, isEnvelope, parseErr)
		}
		if env.APIVersion != envelopeAPIVersion || env.Kind != envelopeKind {
			t.Fatalf("envelope identity = %s/%s", env.APIVersion, env.Kind)
		}
		if env.Sequence != uint64(index+1) {
			t.Fatalf("sequence = %d, want %d", env.Sequence, index+1)
		}
		prevMAC, mac, verifyErr := verifyEnvelope(env, payload, key)
		if verifyErr != nil {
			t.Fatalf("verifyEnvelope(%d) error = %v", index, verifyErr)
		}
		if !bytes.Equal(prevMAC, previousMAC) {
			t.Fatalf("previous MAC %d does not link to predecessor", index)
		}
		previousMAC = mac
	}

	checkpoint, exists, err := loadCheckpoint(path, key)
	if err != nil || !exists {
		t.Fatalf("loadCheckpoint() = (%+v, %t, %v)", checkpoint, exists, err)
	}
	headSequence, headMAC, err := checkpointHead(checkpoint)
	if err != nil {
		t.Fatalf("checkpointHead() error = %v", err)
	}
	if headSequence != 2 || !bytes.Equal(headMAC, previousMAC) {
		t.Fatalf("checkpoint head = (%d, %x), want (2, %x)", headSequence, headMAC, previousMAC)
	}
	for _, artifact := range []string{path, defaultIntegrityKeyPath(path), checkpointPath(path)} {
		if err := verifyOwnerOnlyFile(artifact); err != nil {
			t.Fatalf("verifyOwnerOnlyFile(%s) error = %v", artifact, err)
		}
	}

	query, err := Query(path, Filter{})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(query.Events) != 2 || query.Events[0].Operator != "alice" || query.Events[1].Operator != "bob" {
		t.Fatalf("Query() events = %+v", query.Events)
	}
	verify, err := Verify(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if verify.Authenticated != 2 || verify.HasProblems() {
		t.Fatalf("Verify() = %+v, want two authenticated records without problems", verify)
	}
}

func TestQueryAndVerifyRejectTamperedAuthenticatedPayload(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	for _, operator := range []string{"alice", "bob"} {
		if err := Append(path, Event{EventType: "resource.update", Operator: operator, Status: StatusSuccess}); err != nil {
			t.Fatalf("Append() error = %v", err)
		}
	}
	lines := readAuditLines(t, path)
	lines[0] = strings.Replace(lines[0], `"operator":"alice"`, `"operator":"mallory"`, 1)
	writeAuditLines(t, path, lines)

	if _, err := Query(path, Filter{}); err == nil {
		t.Fatal("Query() error = nil, want authenticated payload failure")
	}
	result, err := Verify(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.IntegrityErrors == 0 || !result.HasProblems() {
		t.Fatalf("Verify() = %+v, want integrity problem", result)
	}
}

func TestEnvelopeIdentityAndShapeTamperingCannotDowngradeToV1(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(string) string
	}{
		{
			name: "both identity markers changed",
			mutate: func(line string) string {
				line = strings.Replace(line, envelopeAPIVersion, "attacker.invalid/audit/v1", 1)
				return strings.Replace(line, envelopeKind, "LegacyEvent", 1)
			},
		},
		{
			name: "duplicate authenticated field",
			mutate: func(line string) string {
				return strings.Replace(line, `"sequence":1`, `"sequence":1,"sequence":1`, 1)
			},
		},
		{
			name: "unknown outer metadata",
			mutate: func(line string) string {
				return strings.Replace(line, `"kind":"AuditEnvelope"`, `"kind":"AuditEnvelope","trusted":true`, 1)
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(privateTestDir(t), "audit.log")
			if err := Append(path, Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess}); err != nil {
				t.Fatalf("Append() error = %v", err)
			}
			lines := readAuditLines(t, path)
			lines[0] = testCase.mutate(lines[0])
			writeAuditLines(t, path, lines)

			if _, err := Query(path, Filter{}); err == nil {
				t.Fatal("Query() error = nil, want envelope rejection")
			}
			result, err := Verify(path, VerifyOptions{})
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if result.IntegrityErrors == 0 || !result.HasProblems() {
				t.Fatalf("Verify() = %+v, want explicit integrity error", result)
			}
		})
	}
}

func TestDuplicateEnvelopeIdentityMarkersCannotDowngradeToV1(t *testing.T) {
	line := []byte(
		`{"apiVersion":"opskit-core.io/audit/v2","apiVersion":"foreign.io/v1",` +
			`"kind":"AuditEnvelope","kind":"LegacyEvent","eventType":"resource.create"}`,
	)
	_, _, isEnvelope, err := parseEnvelope(line)
	if !isEnvelope || err == nil {
		t.Fatalf("parseEnvelope() = (isEnvelope=%t, err=%v), want strict envelope rejection", isEnvelope, err)
	}
}

func TestVerifyDetectsTailTruncationAndAppendFailsClosed(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	for index := range 3 {
		if err := Append(path, Event{EventType: "resource.update", Operator: "alice", Reason: string(rune('a' + index)), Status: StatusSuccess}); err != nil {
			t.Fatalf("Append(%d) error = %v", index, err)
		}
	}
	lines := readAuditLines(t, path)
	writeAuditLines(t, path, lines[:len(lines)-1])
	beforeLog := mustReadFile(t, path)
	beforeCheckpoint := mustReadFile(t, checkpointPath(path))

	result, err := Verify(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !result.TruncationDetected || result.CheckpointViolations == 0 || !result.HasProblems() {
		t.Fatalf("Verify() = %+v, want checkpoint-backed truncation", result)
	}
	assertValidationError(t, Append(path, Event{EventType: "resource.update", Operator: "bob", Status: StatusSuccess}))
	if got := mustReadFile(t, path); !bytes.Equal(got, beforeLog) {
		t.Fatal("Append() changed truncated audit log")
	}
	if got := mustReadFile(t, checkpointPath(path)); !bytes.Equal(got, beforeCheckpoint) {
		t.Fatal("Append() changed checkpoint after truncation")
	}
}

func TestAppendRecoversExactlyOneSyncedRecordAfterCheckpointLag(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	if err := Append(path, Event{EventType: "resource.create", Operator: "first", Status: StatusSuccess}); err != nil {
		t.Fatalf("first Append() error = %v", err)
	}
	checkpointAfterFirst := mustReadFile(t, checkpointPath(path))
	if err := Append(path, Event{EventType: "resource.update", Operator: "second", Status: StatusSuccess}); err != nil {
		t.Fatalf("second Append() error = %v", err)
	}
	if err := os.WriteFile(checkpointPath(path), checkpointAfterFirst, 0o600); err != nil {
		t.Fatalf("restore lagging checkpoint: %v", err)
	}

	if err := Append(path, Event{EventType: "resource.update", Operator: "third", Status: StatusSuccess}); err != nil {
		t.Fatalf("Append() did not recover one-record checkpoint lag: %v", err)
	}
	query, err := Query(path, Filter{})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(query.Events) != 3 ||
		query.Events[0].Operator != "first" ||
		query.Events[1].Operator != "second" ||
		query.Events[2].Operator != "third" {
		t.Fatalf("Query() events = %+v", query.Events)
	}
	verify, err := Verify(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if verify.Authenticated != 3 || verify.HasProblems() {
		t.Fatalf("Verify() = %+v, want recovered clean chain", verify)
	}
}

func TestAppendRecoversFirstSyncedRecordFromGenesisCheckpoint(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	if err := Append(path, Event{EventType: "resource.create", Operator: "first", Status: StatusSuccess}); err != nil {
		t.Fatalf("first Append() error = %v", err)
	}
	key, err := loadIntegrityKey(defaultIntegrityKeyPath(path))
	if err != nil {
		t.Fatalf("loadIntegrityKey() error = %v", err)
	}
	if err := writeCheckpoint(path, makeCheckpoint(key, 0, nil, 0, nil)); err != nil {
		t.Fatalf("write genesis checkpoint: %v", err)
	}

	if err := Append(path, Event{EventType: "resource.update", Operator: "second", Status: StatusSuccess}); err != nil {
		t.Fatalf("Append() did not recover first-record checkpoint lag: %v", err)
	}
	query, err := Query(path, Filter{})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(query.Events) != 2 || query.Events[0].Operator != "first" || query.Events[1].Operator != "second" {
		t.Fatalf("Query() events = %+v", query.Events)
	}
}

func TestAppendRejectsCheckpointLagByMoreThanOneRecord(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	if err := Append(path, Event{EventType: "resource.create", Operator: "first", Status: StatusSuccess}); err != nil {
		t.Fatalf("first Append() error = %v", err)
	}
	checkpointAfterFirst := mustReadFile(t, checkpointPath(path))
	for _, operator := range []string{"second", "third"} {
		if err := Append(path, Event{EventType: "resource.update", Operator: operator, Status: StatusSuccess}); err != nil {
			t.Fatalf("Append(%s) error = %v", operator, err)
		}
	}
	if err := os.WriteFile(checkpointPath(path), checkpointAfterFirst, 0o600); err != nil {
		t.Fatalf("restore lagging checkpoint: %v", err)
	}
	beforeLog := mustReadFile(t, path)
	beforeCheckpoint := mustReadFile(t, checkpointPath(path))

	assertValidationError(t, Append(path, Event{EventType: "resource.update", Operator: "fourth", Status: StatusSuccess}))
	if got := mustReadFile(t, path); !bytes.Equal(got, beforeLog) {
		t.Fatal("Append() changed log after multi-record checkpoint lag")
	}
	if got := mustReadFile(t, checkpointPath(path)); !bytes.Equal(got, beforeCheckpoint) {
		t.Fatal("Append() changed multi-record-lag checkpoint")
	}
}

func TestVerifyDetectsMiddleDeletionAndReplay(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func([]string) []string
	}{
		{
			name: "middle deletion",
			mutate: func(lines []string) []string {
				return append(lines[:1], lines[2:]...)
			},
		},
		{
			name: "replay",
			mutate: func(lines []string) []string {
				return append(lines[:2], lines[1:]...)
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(privateTestDir(t), "audit.log")
			for index := range 3 {
				if err := Append(path, Event{EventType: "resource.update", Operator: "alice", Reason: string(rune('a' + index)), Status: StatusSuccess}); err != nil {
					t.Fatalf("Append(%d) error = %v", index, err)
				}
			}
			writeAuditLines(t, path, testCase.mutate(readAuditLines(t, path)))
			result, err := Verify(path, VerifyOptions{})
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if result.SequenceViolations == 0 || !result.HasProblems() {
				t.Fatalf("Verify() = %+v, want sequence violation", result)
			}
		})
	}
}

func TestV1BeforeV2IsReadableButV1AfterV2IsDowngrade(t *testing.T) {
	t.Run("migration", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "audit.log")
		legacy := Event{
			Timestamp: time.Date(2026, 7, 20, 1, 0, 0, 0, time.UTC),
			EventType: "resource.create",
			Operator:  "legacy",
			Status:    StatusSuccess,
		}
		legacyJSON, err := json.Marshal(legacy)
		if err != nil {
			t.Fatal(err)
		}
		writeAuditLines(t, path, []string{string(legacyJSON)})
		if err := Append(path, Event{
			Timestamp: time.Date(2026, 7, 20, 1, 1, 0, 0, time.UTC),
			EventType: "resource.update",
			Operator:  "v2",
			Status:    StatusSuccess,
		}); err != nil {
			t.Fatalf("Append() error = %v", err)
		}
		query, err := Query(path, Filter{})
		if err != nil {
			t.Fatalf("Query() error = %v", err)
		}
		if len(query.Events) != 2 || query.Events[0].Operator != "legacy" || query.Events[1].Operator != "v2" {
			t.Fatalf("Query() events = %+v", query.Events)
		}
		verify, err := Verify(path, VerifyOptions{})
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if verify.LegacyUnauthenticated != 1 || verify.Authenticated != 1 || verify.HasProblems() {
			t.Fatalf("Verify() = %+v, want clean v1-to-v2 migration", verify)
		}
	})

	t.Run("downgrade", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "audit.log")
		if err := Append(path, Event{EventType: "resource.create", Operator: "v2", Status: StatusSuccess}); err != nil {
			t.Fatalf("Append() error = %v", err)
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // Test-controlled path.
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := file.WriteString(`{"timestamp":"2026-07-20T01:00:00Z","eventType":"resource.update","operator":"legacy"}` + "\n")
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatalf("append legacy line = (%v, %v)", writeErr, closeErr)
		}
		if _, err := Query(path, Filter{}); err == nil {
			t.Fatal("Query() error = nil, want downgrade rejection")
		}
		result, err := Verify(path, VerifyOptions{})
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if result.IntegrityErrors == 0 || !result.HasProblems() {
			t.Fatalf("Verify() = %+v, want downgrade problem", result)
		}
		before := mustReadFile(t, path)
		assertValidationError(t, Append(path, Event{EventType: "resource.update", Operator: "bob", Status: StatusSuccess}))
		if got := mustReadFile(t, path); !bytes.Equal(got, before) {
			t.Fatal("Append() changed downgraded history")
		}
	})
}

func TestMissingOrTamperedIntegrityArtifactsFailClosed(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{
			name: "missing checkpoint",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Remove(checkpointPath(path)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing key",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Remove(defaultIntegrityKeyPath(path)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "tampered checkpoint",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				data := mustReadFile(t, checkpointPath(path))
				data = bytes.Replace(data, []byte(`"headSequence":1`), []byte(`"headSequence":9`), 1)
				if err := os.WriteFile(checkpointPath(path), data, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(privateTestDir(t), "audit.log")
			if err := Append(path, Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess}); err != nil {
				t.Fatalf("Append() error = %v", err)
			}
			testCase.mutate(t, path)
			if _, err := Query(path, Filter{}); err == nil {
				t.Fatal("Query() error = nil, want integrity artifact failure")
			}
			result, err := Verify(path, VerifyOptions{})
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if !result.HasProblems() {
				t.Fatalf("Verify() = %+v, want reported integrity problem", result)
			}
			assertValidationError(t, Append(path, Event{EventType: "resource.update", Operator: "bob", Status: StatusSuccess}))
			if testCase.name == "missing key" {
				if _, err := os.Stat(defaultIntegrityKeyPath(path)); !errorsIsNotExist(err) {
					t.Fatalf("Append() recreated missing key: %v", err)
				}
			}
		})
	}
}

func TestVerifyAuthenticatesEncryptedV2WithoutDecrypting(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	_, publicKeyPath := writeTestAgePublicKey(t)
	if err := AppendWithOptions(
		path,
		Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess},
		Options{EncryptPublicKeyPath: publicKeyPath},
	); err != nil {
		t.Fatalf("AppendWithOptions() error = %v", err)
	}
	result, err := Verify(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Authenticated != 1 || result.EncryptedOpaque != 1 || result.Valid != 1 || result.HasProblems() {
		t.Fatalf("Verify() = %+v, want authenticated opaque record", result)
	}
}

func TestLegacyAgeBeforeV2RemainsReadable(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	identity, publicKeyPath := writeTestAgePublicKey(t)
	legacy := Event{
		Timestamp: time.Date(2026, 7, 20, 1, 0, 0, 0, time.UTC),
		EventType: "resource.create",
		Operator:  "legacy-age",
		Status:    StatusSuccess,
	}
	plain, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := encryptAuditPayload(plain, publicKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	writeAuditLines(t, path, []string{base64.StdEncoding.EncodeToString(ciphertext)})
	if err := Append(path, Event{
		Timestamp: time.Date(2026, 7, 20, 1, 1, 0, 0, time.UTC),
		EventType: "resource.update",
		Operator:  "v2",
		Status:    StatusSuccess,
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	query, err := Query(path, Filter{PrivateKey: identity.String()})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(query.Events) != 2 || query.Events[0].Operator != "legacy-age" {
		t.Fatalf("Query() events = %+v", query.Events)
	}
	verify, err := Verify(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if verify.LegacyUnauthenticated != 1 || verify.EncryptedOpaque != 1 || verify.Authenticated != 1 || verify.HasProblems() {
		t.Fatalf("Verify() = %+v, want opaque legacy plus authenticated v2", verify)
	}
}

func TestRepairRejectsV2WithoutChangingArtifacts(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	if err := Append(path, Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	paths := []string{path, defaultIntegrityKeyPath(path), checkpointPath(path)}
	before := make(map[string][]byte, len(paths))
	for _, artifact := range paths {
		before[artifact] = mustReadFile(t, artifact)
	}
	assertValidationError(t, func() error {
		_, err := Verify(path, VerifyOptions{Repair: true, Confirm: true})
		return err
	}())
	for _, artifact := range paths {
		if got := mustReadFile(t, artifact); !bytes.Equal(got, before[artifact]) {
			t.Fatalf("Verify(Repair) changed %s", artifact)
		}
	}
}

func TestIntegrityKeyOverrideIsRequiredByReaders(t *testing.T) {
	dir := privateTestDir(t)
	path := filepath.Join(dir, "audit.log")
	keyPath := filepath.Join(dir, "custom-integrity.key")
	if err := AppendWithOptions(
		path,
		Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess},
		Options{IntegrityKeyPath: keyPath},
	); err != nil {
		t.Fatalf("AppendWithOptions() error = %v", err)
	}
	if _, err := os.Stat(defaultIntegrityKeyPath(path)); !errorsIsNotExist(err) {
		t.Fatalf("default key unexpectedly exists: %v", err)
	}
	if _, err := Query(path, Filter{}); err == nil {
		t.Fatal("Query() without key override error = nil")
	}
	if _, err := Query(path, Filter{IntegrityKeyPath: keyPath}); err != nil {
		t.Fatalf("Query() with key override error = %v", err)
	}
	result, err := Verify(path, VerifyOptions{IntegrityKeyPath: keyPath})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Authenticated != 1 || result.HasProblems() {
		t.Fatalf("Verify() = %+v", result)
	}
}

func TestKeyOnlyFirstAppendRecovery(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	err := AppendRecord(path, make(chan int), Options{})
	if err == nil {
		t.Fatal("AppendRecord(chan) error = nil")
	}
	if _, err := os.Stat(defaultIntegrityKeyPath(path)); err != nil {
		t.Fatalf("integrity key was not retained after pre-write marshal failure: %v", err)
	}
	if _, err := os.Stat(checkpointPath(path)); !errorsIsNotExist(err) {
		t.Fatalf("checkpoint unexpectedly exists: %v", err)
	}
	if err := Append(path, Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess}); err != nil {
		t.Fatalf("recovery Append() error = %v", err)
	}
}

func TestRotatedFilesUseStrictNumericOrder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	valid := []string{
		path + ".20260720-010203.log",
		path + ".20260720-010203.2.log",
		path + ".20260720-010203.10.log",
	}
	invalid := []string{
		path + ".20260720-010203.0.log",
		path + ".20260720-010203.01.log",
		path + ".20260720-010203.1.extra.log",
		path + ".20260720-010203.tmp.log",
		path + ".quarantine.20260720-010203.log",
	}
	for _, candidate := range append(valid, invalid...) {
		if err := os.WriteFile(candidate, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := RotatedFiles(path)
	if err != nil {
		t.Fatalf("RotatedFiles() error = %v", err)
	}
	if len(got) != len(valid) {
		t.Fatalf("RotatedFiles() = %v, want %v", got, valid)
	}
	for index := range valid {
		if got[index] != valid[index] {
			t.Fatalf("RotatedFiles()[%d] = %s, want %s", index, got[index], valid[index])
		}
	}
	otherDirCandidate := filepath.Join(t.TempDir(), filepath.Base(valid[0]))
	if _, ok := RotatedFileTimestamp(path, otherDirCandidate); ok {
		t.Fatal("RotatedFileTimestamp() accepted candidate from another directory")
	}
}

func readAuditLines(t *testing.T, path string) []string {
	t.Helper()
	data := mustReadFile(t, path)
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

func writeAuditLines(t *testing.T, path string, lines []string) {
	t.Helper()
	data := []byte(strings.Join(lines, "\n") + "\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // Test-controlled path.
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	return data
}

func assertValidationError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("error = nil, want validation failure")
	}
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeValidationFailed {
		t.Fatalf("error code = %s, want %s: %v", got, apperrors.CodeValidationFailed, err)
	}
}

func errorsIsNotExist(err error) bool {
	return err != nil && os.IsNotExist(err)
}
