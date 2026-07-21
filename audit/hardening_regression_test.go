package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/lockfile"
)

func TestAppendFramesLegacyLineWithoutTrailingNewline(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	legacy := Event{
		Timestamp: time.Date(2026, 7, 20, 1, 0, 0, 0, time.UTC),
		EventType: "resource.create",
		Operator:  "legacy",
		Status:    StatusSuccess,
	}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Append(path, Event{
		Timestamp: time.Date(2026, 7, 20, 1, 1, 0, 0, time.UTC),
		EventType: "resource.update",
		Operator:  "v2",
		Status:    StatusSuccess,
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	stored := mustReadFile(t, path)
	if bytes.Contains(stored, []byte("}"+`{"apiVersion"`)) {
		t.Fatal("Append() concatenated records without a JSONL delimiter")
	}
	query, err := Query(path, Filter{})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(query.Events) != 2 || query.Events[0].Operator != "legacy" || query.Events[1].Operator != "v2" {
		t.Fatalf("Query() events = %+v", query.Events)
	}
}

func TestAppendRecoversCheckpointAndFramesV2WithoutTrailingNewline(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	if err := Append(path, Event{EventType: "resource.create", Operator: "first", Status: StatusSuccess}); err != nil {
		t.Fatalf("first Append() error = %v", err)
	}
	data := bytes.TrimSuffix(mustReadFile(t, path), []byte{'\n'})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := loadIntegrityKey(defaultIntegrityKeyPath(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeCheckpoint(path, makeCheckpoint(key, 0, nil, 0, nil)); err != nil {
		t.Fatal(err)
	}

	if err := Append(path, Event{EventType: "resource.update", Operator: "second", Status: StatusSuccess}); err != nil {
		t.Fatalf("recovery Append() error = %v", err)
	}
	lines := readAuditLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("audit line count = %d, want 2", len(lines))
	}
	result, err := Verify(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Authenticated != 2 || result.HasProblems() {
		t.Fatalf("Verify() = %+v, want clean recovered chain", result)
	}
}

func TestStrictAuditJSONRejectsCaseAliasesAndSemanticDuplicates(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, integrityKeySize)
	line, _, err := encodeEnvelope(
		Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess},
		"",
		key,
		1,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, testCase := range []struct {
		name   string
		mutate func(string) string
	}{
		{
			name: "single case alias",
			mutate: func(value string) string {
				return strings.Replace(value, `"apiVersion"`, `"APIVERSION"`, 1)
			},
		},
		{
			name: "semantic duplicate",
			mutate: func(value string) string {
				return strings.Replace(
					value,
					`"apiVersion":"`+envelopeAPIVersion+`"`,
					`"apiVersion":"`+envelopeAPIVersion+`","APIVERSION":"`+envelopeAPIVersion+`"`,
					1,
				)
			},
		},
		{
			name: "unicode simple fold alias",
			mutate: func(value string) string {
				return strings.Replace(value, `"sequence"`, `"ſequence"`, 1)
			},
		},
		{
			name: "unicode simple fold semantic duplicate",
			mutate: func(value string) string {
				return strings.Replace(value, `"sequence":1`, `"sequence":1,"ſequence":1`, 1)
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, _, isEnvelope, parseErr := parseEnvelope([]byte(testCase.mutate(string(line))))
			if !isEnvelope || parseErr == nil {
				t.Fatalf("parseEnvelope() = (isEnvelope=%t, err=%v), want classified rejection", isEnvelope, parseErr)
			}
		})
	}

	for _, target := range []any{&integrityKeyFile{}, &auditCheckpoint{}} {
		if err := strictDecodeObject([]byte(`{"apiVersion":"x","APIVERSION":"x"}`), target); err == nil {
			t.Fatalf("strictDecodeObject(%T) accepted semantic duplicate", target)
		}
		if err := strictDecodeObject([]byte(`{"APIVERSION":"x"}`), target); err == nil {
			t.Fatalf("strictDecodeObject(%T) accepted non-canonical alias", target)
		}
		if err := strictDecodeObject([]byte(`{"kind":"x","Kind":"x"}`), target); err == nil {
			t.Fatalf("strictDecodeObject(%T) accepted Unicode simple-fold duplicate", target)
		}
		if err := strictDecodeObject([]byte(`{"Kind":"x"}`), target); err == nil {
			t.Fatalf("strictDecodeObject(%T) accepted Unicode simple-fold alias", target)
		}
	}
}

func TestReadersRejectInsecureActiveAndRotatedFiles(t *testing.T) {
	for _, rotated := range []bool{false, true} {
		name := "active"
		if rotated {
			name = "rotated"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(privateTestDir(t), "audit.log")
			if err := Append(path, Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess}); err != nil {
				t.Fatal(err)
			}
			target := path
			if rotated {
				target = path + ".20260720-010203.log"
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
			}
			makeTestAuditFileInsecure(t, target)
			if _, err := Query(path, Filter{}); err == nil {
				t.Fatal("Query() error = nil, want insecure-file rejection")
			}
			if _, err := Verify(path, VerifyOptions{}); err == nil {
				t.Fatal("Verify() error = nil, want insecure-file rejection")
			}
		})
	}
}

func TestIntegrityArtifactsRejectOversizedFiles(t *testing.T) {
	for _, artifact := range []string{"key", "checkpoint"} {
		t.Run(artifact, func(t *testing.T) {
			path := filepath.Join(privateTestDir(t), "audit.log")
			if err := Append(path, Event{EventType: "resource.create", Operator: "alice", Status: StatusSuccess}); err != nil {
				t.Fatal(err)
			}
			target := defaultIntegrityKeyPath(path)
			limit := maxIntegrityKeyFileBytes
			if artifact == "checkpoint" {
				target = checkpointPath(path)
				limit = maxCheckpointFileBytes
			}
			if err := os.WriteFile(target, bytes.Repeat([]byte{'x'}, limit+1), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Query(path, Filter{}); err == nil {
				t.Fatal("Query() error = nil, want oversized artifact rejection")
			}
		})
	}
}

func TestAuthenticatedBaseRejectsLegacyDowngrade(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	for _, operator := range []string{"first", "second"} {
		if err := Append(path, Event{EventType: "resource.update", Operator: operator, Status: StatusSuccess}); err != nil {
			t.Fatal(err)
		}
	}
	key, err := loadIntegrityKey(defaultIntegrityKeyPath(path))
	if err != nil {
		t.Fatal(err)
	}
	lines := readAuditLines(t, path)
	env, payload, isEnvelope, err := parseEnvelope([]byte(lines[len(lines)-1]))
	if err != nil || !isEnvelope {
		t.Fatalf("parseEnvelope() = (%t, %v)", isEnvelope, err)
	}
	_, baseMAC, err := verifyEnvelope(env, payload, key)
	if err != nil {
		t.Fatal(err)
	}
	baseCheckpoint := makeCheckpoint(key, env.Sequence, baseMAC, env.Sequence, baseMAC)
	if err := writeCheckpoint(path, baseCheckpoint); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Append(path, Event{EventType: "resource.update", Operator: "third", Status: StatusSuccess}); err != nil {
		t.Fatalf("Append() after authenticated base error = %v", err)
	}
	clean, err := Verify(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify() after authenticated base error = %v", err)
	}
	if clean.Authenticated != 1 || clean.HasProblems() {
		t.Fatalf("Verify() after authenticated base = %+v, want one clean continuation", clean)
	}

	if err := writeCheckpoint(path, baseCheckpoint); err != nil {
		t.Fatal(err)
	}
	legacy := `{"timestamp":"2026-07-20T01:00:00Z","eventType":"resource.update","operator":"legacy"}`
	if err := os.WriteFile(path, []byte(legacy+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Query(path, Filter{}); err == nil {
		t.Fatal("Query() error = nil, want post-base legacy rejection")
	}
	verify, err := Verify(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if verify.IntegrityErrors == 0 || !verify.HasProblems() {
		t.Fatalf("Verify() = %+v, want downgrade problem", verify)
	}
	assertValidationError(t, Append(path, Event{EventType: "resource.update", Operator: "fourth", Status: StatusSuccess}))
}

func TestRotationOrdinalOverflowFailsClosed(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	now := time.Date(2026, 7, 20, 1, 2, 3, 0, time.UTC)
	exhausted := fmt.Sprintf("%s.%s.%d.log", path, now.Format("20060102-150405"), uint64(math.MaxUint64))
	if err := os.WriteFile(exhausted, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := nextRotatedPath(path, now); err == nil ||
		apperrors.AsAppError(err).Code != apperrors.CodeConflict {
		t.Fatalf("nextRotatedPath() error = %v, want conflict", err)
	}
}

func TestVerifyRejectsOversizedLockStatus(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "audit.log")
	lock := lockfile.New(path)
	if err := lock.Acquire(); err != nil {
		t.Fatal(err)
	}
	lockPath := path + ".lock"
	t.Cleanup(func() { _ = os.Remove(lockPath) })
	if err := os.WriteFile(lockPath, bytes.Repeat([]byte{'x'}, 4*1024+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(path, VerifyOptions{}); err == nil {
		t.Fatal("Verify() error = nil, want invalid lock rejection")
	}
}

func TestConcurrentAppendMaintainsSingleAuthenticatedChain(t *testing.T) {
	t.Setenv("OPSKIT_LOCK_TIMEOUT", "30s")
	path := filepath.Join(privateTestDir(t), "audit.log")
	const writers = 32
	timestamp := time.Date(2026, 7, 20, 1, 2, 3, 0, time.UTC)
	start := make(chan struct{})
	errs := make(chan error, writers)
	var wait sync.WaitGroup
	wait.Add(writers)
	for index := range writers {
		go func() {
			defer wait.Done()
			<-start
			errs <- Append(path, Event{
				Timestamp: timestamp,
				EventType: "resource.update",
				Operator:  fmt.Sprintf("writer-%02d", index),
				Status:    StatusSuccess,
			})
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Append() error = %v", err)
		}
	}
	result, err := Verify(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.Authenticated != writers || result.Total != writers || result.HasProblems() {
		t.Fatalf("Verify() = %+v, want %d clean authenticated records", result, writers)
	}
}

func BenchmarkAppendAuthenticated(b *testing.B) {
	path := filepath.Join(privateTestDir(b), "audit.log")
	event := Event{
		Timestamp: time.Date(2026, 7, 20, 1, 2, 3, 0, time.UTC),
		EventType: "resource.update",
		Operator:  "benchmark",
		Status:    StatusSuccess,
	}
	b.ResetTimer()
	for range b.N {
		if err := Append(path, event); err != nil {
			b.Fatal(err)
		}
	}
}
