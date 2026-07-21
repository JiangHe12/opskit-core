package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

func TestPruneRotatedFilesAdvancesCheckpointBeforeDeleting(t *testing.T) {
	path, rotated := createAuthenticatedPruneHistory(t, 5)
	candidates := append([]string(nil), rotated[:2]...)
	checkpointBefore := mustReadFile(t, checkpointPath(path))

	preview, err := PruneRotatedFiles(path, candidates, PruneOptions{})
	if err != nil {
		t.Fatalf("PruneRotatedFiles(preview) error = %v", err)
	}
	if preview.Started || len(preview.DeletedFiles) != 0 ||
		preview.CheckpointState != PruneCheckpointUnchanged {
		t.Fatalf("preview = %+v", preview)
	}
	if got := mustReadFile(t, checkpointPath(path)); !bytes.Equal(got, checkpointBefore) {
		t.Fatal("preview changed checkpoint")
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err != nil {
			t.Fatalf("preview removed %s: %v", candidate, err)
		}
	}

	key, err := loadIntegrityKey(defaultIntegrityKeyPath(path))
	if err != nil {
		t.Fatalf("loadIntegrityKey() error = %v", err)
	}
	wantRange, err := inspectPruneEnvelopeRange(candidates, key)
	if err != nil {
		t.Fatalf("inspectPruneEnvelopeRange() error = %v", err)
	}
	result, err := PruneRotatedFiles(path, candidates, PruneOptions{Confirm: true})
	if err != nil {
		t.Fatalf("PruneRotatedFiles(confirm) error = %v", err)
	}
	if !result.Started || result.CheckpointState != PruneCheckpointAdvanced ||
		!reflect.DeepEqual(result.DeletedFiles, candidates) {
		t.Fatalf("result = %+v", result)
	}
	checkpoint := mustLoadPruneCheckpoint(t, path, key)
	baseSequence, baseMAC, err := checkpointBase(checkpoint)
	if err != nil {
		t.Fatalf("checkpointBase() error = %v", err)
	}
	if baseSequence != wantRange.lastSequence || !hmacEqual(baseMAC, wantRange.lastMAC) {
		t.Fatalf("checkpoint base = (%d, %x), want (%d, %x)", baseSequence, baseMAC, wantRange.lastSequence, wantRange.lastMAC)
	}
	verified, err := Verify(path, VerifyOptions{})
	if err != nil || verified.HasProblems() || verified.Total != 3 {
		t.Fatalf("Verify() = (%+v, %v), want three retained clean records", verified, err)
	}
}

func TestPruneRotatedFilesRequiresCurrentOldestPrefix(t *testing.T) {
	tests := []struct {
		name       string
		candidates func([]string) []string
	}{
		{name: "skips oldest", candidates: func(files []string) []string { return []string{files[1]} }},
		{name: "reordered", candidates: func(files []string) []string { return []string{files[1], files[0]} }},
		{name: "duplicate", candidates: func(files []string) []string { return []string{files[0], files[0]} }},
		{name: "invented strict name", candidates: func(files []string) []string {
			return []string{files[0] + ".20260101-000000.log"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path, rotated := createAuthenticatedPruneHistory(t, 4)
			checkpointBefore := mustReadFile(t, checkpointPath(path))
			result, err := PruneRotatedFiles(
				path,
				test.candidates(rotated),
				PruneOptions{Confirm: true},
			)
			if err == nil || apperrors.AsAppError(err).Code != apperrors.CodeConflict {
				t.Fatalf("PruneRotatedFiles() = (%+v, %v), want conflict", result, err)
			}
			if result.Started || len(result.DeletedFiles) != 0 {
				t.Fatalf("result = %+v, want no mutation", result)
			}
			if got := mustReadFile(t, checkpointPath(path)); !bytes.Equal(got, checkpointBefore) {
				t.Fatal("invalid candidate selection changed checkpoint")
			}
			assertFilesExist(t, rotated)
		})
	}
}

func TestPruneRotatedFilesRejectsUnknownRotationNamespaceEntries(t *testing.T) {
	suffixes := []string{
		".not-a-timestamp.log",
		".20260721-010203.0.log",
		".20260721-010203.01.log",
		".20260721-010203.-1.log",
		".20260721-010203.extra.log",
		".quarantine.not-a-timestamp.log",
		".quarantine.20260721-010203.0.log",
	}
	for _, suffix := range suffixes {
		t.Run(suffix, func(t *testing.T) {
			path, rotated := createAuthenticatedPruneHistory(t, 4)
			suspicious := path + suffix
			if err := writeOwnerOnlyExclusive(suspicious, []byte("suspicious\n")); err != nil {
				t.Fatalf("write suspicious namespace entry: %v", err)
			}
			checkpointBefore := mustReadFile(t, checkpointPath(path))
			result, err := PruneRotatedFiles(path, rotated[:1], PruneOptions{Confirm: true})
			if err == nil || apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
				t.Fatalf("PruneRotatedFiles() = (%+v, %v), want validation failure", result, err)
			}
			if result.Started || len(result.DeletedFiles) != 0 {
				t.Fatalf("result = %+v, want no mutation", result)
			}
			if got := mustReadFile(t, checkpointPath(path)); !bytes.Equal(got, checkpointBefore) {
				t.Fatal("unknown namespace entry changed checkpoint")
			}
			assertFilesExist(t, append(rotated, suspicious))
		})
	}
}

func TestPruneRotatedFilesAllowsKnownQuarantineAndRepairStagingNames(t *testing.T) {
	path, rotated := createAuthenticatedPruneHistory(t, 4)
	quarantine := path + ".quarantine.20260721-010203.log"
	repairTemp := path + ".repair-new-12345"
	for _, artifact := range []string{quarantine, repairTemp} {
		if err := writeOwnerOnlyExclusive(artifact, []byte("evidence\n")); err != nil {
			t.Fatalf("write known artifact %s: %v", artifact, err)
		}
	}
	result, err := PruneRotatedFiles(path, rotated[:1], PruneOptions{Confirm: true})
	if err != nil {
		t.Fatalf("PruneRotatedFiles() error = %v", err)
	}
	if !reflect.DeepEqual(result.DeletedFiles, rotated[:1]) {
		t.Fatalf("DeletedFiles = %v, want %v", result.DeletedFiles, rotated[:1])
	}
	assertFilesExist(t, []string{quarantine, repairTemp})
}

func TestPruneRotatedFilesFailsClosedOnTampering(t *testing.T) {
	path, rotated := createAuthenticatedPruneHistory(t, 4)
	candidate := rotated[0]
	data := mustReadFile(t, candidate)
	tampered := bytes.Replace(data, []byte(`"operator":"operator-0"`), []byte(`"operator":"attacker-0"`), 1)
	if bytes.Equal(tampered, data) {
		t.Fatal("test did not alter the authenticated payload")
	}
	if err := os.WriteFile(candidate, tampered, 0o600); err != nil {
		t.Fatalf("tamper candidate: %v", err)
	}
	checkpointBefore := mustReadFile(t, checkpointPath(path))
	result, err := PruneRotatedFiles(path, []string{candidate}, PruneOptions{Confirm: true})
	if err == nil || apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("PruneRotatedFiles() = (%+v, %v), want validation failure", result, err)
	}
	if result.Started || len(result.DeletedFiles) != 0 {
		t.Fatalf("result = %+v, want no mutation", result)
	}
	if got := mustReadFile(t, checkpointPath(path)); !bytes.Equal(got, checkpointBefore) {
		t.Fatal("tampered history changed checkpoint")
	}
	assertFilesExist(t, rotated)
}

func TestPruneRotatedFilesRejectsLegacyDuplicateTopLevelKeys(t *testing.T) {
	directory := privateTestDir(t)
	path := filepath.Join(directory, "audit.log")
	rotated := path + ".20260101-000000.log"
	duplicate := []byte(`{"timestamp":"2026-07-21T01:00:00Z","eventType":"x","eventType":"y","operator":"tester"}` + "\n")
	if err := writeOwnerOnlyExclusive(rotated, duplicate); err != nil {
		t.Fatalf("write duplicate-key rotation: %v", err)
	}
	writeLegacyPruneFile(t, path, 1)

	verified, err := Verify(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if verified.Malformed == 0 || !verified.HasProblems() {
		t.Fatalf("Verify() = %+v, want duplicate-key problem", verified)
	}
	result, err := PruneRotatedFiles(path, []string{rotated}, PruneOptions{Confirm: true})
	if err == nil || apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("PruneRotatedFiles() = (%+v, %v), want validation failure", result, err)
	}
	if result.Started || len(result.DeletedFiles) != 0 {
		t.Fatalf("result = %+v, want no mutation", result)
	}
	if _, err := os.Stat(rotated); err != nil {
		t.Fatalf("duplicate-key rotation was deleted: %v", err)
	}
}

func TestPruneRotatedFilesRetriesAfterPartialDelete(t *testing.T) {
	path, rotated := createAuthenticatedPruneHistory(t, 5)
	candidates := append([]string(nil), rotated[:2]...)
	key, err := loadIntegrityKey(defaultIntegrityKeyPath(path))
	if err != nil {
		t.Fatalf("loadIntegrityKey() error = %v", err)
	}
	checkpointBefore := mustLoadPruneCheckpoint(t, path, key)
	wantHeadSequence, wantHeadMAC, err := checkpointHead(checkpointBefore)
	if err != nil {
		t.Fatalf("checkpointHead() error = %v", err)
	}

	runtime := productionPruneRuntime
	removeCalls := 0
	runtime.removeFile = func(path string) error {
		removeCalls++
		if removeCalls == 2 {
			return errors.New("injected delete failure")
		}
		return os.Remove(path)
	}
	first, err := pruneRotatedFiles(path, candidates, PruneOptions{Confirm: true}, runtime)
	if err == nil || apperrors.AsAppError(err).Code != apperrors.CodePartialFailure {
		t.Fatalf("first prune = (%+v, %v), want partial failure", first, err)
	}
	if first.CheckpointState != PruneCheckpointAdvanced ||
		!reflect.DeepEqual(first.DeletedFiles, candidates[:1]) {
		t.Fatalf("first result = %+v", first)
	}
	if _, err := os.Stat(candidates[0]); !os.IsNotExist(err) {
		t.Fatalf("first candidate still exists: %v", err)
	}
	if _, err := os.Stat(candidates[1]); err != nil {
		t.Fatalf("second candidate missing after injected failure: %v", err)
	}

	retry, err := PruneRotatedFiles(path, []string{candidates[1]}, PruneOptions{Confirm: true})
	if err != nil {
		t.Fatalf("retry error = %v", err)
	}
	if retry.CheckpointState != PruneCheckpointAlreadyAdvanced ||
		!reflect.DeepEqual(retry.DeletedFiles, []string{candidates[1]}) {
		t.Fatalf("retry result = %+v", retry)
	}
	checkpointAfter := mustLoadPruneCheckpoint(t, path, key)
	gotHeadSequence, gotHeadMAC, err := checkpointHead(checkpointAfter)
	if err != nil {
		t.Fatalf("checkpointHead(after) error = %v", err)
	}
	if gotHeadSequence != wantHeadSequence || !hmacEqual(gotHeadMAC, wantHeadMAC) {
		t.Fatal("partial prune retry changed checkpoint head")
	}
	verified, err := Verify(path, VerifyOptions{})
	if err != nil || verified.HasProblems() || verified.Total != 3 {
		t.Fatalf("Verify() after retry = (%+v, %v)", verified, err)
	}
}

func TestPruneRotatedFilesRetriesIndeterminateCheckpointCommit(t *testing.T) {
	path, rotated := createAuthenticatedPruneHistory(t, 4)
	candidates := append([]string(nil), rotated[:2]...)
	runtime := productionPruneRuntime
	runtime.writeCheckpoint = func(path string, checkpoint auditCheckpoint) error {
		if err := writeCheckpoint(path, checkpoint); err != nil {
			return err
		}
		return errors.New("injected post-replace checkpoint failure")
	}

	first, err := pruneRotatedFiles(path, candidates, PruneOptions{Confirm: true}, runtime)
	if err == nil || apperrors.AsAppError(err).Code != apperrors.CodePartialFailure {
		t.Fatalf("first prune = (%+v, %v), want indeterminate checkpoint failure", first, err)
	}
	if first.CheckpointState != PruneCheckpointIndeterminate || !first.Started || len(first.DeletedFiles) != 0 {
		t.Fatalf("first result = %+v", first)
	}
	assertFilesExist(t, candidates)

	retry, err := PruneRotatedFiles(path, candidates, PruneOptions{Confirm: true})
	if err != nil {
		t.Fatalf("retry error = %v", err)
	}
	if retry.CheckpointState != PruneCheckpointAlreadyAdvanced ||
		!reflect.DeepEqual(retry.DeletedFiles, candidates) {
		t.Fatalf("retry result = %+v", retry)
	}
	verified, err := Verify(path, VerifyOptions{})
	if err != nil || verified.HasProblems() || verified.Total != 2 {
		t.Fatalf("Verify() after retry = (%+v, %v)", verified, err)
	}
}

func TestPruneRotatedFilesReportsOnlyDirectorySyncedDeletes(t *testing.T) {
	path, rotated := createAuthenticatedPruneHistory(t, 4)
	candidates := append([]string(nil), rotated[:2]...)
	runtime := productionPruneRuntime
	syncCalls := 0
	runtime.syncParent = func(path string) error {
		syncCalls++
		if syncCalls == 2 {
			return errors.New("injected directory sync failure")
		}
		return syncParentDirectory(path)
	}

	result, err := pruneRotatedFiles(path, candidates, PruneOptions{Confirm: true}, runtime)
	if err == nil || apperrors.AsAppError(err).Code != apperrors.CodePartialFailure {
		t.Fatalf("prune = (%+v, %v), want partial failure", result, err)
	}
	if !result.Started || result.CheckpointState != PruneCheckpointAdvanced ||
		!reflect.DeepEqual(result.DeletedFiles, candidates[:1]) {
		t.Fatalf("result = %+v", result)
	}
	for _, candidate := range candidates {
		if _, statErr := os.Stat(candidate); !os.IsNotExist(statErr) {
			t.Fatalf("candidate %s still exists: %v", candidate, statErr)
		}
	}
}

func TestPruneRotatedFilesRejectsCandidateIdentitySwapAfterVerification(t *testing.T) {
	path, rotated := createAuthenticatedPruneHistory(t, 4)
	candidate := rotated[0]
	original := mustReadFile(t, candidate)
	checkpointBefore := mustReadFile(t, checkpointPath(path))
	runtime := productionPruneRuntime
	lstatCalls := 0
	runtime.lstat = func(path string) (os.FileInfo, error) {
		if path == candidate {
			lstatCalls++
			if lstatCalls == 3 {
				if err := os.Rename(candidate, candidate+".swapped"); err != nil {
					t.Fatalf("rename candidate: %v", err)
				}
				if err := os.WriteFile(candidate, original, 0o600); err != nil {
					t.Fatalf("replace candidate: %v", err)
				}
			}
		}
		return os.Lstat(path)
	}

	result, err := pruneRotatedFiles(path, []string{candidate}, PruneOptions{Confirm: true}, runtime)
	if err == nil || apperrors.AsAppError(err).Code != apperrors.CodeConflict {
		t.Fatalf("prune = (%+v, %v), want conflict", result, err)
	}
	if result.Started || len(result.DeletedFiles) != 0 {
		t.Fatalf("result = %+v, want no core mutation", result)
	}
	if got := mustReadFile(t, checkpointPath(path)); !bytes.Equal(got, checkpointBefore) {
		t.Fatal("identity swap changed checkpoint")
	}
}

func TestPruneRotatedFilesLegacyHistoryDoesNotCreateCheckpoint(t *testing.T) {
	directory := privateTestDir(t)
	path := filepath.Join(directory, "audit.log")
	rotated := path + ".20260101-000000.log"
	writeLegacyPruneFile(t, rotated, 0)
	writeLegacyPruneFile(t, path, 1)

	result, err := PruneRotatedFiles(path, []string{rotated}, PruneOptions{Confirm: true})
	if err != nil {
		t.Fatalf("PruneRotatedFiles() error = %v", err)
	}
	if result.CheckpointState != PruneCheckpointUnchanged ||
		!reflect.DeepEqual(result.DeletedFiles, []string{rotated}) {
		t.Fatalf("result = %+v", result)
	}
	if _, err := os.Stat(checkpointPath(path)); !os.IsNotExist(err) {
		t.Fatalf("legacy prune created checkpoint: %v", err)
	}
	verified, err := Verify(path, VerifyOptions{})
	if err != nil || verified.HasProblems() || verified.Total != 1 {
		t.Fatalf("Verify() legacy remainder = (%+v, %v)", verified, err)
	}
}

func TestPruneRotatedFilesSerializesConcurrentAppend(t *testing.T) {
	path, rotated := createAuthenticatedPruneHistory(t, 6)
	candidates := append([]string(nil), rotated[:2]...)
	start := make(chan struct{})
	errorsCh := make(chan error, 2)
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		<-start
		_, err := PruneRotatedFiles(path, candidates, PruneOptions{Confirm: true})
		errorsCh <- err
	}()
	go func() {
		defer wait.Done()
		<-start
		errorsCh <- AppendRecord(path, pruneEvent(99), Options{MaxSizeBytes: 1})
	}()
	close(start)
	wait.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatalf("concurrent operation error = %v", err)
		}
	}
	verified, err := Verify(path, VerifyOptions{})
	if err != nil || verified.HasProblems() || verified.Total != 5 {
		t.Fatalf("Verify() after concurrent append/prune = (%+v, %v)", verified, err)
	}
}

func TestVerifyExpectedRotatedFilesBindsInsideLock(t *testing.T) {
	path, rotated := createAuthenticatedPruneHistory(t, 3)
	verified, err := Verify(path, VerifyOptions{ExpectedRotatedFiles: append([]string(nil), rotated...)})
	if err != nil || verified.HasProblems() {
		t.Fatalf("Verify(expected current) = (%+v, %v)", verified, err)
	}
	if err := AppendRecord(path, pruneEvent(4), Options{MaxSizeBytes: 1}); err != nil {
		t.Fatalf("AppendRecord() error = %v", err)
	}
	_, err = Verify(path, VerifyOptions{ExpectedRotatedFiles: rotated})
	if err == nil || apperrors.AsAppError(err).Code != apperrors.CodeConflict {
		t.Fatalf("Verify(stale expected rotations) error = %v, want conflict", err)
	}
}

func TestPruneExpectedRotatedFilesRejectsNewTailAfterPreview(t *testing.T) {
	path, previewRotations := createAuthenticatedPruneHistory(t, 3)
	if err := AppendRecord(path, pruneEvent(4), Options{MaxSizeBytes: 1}); err != nil {
		t.Fatalf("AppendRecord() error = %v", err)
	}
	result, err := PruneRotatedFiles(
		path,
		previewRotations[:1],
		PruneOptions{
			Confirm:              true,
			ExpectedRotatedFiles: previewRotations,
		},
	)
	if err == nil || apperrors.AsAppError(err).Code != apperrors.CodeConflict {
		t.Fatalf("PruneRotatedFiles(stale preview) = (%+v, %v), want conflict", result, err)
	}
	if result.Started || len(result.DeletedFiles) != 0 {
		t.Fatalf("result = %+v, want no mutation", result)
	}
	assertFilesExist(t, previewRotations)
}

func createAuthenticatedPruneHistory(t *testing.T, records int) (string, []string) {
	t.Helper()
	path := filepath.Join(privateTestDir(t), "audit.log")
	for index := 0; index < records; index++ {
		if err := AppendRecord(path, pruneEvent(index), Options{MaxSizeBytes: 1}); err != nil {
			t.Fatalf("AppendRecord(%d) error = %v", index, err)
		}
	}
	rotated, err := RotatedFiles(path)
	if err != nil {
		t.Fatalf("RotatedFiles() error = %v", err)
	}
	if len(rotated) != records-1 {
		t.Fatalf("rotated files = %d, want %d", len(rotated), records-1)
	}
	return path, rotated
}

func pruneEvent(index int) Event {
	return Event{
		Timestamp: time.Date(2026, 7, 21, 1, index, 0, 0, time.UTC),
		EventType: EventType("resource.update"),
		Operator:  fmt.Sprintf("operator-%d", index),
		Status:    StatusSuccess,
	}
}

func mustLoadPruneCheckpoint(t *testing.T, path string, key []byte) auditCheckpoint {
	t.Helper()
	checkpoint, exists, err := loadCheckpoint(path, key)
	if err != nil || !exists {
		t.Fatalf("loadCheckpoint() = (%+v, %t, %v)", checkpoint, exists, err)
	}
	return checkpoint
}

func assertFilesExist(t *testing.T, paths []string) {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s to exist: %v", path, err)
		}
	}
}

func writeLegacyPruneFile(t *testing.T, path string, index int) {
	t.Helper()
	data, err := json.Marshal(pruneEvent(index))
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if err := writeOwnerOnlyExclusive(path, append(data, '\n')); err != nil {
		t.Fatalf("writeOwnerOnlyExclusive() error = %v", err)
	}
}

func hmacEqual(left, right []byte) bool {
	return bytes.Equal(left, right)
}
