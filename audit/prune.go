package audit

import (
	"bytes"
	"crypto/hmac"
	"os"
	"path/filepath"
	"strings"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/lockfile"
)

// PruneOptions controls rotated audit log pruning. Callers remain responsible
// for completing their R3 authorization before setting Confirm.
type PruneOptions struct {
	Confirm          bool
	IntegrityKeyPath string
	// ExpectedRotatedFiles, when non-nil, must exactly match RotatedFiles
	// while the audit lock is held. Candidates must still be its oldest prefix.
	ExpectedRotatedFiles []string
}

// PruneCheckpointState reports the durable checkpoint state of a prune call.
type PruneCheckpointState string

const (
	// PruneCheckpointUnchanged means the call did not need to, or did not yet,
	// advance the authenticated checkpoint base.
	PruneCheckpointUnchanged PruneCheckpointState = "unchanged"
	// PruneCheckpointAdvanced means this call durably advanced the checkpoint
	// base before deleting authenticated rotations.
	PruneCheckpointAdvanced PruneCheckpointState = "advanced"
	// PruneCheckpointAlreadyAdvanced means the selected files are residue from
	// an earlier partial prune whose checkpoint advance already committed.
	PruneCheckpointAlreadyAdvanced PruneCheckpointState = "already-advanced"
	// PruneCheckpointIndeterminate means a checkpoint write failed after it may
	// have replaced the prior checkpoint. No candidate deletion is attempted.
	PruneCheckpointIndeterminate PruneCheckpointState = "indeterminate"
)

// PruneResult describes the durable progress of PruneRotatedFiles. DeletedFiles
// contains only removals followed by the platform parent durability step:
// directory sync on POSIX, and completed removal on Windows. Started is true
// once the call may have changed persistent state.
type PruneResult struct {
	Candidates      []string             `json:"candidates"`
	DeletedFiles    []string             `json:"deletedFiles"`
	Started         bool                 `json:"started"`
	CheckpointState PruneCheckpointState `json:"checkpointState"`
}

type pruneRuntime struct {
	writeCheckpoint func(string, auditCheckpoint) error
	removeFile      func(string) error
	syncParent      func(string) error
	lstat           func(string) (os.FileInfo, error)
	releaseLock     func(*lockfile.Lock) error
}

var productionPruneRuntime = pruneRuntime{
	writeCheckpoint: writeCheckpoint,
	removeFile:      os.Remove,
	syncParent:      syncParentDirectory,
	lstat:           os.Lstat,
	releaseLock: func(lock *lockfile.Lock) error {
		return lock.Release()
	},
}

type pruneEnvelopeRange struct {
	found         bool
	firstSequence uint64
	firstPrevMAC  []byte
	lastSequence  uint64
	lastMAC       []byte
}

// PruneRotatedFiles deletes an explicitly selected, continuous oldest prefix
// of RotatedFiles. It validates the full history under the append lock. For v2
// history it durably advances the authenticated checkpoint base before any
// deletion, allowing a partial deletion to be retried safely.
func PruneRotatedFiles(
	path string,
	candidates []string,
	opts PruneOptions,
) (PruneResult, error) {
	return pruneRotatedFiles(path, candidates, opts, productionPruneRuntime)
}

func pruneRotatedFiles(
	path string,
	candidates []string,
	opts PruneOptions,
	runtime pruneRuntime,
) (result PruneResult, retErr error) {
	result = PruneResult{
		Candidates:      []string{},
		DeletedFiles:    []string{},
		CheckpointState: PruneCheckpointUnchanged,
	}
	if len(candidates) == 0 {
		return result, nil
	}
	keyPath := effectiveIntegrityKeyPath(path, opts.IntegrityKeyPath)
	if err := validateIntegrityKeyPath(path, keyPath); err != nil {
		return result, err
	}
	if err := validateAuditArtifactParent(path); err != nil {
		return result, err
	}

	lock := lockfile.New(path)
	if err := lock.Acquire(); err != nil {
		return result, err
	}
	defer func() {
		if err := runtime.releaseLock(lock); err != nil && retErr == nil {
			code := apperrors.CodeLocalIOError
			if result.Started {
				code = apperrors.CodePartialFailure
			}
			retErr = apperrors.New(code, "failed to release audit prune lock", err)
		}
	}()
	if err := validatePruneRotationNamespace(path); err != nil {
		return result, err
	}
	if err := validateExpectedRotatedFiles(path, opts.ExpectedRotatedFiles); err != nil {
		return result, err
	}

	selected, snapshots, err := validatePrunePrefix(path, candidates, runtime)
	if err != nil {
		return result, err
	}
	result.Candidates = append(result.Candidates, selected...)

	key, checkpoint, checkpointExists, err := loadPruneIntegrity(path, keyPath)
	if err != nil {
		return result, err
	}
	selectedRange, err := inspectPruneEnvelopeRange(selected, key)
	if err != nil {
		return result, err
	}
	retry := pruneCheckpointMatchesRange(checkpoint, checkpointExists, selectedRange)
	if retry {
		result.CheckpointState = PruneCheckpointAlreadyAdvanced
		if err := verifyRetryablePruneHistory(path, keyPath, key, checkpoint, selectedRange); err != nil {
			return result, err
		}
	} else if err := verifyPrunableHistory(path, keyPath); err != nil {
		return result, err
	}

	revalidatedRange, err := inspectPruneEnvelopeRange(selected, key)
	if err != nil {
		return result, err
	}
	if !samePruneEnvelopeRange(selectedRange, revalidatedRange) {
		return result, apperrors.New(
			apperrors.CodeConflict,
			"audit prune candidates changed during verification",
			nil,
		)
	}
	if err := revalidatePruneSnapshots(selected, snapshots, runtime); err != nil {
		return result, err
	}
	if err := revalidatePruneIntegrity(path, keyPath, key, checkpoint, checkpointExists); err != nil {
		return result, err
	}
	if !opts.Confirm {
		return result, nil
	}

	if selectedRange.found && !retry {
		if !checkpointExists {
			return result, apperrors.New(
				apperrors.CodeValidationFailed,
				"authenticated audit history is missing its checkpoint",
				nil,
			)
		}
		headSequence, headMAC, err := checkpointHead(checkpoint)
		if err != nil {
			return result, apperrors.New(
				apperrors.CodeValidationFailed,
				"invalid audit checkpoint head",
				err,
			)
		}
		result.Started = true
		nextCheckpoint := makeCheckpoint(
			key,
			selectedRange.lastSequence,
			selectedRange.lastMAC,
			headSequence,
			headMAC,
		)
		if err := runtime.writeCheckpoint(path, nextCheckpoint); err != nil {
			result.CheckpointState = PruneCheckpointIndeterminate
			return result, apperrors.New(
				apperrors.CodePartialFailure,
				"audit prune checkpoint state is indeterminate; no rotated file deletion was attempted",
				err,
			)
		}
		result.CheckpointState = PruneCheckpointAdvanced
	}

	for index, candidate := range selected {
		if err := revalidatePruneSnapshot(candidate, snapshots[index], runtime); err != nil {
			return result, pruneProgressError(result, "audit prune candidate changed before deletion", err)
		}
		result.Started = true
		if err := runtime.removeFile(candidate); err != nil {
			return result, pruneProgressError(result, "failed to delete rotated audit log", err)
		}
		if err := runtime.syncParent(candidate); err != nil {
			return result, apperrors.New(
				apperrors.CodePartialFailure,
				"rotated audit log was removed but directory durability is indeterminate",
				err,
			)
		}
		result.DeletedFiles = append(result.DeletedFiles, candidate)
	}
	return result, nil
}

func validatePruneRotationNamespace(path string) error {
	directory := filepath.Dir(path)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return apperrors.New(
			apperrors.CodeLocalIOError,
			"failed to inspect audit rotation namespace",
			err,
		)
	}
	activeBase := filepath.Base(path)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, activeBase+".") {
			continue
		}
		if isKnownAuditRepairTemp(activeBase, name) {
			continue
		}
		if !strings.HasSuffix(name, ".log") {
			continue
		}
		candidate := filepath.Join(directory, name)
		if isRotatedAuditLog(path, candidate) || isAuditQuarantineLog(path, candidate) {
			continue
		}
		return apperrors.New(
			apperrors.CodeValidationFailed,
			"unrecognized file in audit rotation namespace: "+name,
			nil,
		)
	}
	return nil
}

func isAuditQuarantineLog(activePath, candidate string) bool {
	_, ok := RotatedFileTimestamp(activePath+".quarantine", candidate)
	return ok
}

func isKnownAuditRepairTemp(activeBase, name string) bool {
	for _, marker := range []string{".repair-new-", ".repair-original-"} {
		prefix := activeBase + marker
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		suffix := strings.TrimPrefix(name, prefix)
		if suffix == "" {
			return false
		}
		for _, character := range suffix {
			if character < '0' || character > '9' {
				return false
			}
		}
		return true
	}
	return false
}

func validatePrunePrefix(
	path string,
	candidates []string,
	runtime pruneRuntime,
) ([]string, []os.FileInfo, error) {
	rotated, err := RotatedFiles(path)
	if err != nil {
		return nil, nil, err
	}
	if len(candidates) > len(rotated) {
		return nil, nil, prunePrefixConflict()
	}
	selected := make([]string, len(candidates))
	snapshots := make([]os.FileInfo, len(candidates))
	for index, candidate := range candidates {
		if !auditPathEqual(filepath.Clean(candidate), filepath.Clean(rotated[index])) {
			return nil, nil, prunePrefixConflict()
		}
		selected[index] = rotated[index]
		info, err := snapshotPruneFile(selected[index], runtime)
		if err != nil {
			return nil, nil, err
		}
		snapshots[index] = info
	}
	return selected, snapshots, nil
}

func prunePrefixConflict() error {
	return apperrors.New(
		apperrors.CodeConflict,
		"audit prune candidates must be the current continuous oldest rotation prefix",
		nil,
	)
}

func snapshotPruneFile(path string, runtime pruneRuntime) (os.FileInfo, error) {
	before, err := runtime.lstat(path)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to inspect audit prune candidate", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, apperrors.New(
			apperrors.CodeValidationFailed,
			"audit prune candidate must be a regular non-link file",
			nil,
		)
	}
	if err := verifyOwnerOnlyFile(path); err != nil {
		return nil, err
	}
	after, err := runtime.lstat(path)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to re-inspect audit prune candidate", err)
	}
	if !samePruneFile(before, after) {
		return nil, apperrors.New(
			apperrors.CodeConflict,
			"audit prune candidate changed during inspection",
			nil,
		)
	}
	return after, nil
}

func revalidatePruneSnapshots(
	paths []string,
	snapshots []os.FileInfo,
	runtime pruneRuntime,
) error {
	for index, path := range paths {
		if err := revalidatePruneSnapshot(path, snapshots[index], runtime); err != nil {
			return err
		}
	}
	return nil
}

func revalidatePruneSnapshot(path string, expected os.FileInfo, runtime pruneRuntime) error {
	current, err := runtime.lstat(path)
	if err != nil {
		return apperrors.New(apperrors.CodeConflict, "audit prune candidate changed after preview", err)
	}
	if current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() ||
		!samePruneFile(expected, current) {
		return apperrors.New(
			apperrors.CodeConflict,
			"audit prune candidate changed after preview",
			nil,
		)
	}
	if err := verifyOwnerOnlyFile(path); err != nil {
		return err
	}
	return nil
}

func samePruneFile(left, right os.FileInfo) bool {
	return os.SameFile(left, right) &&
		left.Size() == right.Size() &&
		left.Mode() == right.Mode() &&
		left.ModTime().Equal(right.ModTime())
}

func loadPruneIntegrity(
	path string,
	keyPath string,
) ([]byte, auditCheckpoint, bool, error) {
	keyExists, err := pathExists(keyPath)
	if err != nil {
		return nil, auditCheckpoint{}, false, err
	}
	checkpointExists, err := pathExists(checkpointPath(path))
	if err != nil {
		return nil, auditCheckpoint{}, false, err
	}
	if checkpointExists && !keyExists {
		return nil, auditCheckpoint{}, true, apperrors.New(
			apperrors.CodeValidationFailed,
			"audit integrity key is missing for authenticated audit history",
			nil,
		)
	}
	if !keyExists {
		return nil, auditCheckpoint{}, false, nil
	}
	key, err := loadIntegrityKey(keyPath)
	if err != nil {
		return nil, auditCheckpoint{}, checkpointExists, err
	}
	if !checkpointExists {
		return key, auditCheckpoint{}, false, nil
	}
	checkpoint, _, err := loadCheckpoint(path, key)
	return key, checkpoint, true, err
}

func revalidatePruneIntegrity(
	path string,
	keyPath string,
	expectedKey []byte,
	expectedCheckpoint auditCheckpoint,
	expectedCheckpointExists bool,
) error {
	key, checkpoint, checkpointExists, err := loadPruneIntegrity(path, keyPath)
	if err != nil {
		return err
	}
	if !bytes.Equal(key, expectedKey) ||
		checkpointExists != expectedCheckpointExists ||
		(checkpointExists && checkpoint != expectedCheckpoint) {
		return apperrors.New(
			apperrors.CodeConflict,
			"audit integrity state changed during prune verification",
			nil,
		)
	}
	return nil
}

func inspectPruneEnvelopeRange(paths []string, key []byte) (pruneEnvelopeRange, error) {
	var result pruneEnvelopeRange
	seenV2 := false
	for _, path := range paths {
		file, err := openAuditReadFile(path)
		if err != nil {
			return result, err
		}
		scanner := newAuditScanner(file)
		for scanner.Scan() {
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}
			env, payload, isEnvelope, parseErr := parseEnvelope(line)
			if !isEnvelope {
				if seenV2 {
					_ = file.Close()
					return result, apperrors.New(
						apperrors.CodeValidationFailed,
						"unauthenticated audit record follows authenticated prune candidate history",
						nil,
					)
				}
				continue
			}
			if parseErr != nil {
				_ = file.Close()
				return result, apperrors.New(
					apperrors.CodeValidationFailed,
					"invalid authenticated audit prune candidate",
					parseErr,
				)
			}
			if len(key) == 0 {
				_ = file.Close()
				return result, apperrors.New(
					apperrors.CodeValidationFailed,
					"audit integrity key is missing for authenticated prune candidates",
					nil,
				)
			}
			prevMAC, mac, verifyErr := verifyEnvelope(env, payload, key)
			if verifyErr != nil {
				_ = file.Close()
				return result, apperrors.New(
					apperrors.CodeValidationFailed,
					"authenticated audit prune candidate failed integrity verification",
					verifyErr,
				)
			}
			if !result.found {
				result.found = true
				result.firstSequence = env.Sequence
				result.firstPrevMAC = append([]byte(nil), prevMAC...)
			} else if env.Sequence != result.lastSequence+1 || !hmac.Equal(prevMAC, result.lastMAC) {
				_ = file.Close()
				return result, apperrors.New(
					apperrors.CodeValidationFailed,
					"authenticated audit prune candidates are discontinuous",
					nil,
				)
			}
			seenV2 = true
			result.lastSequence = env.Sequence
			result.lastMAC = append(result.lastMAC[:0], mac...)
		}
		scanErr := scanner.Err()
		closeErr := file.Close()
		if scanErr != nil {
			return result, apperrors.New(apperrors.CodeLocalIOError, "failed to read audit prune candidate", scanErr)
		}
		if closeErr != nil {
			return result, apperrors.New(apperrors.CodeLocalIOError, "failed to close audit prune candidate", closeErr)
		}
	}
	return result, nil
}

func samePruneEnvelopeRange(left, right pruneEnvelopeRange) bool {
	return left.found == right.found &&
		left.firstSequence == right.firstSequence &&
		hmac.Equal(left.firstPrevMAC, right.firstPrevMAC) &&
		left.lastSequence == right.lastSequence &&
		hmac.Equal(left.lastMAC, right.lastMAC)
}

func pruneCheckpointMatchesRange(
	checkpoint auditCheckpoint,
	checkpointExists bool,
	selected pruneEnvelopeRange,
) bool {
	if !checkpointExists || !selected.found {
		return false
	}
	baseSequence, baseMAC, err := checkpointBase(checkpoint)
	return err == nil &&
		baseSequence == selected.lastSequence &&
		hmac.Equal(baseMAC, selected.lastMAC)
}

func verifyPrunableHistory(path, keyPath string) error {
	result := VerifyResult{Files: []VerifyFileResult{}}
	state, err := newVerifyIntegrityState(
		path,
		keyPath,
		VerifyOptions{IntegrityKeyPath: keyPath},
		productionAuditRepairRuntime,
		&result,
	)
	if err != nil {
		return err
	}
	files, err := queryFiles(path)
	if err != nil {
		return err
	}
	if err := verifyFilesWithState(files, state, &result); err != nil {
		return err
	}
	if result.HasProblems() {
		return apperrors.New(
			apperrors.CodeValidationFailed,
			"audit history must pass complete verification before pruning",
			nil,
		)
	}
	return nil
}

func verifyRetryablePruneHistory(
	path string,
	keyPath string,
	key []byte,
	checkpoint auditCheckpoint,
	selected pruneEnvelopeRange,
) error {
	if !selected.found || selected.firstSequence == 0 {
		return apperrors.New(
			apperrors.CodeValidationFailed,
			"invalid authenticated audit prune retry boundary",
			nil,
		)
	}
	result := VerifyResult{Files: []VerifyFileResult{}}
	state := &verifyIntegrityState{
		key:              append([]byte(nil), key...),
		checkpoint:       checkpoint,
		checkpointOnDisk: true,
		checkpointValid:  true,
		seenV2:           selected.firstSequence > 1,
		sequence:         selected.firstSequence - 1,
		mac:              append([]byte(nil), selected.firstPrevMAC...),
		result:           &result,
		opts:             VerifyOptions{IntegrityKeyPath: keyPath},
		repairRuntime:    productionAuditRepairRuntime,
	}
	files, err := queryFiles(path)
	if err != nil {
		return err
	}
	if err := verifyFilesWithState(files, state, &result); err != nil {
		return err
	}
	if result.HasProblems() {
		return apperrors.New(
			apperrors.CodeValidationFailed,
			"partially pruned audit history failed complete retry verification",
			nil,
		)
	}
	return nil
}

func pruneProgressError(result PruneResult, message string, err error) error {
	if !result.Started && len(result.DeletedFiles) == 0 &&
		result.CheckpointState == PruneCheckpointUnchanged {
		appErr := apperrors.AsAppError(err)
		if appErr.Code == apperrors.CodeConflict || appErr.Code == apperrors.CodeValidationFailed {
			return appErr
		}
	}
	code := apperrors.CodeLocalIOError
	if result.Started || len(result.DeletedFiles) > 0 ||
		result.CheckpointState == PruneCheckpointAdvanced ||
		result.CheckpointState == PruneCheckpointAlreadyAdvanced ||
		result.CheckpointState == PruneCheckpointIndeterminate {
		code = apperrors.CodePartialFailure
	}
	return apperrors.New(code, message, err)
}
