package audit

import (
	"bytes"
	"crypto/hmac"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/lockfile"
)

// VerifyOptions controls audit log verification.
type VerifyOptions struct {
	Decrypt          bool
	PrivateKey       string
	Repair           bool
	Confirm          bool
	IntegrityKeyPath string
	// ExpectedRotatedFiles, when non-nil, must exactly match RotatedFiles
	// while the audit lock is held. It binds a preview to repair/verification.
	ExpectedRotatedFiles []string
}

// VerifyResult summarizes audit log verification.
type VerifyResult struct {
	Files                    []VerifyFileResult `json:"files"`
	Total                    int                `json:"total"`
	Valid                    int                `json:"valid"`
	Malformed                int                `json:"malformed"`
	SchemaErrors             int                `json:"schemaErrors"`
	TimestampOrderViolations int                `json:"timestampOrderViolations"`
	Authenticated            int                `json:"authenticated"`
	LegacyUnauthenticated    int                `json:"legacyUnauthenticated"`
	EncryptedOpaque          int                `json:"encryptedOpaque"`
	IntegrityErrors          int                `json:"integrityErrors"`
	SequenceViolations       int                `json:"sequenceViolations"`
	CheckpointViolations     int                `json:"checkpointViolations"`
	TruncationDetected       bool               `json:"truncationDetected"`
	Lock                     VerifyLockStatus   `json:"lock"`
}

// HasProblems reports whether verification found malformed, invalid, or
// discontinuous audit history.
func (result VerifyResult) HasProblems() bool {
	return result.Malformed > 0 ||
		result.SchemaErrors > 0 ||
		result.TimestampOrderViolations > 0 ||
		result.IntegrityErrors > 0 ||
		result.SequenceViolations > 0 ||
		result.CheckpointViolations > 0 ||
		result.TruncationDetected
}

// VerifyFileResult summarizes one active or rotated audit file.
type VerifyFileResult struct {
	Path                     string `json:"path"`
	Total                    int    `json:"total"`
	Valid                    int    `json:"valid"`
	Malformed                int    `json:"malformed"`
	Quarantine               string `json:"quarantine,omitempty"`
	Repaired                 bool   `json:"repaired,omitempty"`
	SchemaError              int    `json:"schemaErrors,omitempty"`
	TimestampOrderViolations int    `json:"timestampOrderViolations,omitempty"`
	Authenticated            int    `json:"authenticated,omitempty"`
	LegacyUnauthenticated    int    `json:"legacyUnauthenticated,omitempty"`
	EncryptedOpaque          int    `json:"encryptedOpaque,omitempty"`
	IntegrityErrors          int    `json:"integrityErrors,omitempty"`
	SequenceViolations       int    `json:"sequenceViolations,omitempty"`
}

// VerifyLockStatus reports the active audit lock file if present.
type VerifyLockStatus struct {
	Path    string `json:"path,omitempty"`
	Present bool   `json:"present"`
	Content string `json:"content,omitempty"`
}

type verifyIntegrityState struct {
	key                       []byte
	checkpoint                auditCheckpoint
	checkpointOnDisk          bool
	checkpointValid           bool
	checkpointProblemRecorded bool
	seenV2                    bool
	observedV2                bool
	sequence                  uint64
	mac                       []byte
	previousTimestamp         time.Time
	result                    *VerifyResult
	opts                      VerifyOptions
	repairRuntime             auditRepairRuntime
}

type auditRepairRuntime struct {
	syncFile      func(*os.File) error
	atomicReplace func(string, string) error
	syncParent    func(string) error
	removeFile    func(string) error
	lstat         func(string) (os.FileInfo, error)
}

var productionAuditRepairRuntime = auditRepairRuntime{
	syncFile: func(file *os.File) error {
		return file.Sync()
	},
	atomicReplace: atomicReplaceFile,
	syncParent:    syncParentDirectory,
	removeFile:    os.Remove,
	lstat:         os.Lstat,
}

// Verify scans active and rotated audit files under the same lock used by
// append, authenticating v2 envelopes before inspecting their payloads.
func Verify(path string, opts VerifyOptions) (VerifyResult, error) {
	return verifyWithRepairRuntime(path, opts, productionAuditRepairRuntime)
}

func verifyWithRepairRuntime(
	path string,
	opts VerifyOptions,
	repairRuntime auditRepairRuntime,
) (VerifyResult, error) {
	lockStatus, err := readLockStatus(path)
	result := VerifyResult{Files: []VerifyFileResult{}, Lock: lockStatus}
	if err != nil {
		return result, err
	}
	keyPath := effectiveIntegrityKeyPath(path, opts.IntegrityKeyPath)
	if err := validateIntegrityKeyPath(path, keyPath); err != nil {
		return result, err
	}
	hasArtifacts, err := auditArtifactsExist(path, keyPath)
	if err != nil {
		return result, err
	}
	if !hasArtifacts {
		return result, nil
	}
	if err := validateAuditArtifactParent(path); err != nil {
		return result, err
	}

	lock := lockfile.New(path)
	if err := lock.Acquire(); err != nil {
		return result, err
	}
	defer func() { _ = lock.Release() }()
	if err := validateExpectedRotatedFiles(path, opts.ExpectedRotatedFiles); err != nil {
		return result, err
	}

	if opts.Repair {
		checkpointExists, existsErr := pathExists(checkpointPath(path))
		if existsErr != nil {
			return result, existsErr
		}
		hasV2, scanErr := auditContainsV2(path)
		if scanErr != nil {
			return result, scanErr
		}
		genesisOnly := false
		if checkpointExists && !hasV2 {
			genesisOnly, err = isGenesisCheckpoint(path, keyPath)
			if err != nil {
				return result, err
			}
		}
		if hasV2 || (checkpointExists && !genesisOnly) {
			return result, apperrors.New(
				apperrors.CodeValidationFailed,
				"repair is not supported for authenticated audit history",
				nil,
			)
		}
	}

	state, err := newVerifyIntegrityState(path, keyPath, opts, repairRuntime, &result)
	if err != nil {
		return result, err
	}
	files, err := queryFiles(path)
	if err != nil {
		return result, err
	}
	if err := verifyFilesWithState(files, state, &result); err != nil {
		return result, err
	}
	return result, nil
}

func validateExpectedRotatedFiles(path string, expected []string) error {
	if expected == nil {
		return nil
	}
	current, err := RotatedFiles(path)
	if err != nil {
		return err
	}
	if len(current) != len(expected) {
		return apperrors.New(
			apperrors.CodeConflict,
			"audit rotated files changed after preview",
			nil,
		)
	}
	for index := range current {
		if !auditPathEqual(filepath.Clean(current[index]), filepath.Clean(expected[index])) {
			return apperrors.New(
				apperrors.CodeConflict,
				"audit rotated files changed after preview",
				nil,
			)
		}
	}
	return nil
}

func verifyFilesWithState(
	files []string,
	state *verifyIntegrityState,
	result *VerifyResult,
) error {
	for _, filePath := range files {
		fileResult, verifyErr := state.verifyOneFile(filePath)
		if verifyErr != nil {
			return verifyErr
		}
		result.Files = append(result.Files, fileResult)
		result.Total += fileResult.Total
		result.Valid += fileResult.Valid
		result.Malformed += fileResult.Malformed
		result.SchemaErrors += fileResult.SchemaError
		result.TimestampOrderViolations += fileResult.TimestampOrderViolations
		result.Authenticated += fileResult.Authenticated
		result.LegacyUnauthenticated += fileResult.LegacyUnauthenticated
		result.EncryptedOpaque += fileResult.EncryptedOpaque
		result.IntegrityErrors += fileResult.IntegrityErrors
		result.SequenceViolations += fileResult.SequenceViolations
	}
	state.finish()
	return nil
}

func isGenesisCheckpoint(path, keyPath string) (bool, error) {
	keyExists, err := pathExists(keyPath)
	if err != nil || !keyExists {
		return false, err
	}
	key, err := loadIntegrityKey(keyPath)
	if err != nil {
		return false, err
	}
	checkpoint, exists, err := loadCheckpoint(path, key)
	if err != nil || !exists {
		return false, err
	}
	baseSequence, baseMAC, err := checkpointBase(checkpoint)
	if err != nil {
		return false, err
	}
	headSequence, headMAC, err := checkpointHead(checkpoint)
	if err != nil {
		return false, err
	}
	return baseSequence == 0 &&
		headSequence == 0 &&
		len(baseMAC) == 0 &&
		len(headMAC) == 0, nil
}

func newVerifyIntegrityState(
	path string,
	keyPath string,
	opts VerifyOptions,
	repairRuntime auditRepairRuntime,
	result *VerifyResult,
) (*verifyIntegrityState, error) {
	state := &verifyIntegrityState{result: result, opts: opts, repairRuntime: repairRuntime}
	var err error
	state.checkpointOnDisk, err = pathExists(checkpointPath(path))
	if err != nil {
		return nil, err
	}
	keyExists, err := pathExists(keyPath)
	if err != nil {
		return nil, err
	}
	if keyExists {
		state.key, err = loadIntegrityKey(keyPath)
		if err != nil {
			return nil, err
		}
	}
	if !state.checkpointOnDisk {
		return state, nil
	}
	if len(state.key) == 0 {
		result.CheckpointViolations++
		state.checkpointProblemRecorded = true
		return state, nil
	}
	state.checkpoint, state.checkpointValid, err = loadCheckpoint(path, state.key)
	if err != nil {
		if apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
			return nil, err
		}
		result.CheckpointViolations++
		state.checkpointProblemRecorded = true
		return state, nil
	}
	state.sequence, state.mac, err = checkpointBase(state.checkpoint)
	if err != nil {
		result.CheckpointViolations++
		state.checkpointProblemRecorded = true
		state.checkpointValid = false
	}
	state.seenV2 = state.sequence > 0
	return state, nil
}

func (state *verifyIntegrityState) verifyOneFile(path string) (VerifyFileResult, error) {
	fileResult := VerifyFileResult{Path: path}
	file, err := openAuditReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fileResult, nil
		}
		return fileResult, err
	}
	defer func() { _ = file.Close() }()
	sourceInfo, err := file.Stat()
	if err != nil {
		return fileResult, apperrors.New(apperrors.CodeLocalIOError, "failed to stat audit log", err)
	}

	repairing := state.opts.Repair && state.opts.Confirm
	var kept, quarantine bytes.Buffer
	scanner := newAuditScanner(file)
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fileResult.Total++
		keep, inspectErr := state.verifyLine(line, &fileResult)
		if inspectErr != nil {
			return fileResult, inspectErr
		}
		if !keep {
			if repairing {
				quarantine.WriteString(raw)
				quarantine.WriteByte('\n')
			}
			continue
		}
		if repairing {
			kept.WriteString(raw)
			kept.WriteByte('\n')
		}
	}
	if err := scanner.Err(); err != nil {
		return fileResult, apperrors.New(apperrors.CodeLocalIOError, "failed to read audit log", err)
	}
	if repairing && fileResult.Malformed > 0 {
		quarantinePath, err := repairLegacyAuditFile(
			path,
			file,
			sourceInfo,
			kept.Bytes(),
			quarantine.Bytes(),
			time.Now().UTC(),
			state.repairRuntime,
		)
		if err != nil {
			return fileResult, err
		}
		fileResult.Quarantine = quarantinePath
		fileResult.Repaired = true
		return fileResult, nil
	}
	if err := file.Close(); err != nil {
		return fileResult, apperrors.New(apperrors.CodeLocalIOError, "failed to close audit log", err)
	}
	return fileResult, nil
}

func repairLegacyAuditFile(
	path string,
	source *os.File,
	sourceInfo os.FileInfo,
	kept []byte,
	quarantine []byte,
	now time.Time,
	runtime auditRepairRuntime,
) (string, error) {
	directory := filepath.Dir(path)
	if err := ensureOwnerOnlyDirectory(directory); err != nil {
		return "", err
	}
	replacementPath, err := stageOwnerOnlyAuditFile(
		directory,
		filepath.Base(path)+".repair-new-",
		runtime,
		func(file *os.File) error {
			written, writeErr := file.Write(kept)
			if writeErr != nil {
				return writeErr
			}
			if written != len(kept) {
				return io.ErrShortWrite
			}
			return nil
		},
	)
	if err != nil {
		return "", err
	}
	defer func() {
		if replacementPath != "" {
			_ = runtime.removeFile(replacementPath)
		}
	}()

	backupPath, err := stageOwnerOnlyAuditFile(
		directory,
		filepath.Base(path)+".repair-original-",
		runtime,
		func(file *os.File) error {
			if _, seekErr := source.Seek(0, io.SeekStart); seekErr != nil {
				return seekErr
			}
			_, copyErr := io.Copy(file, source)
			return copyErr
		},
	)
	if err != nil {
		return "", err
	}
	defer func() {
		if backupPath != "" {
			_ = runtime.removeFile(backupPath)
		}
	}()
	if err := source.Close(); err != nil {
		return "", apperrors.New(apperrors.CodeLocalIOError, "failed to close audit repair backup source", err)
	}
	if err := validateUnchangedRepairTarget(path, sourceInfo, runtime); err != nil {
		return "", err
	}

	quarantinePath, err := writeAuditQuarantine(path, quarantine, now)
	if err != nil {
		return "", err
	}
	if err := runtime.atomicReplace(replacementPath, path); err != nil {
		cleanupErr := removeRepairArtifact(quarantinePath, runtime)
		if cleanupErr != nil {
			return "", apperrors.New(
				apperrors.CodeLocalIOError,
				"audit repair replacement failed and quarantine cleanup also failed",
				errors.Join(err, cleanupErr),
			)
		}
		return "", apperrors.New(apperrors.CodeLocalIOError, "failed to replace audit file", err)
	}
	replacementPath = ""
	if err := runtime.syncParent(path); err != nil {
		rollbackErr := rollbackAuditRepair(path, backupPath, quarantinePath, runtime)
		if rollbackErr != nil {
			return "", apperrors.New(
				apperrors.CodeLocalIOError,
				"audit repair state is indeterminate after directory sync and rollback failed",
				errors.Join(err, rollbackErr),
			)
		}
		backupPath = ""
		return "", apperrors.New(
			apperrors.CodeLocalIOError,
			"failed to sync repaired audit directory; original audit file was restored",
			err,
		)
	}

	// The repaired file and quarantine are durable at this point. Cleanup is
	// best-effort because reporting a cleanup error as a failed repair would
	// incorrectly imply that the already committed evidence was unchanged.
	if err := runtime.removeFile(backupPath); err == nil {
		backupPath = ""
		_ = runtime.syncParent(path)
	}
	return quarantinePath, nil
}

func stageOwnerOnlyAuditFile(
	directory string,
	prefix string,
	runtime auditRepairRuntime,
	write func(*os.File) error,
) (string, error) {
	file, tempPath, err := createOwnerOnlyTemp(directory, prefix)
	if err != nil {
		return "", apperrors.New(apperrors.CodeLocalIOError, "failed to create audit repair temp file", err)
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = runtime.removeFile(tempPath)
		}
	}()
	if err := verifyOwnerOnlyFile(tempPath); err != nil {
		return "", err
	}
	if err := write(file); err != nil {
		return "", apperrors.New(apperrors.CodeLocalIOError, "failed to write audit repair temp file", err)
	}
	if err := runtime.syncFile(file); err != nil {
		return "", apperrors.New(apperrors.CodeLocalIOError, "failed to sync audit repair temp file", err)
	}
	if err := file.Close(); err != nil {
		return "", apperrors.New(apperrors.CodeLocalIOError, "failed to close audit repair temp file", err)
	}
	if err := verifyOwnerOnlyFile(tempPath); err != nil {
		return "", err
	}
	keep = true
	return tempPath, nil
}

func validateUnchangedRepairTarget(
	path string,
	sourceInfo os.FileInfo,
	runtime auditRepairRuntime,
) error {
	current, err := runtime.lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return apperrors.New(apperrors.CodeConflict, "audit repair target changed during verification", err)
		}
		return apperrors.New(apperrors.CodeLocalIOError, "failed to revalidate audit repair target", err)
	}
	if current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() {
		return apperrors.New(apperrors.CodeConflict, "audit repair target changed during verification", nil)
	}
	if !os.SameFile(sourceInfo, current) {
		return apperrors.New(apperrors.CodeConflict, "audit repair target changed during verification", nil)
	}
	if err := verifyOwnerOnlyFile(path); err != nil {
		return err
	}
	return nil
}

func rollbackAuditRepair(path, backupPath, quarantinePath string, runtime auditRepairRuntime) error {
	if err := runtime.atomicReplace(backupPath, path); err != nil {
		return errors.Join(err, removeRepairArtifact(quarantinePath, runtime))
	}
	if err := runtime.syncParent(path); err != nil {
		return errors.Join(err, removeRepairArtifact(quarantinePath, runtime))
	}
	return removeRepairArtifact(quarantinePath, runtime)
}

func removeRepairArtifact(path string, runtime auditRepairRuntime) error {
	if err := runtime.removeFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return runtime.syncParent(path)
}

func writeAuditQuarantine(path string, data []byte, now time.Time) (string, error) {
	stamp := now.UTC().Format("20060102-150405")
	for ordinal := uint64(0); ; ordinal++ {
		candidate := fmt.Sprintf("%s.quarantine.%s.log", path, stamp)
		if ordinal > 0 {
			candidate = fmt.Sprintf("%s.quarantine.%s.%d.log", path, stamp, ordinal)
		}
		err := writeOwnerOnlyExclusive(candidate, data)
		if errors.Is(err, os.ErrExist) {
			if ordinal == math.MaxUint64 {
				return "", apperrors.New(apperrors.CodeConflict, "audit quarantine ordinal exhausted", nil)
			}
			continue
		}
		if err != nil {
			return "", err
		}
		return candidate, nil
	}
}

func (state *verifyIntegrityState) verifyLine(line string, fileResult *VerifyFileResult) (bool, error) {
	env, payload, isEnvelope, parseErr := parseEnvelope([]byte(line))
	if isEnvelope {
		state.seenV2 = true
		state.observedV2 = true
		if parseErr != nil {
			fileResult.Malformed++
			fileResult.IntegrityErrors++
			return false, nil
		}
		return state.verifyEnvelopeLine(env, payload, fileResult)
	}
	if state.seenV2 {
		fileResult.LegacyUnauthenticated++
		fileResult.IntegrityErrors++
		if _, ok := parseRawRecordFields([]byte(line)); !ok {
			fileResult.Malformed++
		}
		return false, nil
	}
	return state.verifyLegacyLine(line, fileResult)
}

func (state *verifyIntegrityState) verifyEnvelopeLine(
	env auditEnvelope,
	payload envelopePayload,
	fileResult *VerifyFileResult,
) (bool, error) {
	if len(state.key) == 0 {
		fileResult.IntegrityErrors++
		return false, nil
	}
	prevMAC, mac, err := verifyEnvelope(env, payload, state.key)
	if err != nil {
		fileResult.IntegrityErrors++
		return false, nil
	}
	fileResult.Authenticated++
	expectedSequence := state.sequence + 1
	if env.Sequence != expectedSequence || !hmac.Equal(prevMAC, state.mac) {
		fileResult.SequenceViolations++
		if env.Sequence > expectedSequence || !hmac.Equal(prevMAC, state.mac) {
			state.result.TruncationDetected = true
		}
	}
	state.sequence = env.Sequence
	state.mac = mac

	if payload.encoding == payloadEncodingAge && !state.opts.Decrypt {
		fileResult.Valid++
		fileResult.EncryptedOpaque++
		return true, nil
	}
	plain := payload.plain
	if payload.encoding == payloadEncodingAge {
		plain, err = decryptAgePayload(payload.ciphertext, state.opts.PrivateKey)
		if err != nil {
			return false, err
		}
	}
	return state.verifyPlainLine(plain, fileResult), nil
}

func (state *verifyIntegrityState) verifyLegacyLine(line string, fileResult *VerifyFileResult) (bool, error) {
	fileResult.LegacyUnauthenticated++
	plain := []byte(line)
	if ciphertext, encoded := decodeBase64Line(line); encoded && bytes.HasPrefix(ciphertext, []byte("age-encryption.org/v1")) {
		if !state.opts.Decrypt {
			fileResult.Valid++
			fileResult.EncryptedOpaque++
			return true, nil
		}
		var err error
		plain, err = decryptAgePayload(ciphertext, state.opts.PrivateKey)
		if err != nil {
			return false, err
		}
	}
	return state.verifyPlainLine(plain, fileResult), nil
}

func (state *verifyIntegrityState) verifyPlainLine(plain []byte, fileResult *VerifyFileResult) bool {
	fields, ok := parseRawRecordFields(plain)
	if !ok {
		fileResult.Malformed++
		return false
	}
	fileResult.Valid++
	if fields.Timestamp.IsZero() || fields.EventType == "" || fields.Operator == "" {
		fileResult.SchemaError++
	}
	if !state.previousTimestamp.IsZero() &&
		!fields.Timestamp.IsZero() &&
		fields.Timestamp.Before(state.previousTimestamp) {
		fileResult.TimestampOrderViolations++
	}
	if !fields.Timestamp.IsZero() {
		state.previousTimestamp = fields.Timestamp
	}
	return true
}

func (state *verifyIntegrityState) finish() {
	if state.observedV2 && !state.checkpointValid && !state.checkpointProblemRecorded {
		state.result.CheckpointViolations++
		state.checkpointProblemRecorded = true
	}
	if !state.checkpointValid {
		return
	}
	headSequence, headMAC, err := checkpointHead(state.checkpoint)
	if err != nil {
		state.result.CheckpointViolations++
		return
	}
	if state.sequence == headSequence && hmac.Equal(state.mac, headMAC) {
		return
	}
	state.result.CheckpointViolations++
	if state.sequence < headSequence ||
		(state.sequence == headSequence && !hmac.Equal(state.mac, headMAC)) {
		state.result.TruncationDetected = true
	}
}

func auditArtifactsExist(path, keyPath string) (bool, error) {
	for _, candidate := range []string{path, checkpointPath(path), keyPath, path + ".lock"} {
		_, err := os.Lstat(candidate)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return false, apperrors.New(apperrors.CodeLocalIOError, "failed to inspect audit artifact", err)
		}
	}
	rotated, err := RotatedFiles(path)
	if err != nil {
		return false, err
	}
	return len(rotated) > 0, nil
}

func writeOwnerOnlyExclusive(path string, data []byte) error {
	if err := ensureOwnerOnlyDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	file, err := createOwnerOnlyExclusive(path)
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to create audit evidence file", err)
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if err := verifyOwnerOnlyFile(path); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to write audit evidence file", err)
	}
	if err := file.Sync(); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to sync audit evidence file", err)
	}
	if err := file.Close(); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to close audit evidence file", err)
	}
	if err := verifyOwnerOnlyFile(path); err != nil {
		return err
	}
	if err := syncParentDirectory(path); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to sync audit evidence directory", err)
	}
	ok = true
	return nil
}

func readLockStatus(path string) (VerifyLockStatus, error) {
	lockPath := path + ".lock"
	content, present, err := lockfile.Inspect(path)
	if err != nil {
		return VerifyLockStatus{Path: lockPath}, err
	}
	return VerifyLockStatus{Path: lockPath, Present: present, Content: strings.TrimSpace(content)}, nil
}
