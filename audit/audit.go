// Package audit appends governance events as JSONL.
package audit

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/lockfile"
)

// EventType is an audit event category.
type EventType string

const (
	EventContextExport       EventType = "ctx.export"
	EventContextImport       EventType = "ctx.import"
	EventContextTest         EventType = "ctx.test"
	EventBackupPrune         EventType = "backup.prune"
	EventRoleAssign          EventType = "role.assign"
	EventRoleRevoke          EventType = "role.revoke"
	EventRoleFetch           EventType = "role.fetch"
	EventAuditPrune          EventType = "audit.prune"
	EventAuthorizationDenied EventType = "authorization.denied"
)

// DefaultMaxSizeBytes is the default active audit log size before rotation.
const DefaultMaxSizeBytes int64 = 100 * 1024 * 1024

const maxAgeRecipientFileBytes int64 = 64 * 1024

// Event status values written to Event.Status.
const (
	StatusPending       = "pending"
	StatusDenied        = "denied"
	StatusSuccess       = "success"
	StatusFailed        = "failed"
	StatusPartialFailed = "partial-failed"
)

// Config controls package-level defaults for audit logs.
type Config struct {
	APIVersion         string
	ConfigDirName      string
	PrivateKeyEnvVar   string
	TargetTypeJSONName string
	TimestampJSONName  string
	EventTypeJSONName  string
	OperatorJSONName   string
}

var config = Config{
	APIVersion:         "opskit-core.io/audit/v1",
	ConfigDirName:      ".opskit",
	PrivateKeyEnvVar:   "OPSKIT_AUDIT_PRIVATE_KEY",
	TargetTypeJSONName: "resourceType",
	TimestampJSONName:  "timestamp",
	EventTypeJSONName:  "eventType",
	OperatorJSONName:   "operator",
}

// Configure sets package-level audit defaults for a consumer CLI.
func Configure(next Config) {
	if next.APIVersion != "" {
		config.APIVersion = next.APIVersion
	}
	if next.ConfigDirName != "" {
		config.ConfigDirName = next.ConfigDirName
	}
	if next.PrivateKeyEnvVar != "" {
		config.PrivateKeyEnvVar = next.PrivateKeyEnvVar
	}
	if next.TargetTypeJSONName != "" {
		config.TargetTypeJSONName = next.TargetTypeJSONName
	}
	if next.TimestampJSONName != "" {
		config.TimestampJSONName = next.TimestampJSONName
	}
	if next.EventTypeJSONName != "" {
		config.EventTypeJSONName = next.EventTypeJSONName
	}
	if next.OperatorJSONName != "" {
		config.OperatorJSONName = next.OperatorJSONName
	}
}

// APIVersion returns the apiVersion stamp emitted by audit query JSON output.
func APIVersion() string { return config.APIVersion }

// Event is one JSONL audit record.
type Event struct {
	Timestamp   time.Time             `json:"timestamp"`
	EventType   EventType             `json:"eventType"`
	Operator    string                `json:"operator,omitempty"`
	Context     EventContext          `json:"context"`
	Ticket      string                `json:"ticket,omitempty"`
	Reason      string                `json:"reason,omitempty"`
	Target      EventTarget           `json:"target"`
	Status      string                `json:"status"`
	Diff        string                `json:"diff,omitempty"`
	Error       *EventError           `json:"error,omitempty"`
	RoleChange  *EventRoleChange      `json:"roleChange,omitempty"`
	AuditPrune  *AuditPruneDetail     `json:"auditPrune,omitempty"`
	BackupPrune *BackupPruneDetail    `json:"backupPrune,omitempty"`
	RoleFetch   *EventRoleFetchDetail `json:"roleFetch,omitempty"`
}

// EventContext identifies the active context.
type EventContext struct {
	Name      string `json:"name,omitempty"`
	Env       string `json:"env,omitempty"`
	Protected bool   `json:"protected,omitempty"`
}

// EventTarget identifies the changed resource set.
type EventTarget struct {
	App          string `json:"app,omitempty"`
	ResourceType string `json:"-"`
	Resource     string `json:"resource,omitempty"`
}

func (t EventTarget) MarshalJSON() ([]byte, error) {
	m := map[string]string{}
	if t.App != "" {
		m["app"] = t.App
	}
	if t.ResourceType != "" {
		m[config.TargetTypeJSONName] = t.ResourceType
	}
	if t.Resource != "" {
		m["resource"] = t.Resource
	}
	return json.Marshal(m)
}

func (t *EventTarget) UnmarshalJSON(data []byte) error {
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	t.App = m["app"]
	t.Resource = m["resource"]
	t.ResourceType = m[config.TargetTypeJSONName]
	if t.ResourceType == "" && config.TargetTypeJSONName != "resourceType" {
		t.ResourceType = m["resourceType"]
	}
	return nil
}

// EventError records a failed result.
type EventError struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
}

// EventRoleChange records RBAC role assignments and revocations.
type EventRoleChange struct {
	ChangedOperator string `json:"changedOperator"`
	Role            string `json:"role,omitempty"`
}

// EventRoleFetchDetail records remote RBAC role fetches.
type EventRoleFetchDetail struct {
	URL        string `json:"url,omitempty"`
	CacheState string `json:"cacheState"`
}

// AuditPruneDetail records audit rotated files pruned by audit prune.
type AuditPruneDetail struct {
	DeletedFiles []string `json:"deletedFiles"`
	Count        int      `json:"count"`
}

// BackupPruneDetail records backup snapshots pruned after new backups.
type BackupPruneDetail struct {
	DeletedDirs []string `json:"deletedDirs"`
	Count       int      `json:"count"`
}

// Options controls audit append behavior.
type Options struct {
	MaxSizeBytes         int64
	EncryptPublicKeyPath string
	IntegrityKeyPath     string
}

// AppendCommitState reports whether an AppendRecordWithResult call durably
// committed its record.
type AppendCommitState string

const (
	// AppendCommitNotCommitted means the record is absent, including after a
	// successful truncate-and-sync rollback of a failed write.
	AppendCommitNotCommitted AppendCommitState = "not-committed"
	// AppendCommitCommitted means the record reached the platform commit point
	// and all post-commit bookkeeping completed.
	AppendCommitCommitted AppendCommitState = "committed"
	// AppendCommitCommittedPostCommitError means the record reached the
	// platform commit point, but later checkpoint or lock cleanup failed.
	AppendCommitCommittedPostCommitError AppendCommitState = "committed-postcommit-error"
	// AppendCommitIndeterminate means the record may be present because neither
	// commit nor a durable rollback could be established.
	AppendCommitIndeterminate AppendCommitState = "indeterminate"
)

// AppendResult describes the durable record state returned by
// AppendRecordWithResult.
type AppendResult struct {
	State AppendCommitState
}

// IsCommitted reports whether the record is known to have reached its platform
// commit point, even if a later operation returned an error.
func (result AppendResult) IsCommitted() bool {
	return result.State == AppendCommitCommitted ||
		result.State == AppendCommitCommittedPostCommitError
}

type appendRecordRuntime struct {
	writeFile       func(*os.File, []byte) (int, error)
	syncFile        func(*os.File) error
	truncateFile    func(*os.File, int64) error
	closeFile       func(*os.File) error
	syncParent      func(string) error
	writeCheckpoint func(string, auditCheckpoint) error
	releaseLock     func(*lockfile.Lock) error
}

var productionAppendRecordRuntime = appendRecordRuntime{
	writeFile: func(file *os.File, data []byte) (int, error) {
		return file.Write(data)
	},
	syncFile: func(file *os.File) error {
		return file.Sync()
	},
	truncateFile: func(file *os.File, size int64) error {
		return file.Truncate(size)
	},
	closeFile: func(file *os.File) error {
		return file.Close()
	},
	syncParent:      syncParentDirectory,
	writeCheckpoint: writeCheckpoint,
	releaseLock: func(lock *lockfile.Lock) error {
		return lock.Release()
	},
}

// DefaultPath returns the default audit log path.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, config.ConfigDirName, "audit.log"), nil
}

// Append appends one JSONL event. The file is owner-only.
func Append(path string, event Event) error {
	return AppendWithOptions(path, event, Options{})
}

// AppendWithOptions appends one JSONL event and rotates the active log when it exceeds the configured max size.
func AppendWithOptions(path string, event Event, opts Options) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	return AppendRecord(path, event, opts)
}

// AppendRecord appends one JSONL record using the record's own JSON shape.
func AppendRecord(path string, record any, opts Options) error {
	_, err := AppendRecordWithResult(path, record, opts)
	return err
}

// AppendRecordWithResult appends one JSONL record and reports its durable
// commit state. Existing active files commit when the appended bytes are
// fsynced. Newly created active files additionally pass the platform parent
// directory sync step: POSIX fsyncs the directory, while Windows treats the
// synced and closed file as the available platform durability boundary because
// directory handles do not provide the POSIX fsync contract.
//
// A write or file-sync failure is rolled back with Truncate followed by Sync
// while the audit lock is still held. A successful rollback is
// AppendCommitNotCommitted; a failed rollback is AppendCommitIndeterminate.
func AppendRecordWithResult(path string, record any, opts Options) (AppendResult, error) {
	return appendRecordWithResult(path, record, opts, productionAppendRecordRuntime)
}

func appendRecordWithResult(
	path string,
	record any,
	opts Options,
	runtime appendRecordRuntime,
) (result AppendResult, retErr error) {
	result.State = AppendCommitNotCommitted
	if err := ensureOwnerOnlyDirectory(filepath.Dir(path)); err != nil {
		return result, err
	}
	lock := lockfile.New(path)
	if err := lock.Acquire(); err != nil {
		return result, err
	}
	defer func() {
		if err := runtime.releaseLock(lock); err != nil {
			if result.State == AppendCommitCommitted {
				result.State = AppendCommitCommittedPostCommitError
			}
			if retErr == nil {
				retErr = apperrors.New(apperrors.CodeLocalIOError, "failed to release audit append lock", err)
			}
		}
	}()
	keyPath := effectiveIntegrityKeyPath(path, opts.IntegrityKeyPath)
	key, checkpoint, checkpointExists, err := prepareAppendIntegrity(path, keyPath)
	if err != nil {
		return result, err
	}
	headSequence := uint64(0)
	var headMAC []byte
	baseSequence := uint64(0)
	var baseMAC []byte
	if checkpointExists {
		baseSequence, baseMAC, err = checkpointBase(checkpoint)
		if err != nil {
			return result, apperrors.New(apperrors.CodeValidationFailed, "invalid audit checkpoint base", err)
		}
		headSequence, headMAC, err = checkpointHead(checkpoint)
		if err != nil {
			return result, apperrors.New(apperrors.CodeValidationFailed, "invalid audit checkpoint head", err)
		}
	}
	sequence, err := nextSequence(headSequence)
	if err != nil {
		return result, err
	}
	line, mac, err := encodeEnvelope(record, opts.EncryptPublicKeyPath, key, sequence, headMAC)
	if err != nil {
		return result, err
	}
	if err := validateAuditLineSize(line); err != nil {
		return result, err
	}
	if !checkpointExists {
		genesis := makeCheckpoint(key, 0, nil, 0, nil)
		if err := runtime.writeCheckpoint(path, genesis); err != nil {
			return result, err
		}
	}
	if err := rotateIfNeeded(path, opts.MaxSizeBytes); err != nil {
		return result, err
	}
	file, created, err := openAuditAppendFile(path)
	if err != nil {
		return result, err
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	framedLine, originalSize, err := frameAuditAppend(file, line)
	if err != nil {
		if closeErr := runtime.closeFile(file); closeErr == nil {
			closed = true
		}
		return result, err
	}
	if _, err := file.Seek(originalSize, io.SeekStart); err != nil {
		if closeErr := runtime.closeFile(file); closeErr == nil {
			closed = true
		}
		return result, apperrors.New(apperrors.CodeLocalIOError, "failed to position audit log for append", err)
	}
	written, writeErr := runtime.writeFile(file, framedLine)
	if writeErr != nil || written != len(framedLine) {
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		rollbackErr := rollbackAuditAppend(file, originalSize, runtime)
		if closeErr := runtime.closeFile(file); closeErr == nil {
			closed = true
		}
		if rollbackErr != nil {
			result.State = AppendCommitIndeterminate
			return result, apperrors.New(
				apperrors.CodeLocalIOError,
				"audit append state is indeterminate after write rollback failed",
				rollbackErr,
			)
		}
		return result, apperrors.New(apperrors.CodeLocalIOError, "failed to write audit log", writeErr)
	}
	if err := runtime.syncFile(file); err != nil {
		rollbackErr := rollbackAuditAppend(file, originalSize, runtime)
		if closeErr := runtime.closeFile(file); closeErr == nil {
			closed = true
		}
		if rollbackErr != nil {
			result.State = AppendCommitIndeterminate
			return result, apperrors.New(
				apperrors.CodeLocalIOError,
				"audit append state is indeterminate after sync rollback failed",
				rollbackErr,
			)
		}
		return result, apperrors.New(apperrors.CodeLocalIOError, "failed to sync audit log", err)
	}
	if !created {
		result.State = AppendCommitCommitted
	}
	if err := runtime.closeFile(file); err != nil {
		if created {
			result.State = AppendCommitIndeterminate
		} else {
			result.State = AppendCommitCommittedPostCommitError
		}
		return result, apperrors.New(apperrors.CodeLocalIOError, "failed to close audit log", err)
	}
	closed = true
	if created {
		if err := runtime.syncParent(path); err != nil {
			result.State = AppendCommitIndeterminate
			return result, apperrors.New(apperrors.CodeLocalIOError, "failed to sync audit log directory", err)
		}
		result.State = AppendCommitCommitted
	}
	nextCheckpoint := makeCheckpoint(key, baseSequence, baseMAC, sequence, mac)
	if err := runtime.writeCheckpoint(path, nextCheckpoint); err != nil {
		result.State = AppendCommitCommittedPostCommitError
		return result, err
	}
	return result, nil
}

func rollbackAuditAppend(file *os.File, originalSize int64, runtime appendRecordRuntime) error {
	if err := runtime.truncateFile(file, originalSize); err != nil {
		return err
	}
	return runtime.syncFile(file)
}

func openAuditAppendFile(path string) (*os.File, bool, error) {
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, false, apperrors.New(apperrors.CodeLocalIOError, "audit path must be a regular file", nil)
		}
		if err := secureOwnerOnlyFile(path); err != nil {
			return nil, false, err
		}
		file, openErr := os.OpenFile(path, os.O_RDWR, 0o600) //nolint:gosec // Existing audit path was validated above and the audit lock serializes writes.
		if openErr != nil {
			return nil, false, apperrors.New(apperrors.CodeLocalIOError, "failed to open audit log", openErr)
		}
		return file, false, nil
	case os.IsNotExist(err):
		file, openErr := createOwnerOnlyExclusive(path)
		if openErr != nil {
			return nil, false, apperrors.New(apperrors.CodeLocalIOError, "failed to create audit log", openErr)
		}
		if secureErr := verifyOwnerOnlyFile(path); secureErr != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return nil, false, secureErr
		}
		return file, true, nil
	default:
		return nil, false, apperrors.New(apperrors.CodeLocalIOError, "failed to inspect audit log", err)
	}
}

func frameAuditAppend(file *os.File, line []byte) ([]byte, int64, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, 0, apperrors.New(apperrors.CodeLocalIOError, "failed to stat audit log before append", err)
	}
	prefix := byte(0)
	if info.Size() > 0 {
		var tail [1]byte
		if _, err := file.ReadAt(tail[:], info.Size()-1); err != nil {
			return nil, 0, apperrors.New(apperrors.CodeLocalIOError, "failed to inspect audit log framing", err)
		}
		if tail[0] != '\n' {
			prefix = '\n'
		}
	}
	framed := make([]byte, 0, len(line)+2)
	if prefix != 0 {
		framed = append(framed, prefix)
	}
	framed = append(framed, line...)
	framed = append(framed, '\n')
	return framed, info.Size(), nil
}

func encryptAuditPayload(plain []byte, publicKeyPath string) ([]byte, error) {
	recipient, err := loadAgeRecipient(publicKeyPath)
	if err != nil {
		return nil, err
	}
	var encrypted bytes.Buffer
	writer, err := age.Encrypt(&encrypted, recipient)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to initialize audit encryption", err)
	}
	if _, err := writer.Write(plain); err != nil {
		_ = writer.Close()
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to encrypt audit event", err)
	}
	if err := writer.Close(); err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to finalize audit encryption", err)
	}
	return encrypted.Bytes(), nil
}

func loadAgeRecipient(path string) (age.Recipient, error) {
	file, err := openAuditRecipientFile(path)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read audit encryption public key", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to stat audit encryption public key", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxAgeRecipientFileBytes {
		return nil, apperrors.New(
			apperrors.CodeValidationFailed,
			"audit encryption public key must be a bounded regular file",
			nil,
		)
	}
	if err := verifyAuditRecipientFile(file, info, path); err != nil {
		return nil, err
	}
	if err := validateAuditDirectoryChain(filepath.Dir(path), true); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxAgeRecipientFileBytes+1))
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read audit encryption public key", err)
	}
	if int64(len(data)) > maxAgeRecipientFileBytes {
		return nil, apperrors.New(
			apperrors.CodeValidationFailed,
			"audit encryption public key exceeds the maximum supported size",
			nil,
		)
	}
	recipient, err := age.ParseX25519Recipient(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to parse audit encryption public key", err)
	}
	return recipient, nil
}

func decryptAuditLine(line string, privateKey string) ([]byte, error) {
	decoded, ok := decodeBase64Line(line)
	if !ok {
		return []byte(line), nil
	}
	if !bytes.HasPrefix(decoded, []byte("age-encryption.org/v1")) {
		return []byte(line), nil
	}
	return decryptAgePayload(decoded, privateKey)
}

func decryptAgePayload(ciphertext []byte, privateKey string) ([]byte, error) {
	if strings.TrimSpace(privateKey) == "" {
		return nil, apperrors.New(apperrors.CodeCredentialStoreError, fmt.Sprintf("audit log encrypted; provide %s", config.PrivateKeyEnvVar), nil)
	}
	identity, err := age.ParseX25519Identity(strings.TrimSpace(privateKey))
	if err != nil {
		return nil, apperrors.New(apperrors.CodeCredentialStoreError, fmt.Sprintf("failed to parse %s", config.PrivateKeyEnvVar), err)
	}
	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeCredentialStoreError, "failed to decrypt audit log entry", err)
	}
	plain, err := io.ReadAll(reader)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeCredentialStoreError, "failed to read decrypted audit log entry", err)
	}
	return plain, nil
}

func decodeBase64Line(line string) ([]byte, bool) {
	decoded, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return nil, false
	}
	return decoded, true
}

func rotateIfNeeded(path string, maxSize int64) error {
	if maxSize <= 0 {
		maxSize = DefaultMaxSizeBytes
	}
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to stat audit log", err)
	}
	if !info.Mode().IsRegular() {
		return apperrors.New(apperrors.CodeLocalIOError, "audit path must be a regular file", nil)
	}
	if err := secureOwnerOnlyFile(path); err != nil {
		return err
	}
	if info.Size() <= maxSize {
		return nil
	}
	rotated, err := nextRotatedPath(path, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := os.Rename(path, rotated); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to rotate audit log", err)
	}
	if err := syncParentDirectory(rotated); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to sync rotated audit log directory", err)
	}
	if err := secureOwnerOnlyFile(rotated); err != nil {
		return err
	}
	return nil
}

func nextRotatedPath(path string, now time.Time) (string, error) {
	stampTime := now.UTC().Truncate(time.Second)
	ordinal := uint64(0)
	rotated, err := RotatedFiles(path)
	if err != nil {
		return "", err
	}
	if len(rotated) > 0 {
		latestTime, latestOrdinal, ok := rotatedFileOrder(path, rotated[len(rotated)-1])
		if ok && !stampTime.After(latestTime) {
			stampTime = latestTime
			if latestOrdinal == math.MaxUint64 {
				return "", apperrors.New(apperrors.CodeConflict, "audit rotation ordinal exhausted", nil)
			}
			ordinal = latestOrdinal + 1
		}
	}
	stamp := stampTime.Format("20060102-150405")
	for {
		candidate := fmt.Sprintf("%s.%s.log", path, stamp)
		if ordinal > 0 {
			candidate = fmt.Sprintf("%s.%s.%d.log", path, stamp, ordinal)
		}
		if _, err := os.Lstat(candidate); os.IsNotExist(err) {
			return candidate, nil
		} else if err != nil {
			return "", apperrors.New(apperrors.CodeLocalIOError, "failed to stat rotated audit log", err)
		}
		if ordinal == math.MaxUint64 {
			return "", apperrors.New(apperrors.CodeConflict, "audit rotation ordinal exhausted", nil)
		}
		ordinal++
	}
}

// RotatedFiles returns strictly named rotated audit logs sorted by timestamp and numeric collision suffix.
func RotatedFiles(path string) ([]string, error) {
	matches, err := filepath.Glob(path + ".*.log")
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to list rotated audit logs", err)
	}
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		if isRotatedAuditLog(path, match) {
			out = append(out, match)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		ti, oi, _ := rotatedFileOrder(path, out[i])
		tj, oj, _ := rotatedFileOrder(path, out[j])
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		if oi != oj {
			return oi < oj
		}
		return out[i] < out[j]
	})
	return out, nil
}

// RotatedFileTimestamp returns the timestamp encoded in a rotated audit file.
func RotatedFileTimestamp(activePath, candidate string) (time.Time, bool) {
	timestamp, _, ok := rotatedFileOrder(activePath, candidate)
	return timestamp, ok
}

func rotatedFileOrder(activePath, candidate string) (time.Time, uint64, bool) {
	if filepath.Clean(filepath.Dir(activePath)) != filepath.Clean(filepath.Dir(candidate)) {
		return time.Time{}, 0, false
	}
	base := filepath.Base(candidate)
	active := filepath.Base(activePath)
	if !strings.HasPrefix(base, active+".") || !strings.HasSuffix(base, ".log") {
		return time.Time{}, 0, false
	}
	stem := strings.TrimSuffix(strings.TrimPrefix(base, active+"."), ".log")
	parts := strings.Split(stem, ".")
	if len(parts) < 1 || len(parts) > 2 {
		return time.Time{}, 0, false
	}
	t, err := time.Parse("20060102-150405", parts[0])
	if err != nil {
		return time.Time{}, 0, false
	}
	ordinal := uint64(0)
	if len(parts) == 2 {
		if parts[1] == "" || (len(parts[1]) > 1 && parts[1][0] == '0') {
			return time.Time{}, 0, false
		}
		ordinal, err = strconv.ParseUint(parts[1], 10, 64)
		if err != nil || ordinal <= 0 {
			return time.Time{}, 0, false
		}
	}
	return t.UTC(), ordinal, true
}

func isRotatedAuditLog(activePath, candidate string) bool {
	_, ok := RotatedFileTimestamp(activePath, candidate)
	return ok
}
