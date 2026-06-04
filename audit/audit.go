// Package audit appends governance events as JSONL.
package audit

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/lockfile"
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
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to create audit directory", err)
	}
	lock := lockfile.New(path)
	if err := lock.Acquire(); err != nil {
		return err
	}
	defer func() { _ = lock.Release() }()
	if err := rotateIfNeeded(path, opts.MaxSizeBytes); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to open audit log", err)
	}
	defer func() { _ = file.Close() }()
	if err := os.Chmod(path, 0o600); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to set audit log permissions", err)
	}
	line, err := encodeRecordLine(record, opts.EncryptPublicKeyPath)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(line, '\n')); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to write audit log", err)
	}
	return nil
}

func encodeRecordLine(record any, publicKeyPath string) ([]byte, error) {
	plain, err := json.Marshal(record)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to marshal audit event", err)
	}
	if strings.TrimSpace(publicKeyPath) == "" {
		return plain, nil
	}
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
	out := make([]byte, base64.StdEncoding.EncodedLen(encrypted.Len()))
	base64.StdEncoding.Encode(out, encrypted.Bytes())
	return out, nil
}

func loadAgeRecipient(path string) (age.Recipient, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read audit encryption public key", err)
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
	if strings.TrimSpace(privateKey) == "" {
		return nil, apperrors.New(apperrors.CodeCredentialStoreError, fmt.Sprintf("audit log encrypted; provide %s", config.PrivateKeyEnvVar), nil)
	}
	identity, err := age.ParseX25519Identity(strings.TrimSpace(privateKey))
	if err != nil {
		return nil, apperrors.New(apperrors.CodeCredentialStoreError, fmt.Sprintf("failed to parse %s", config.PrivateKeyEnvVar), err)
	}
	reader, err := age.Decrypt(bytes.NewReader(decoded), identity)
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
	if err := os.Chmod(rotated, 0o600); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to set rotated audit log permissions", err)
	}
	return nil
}

func nextRotatedPath(path string, now time.Time) (string, error) {
	stamp := now.UTC().Format("20060102-150405")
	candidate := fmt.Sprintf("%s.%s.log", path, stamp)
	if _, err := os.Stat(candidate); os.IsNotExist(err) {
		return candidate, nil
	} else if err != nil {
		return "", apperrors.New(apperrors.CodeLocalIOError, "failed to stat rotated audit log", err)
	}
	for i := 1; ; i++ {
		candidate = fmt.Sprintf("%s.%s.%d.log", path, stamp, i)
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate, nil
		} else if err != nil {
			return "", apperrors.New(apperrors.CodeLocalIOError, "failed to stat rotated audit log", err)
		}
	}
}

// RotatedFiles returns rotated audit log paths sorted by filename timestamp.
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
	sortStrings(out)
	return out, nil
}

// RotatedFileTimestamp returns the timestamp encoded in a rotated audit file.
func RotatedFileTimestamp(activePath, candidate string) (time.Time, bool) {
	base := filepath.Base(candidate)
	active := filepath.Base(activePath)
	if !strings.HasPrefix(base, active+".") || !strings.HasSuffix(base, ".log") {
		return time.Time{}, false
	}
	stamp := strings.TrimSuffix(strings.TrimPrefix(base, active+"."), ".log")
	if i := strings.Index(stamp, "."); i >= 0 {
		stamp = stamp[:i]
	}
	t, err := time.Parse("20060102-150405", stamp)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func isRotatedAuditLog(activePath, candidate string) bool {
	_, ok := RotatedFileTimestamp(activePath, candidate)
	return ok
}

func sortStrings(values []string) {
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
}
