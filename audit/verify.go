package audit

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/JiangHe12/opskit-core/apperrors"
)

// VerifyOptions controls audit log verification.
type VerifyOptions struct {
	Decrypt    bool
	PrivateKey string
	Repair     bool
	Confirm    bool
}

// VerifyResult summarizes audit log verification.
type VerifyResult struct {
	Files                    []VerifyFileResult `json:"files"`
	Total                    int                `json:"total"`
	Valid                    int                `json:"valid"`
	Malformed                int                `json:"malformed"`
	SchemaErrors             int                `json:"schemaErrors"`
	TimestampOrderViolations int                `json:"timestampOrderViolations"`
	Lock                     VerifyLockStatus   `json:"lock"`
}

// VerifyFileResult summarizes one active or rotated audit file.
type VerifyFileResult struct {
	Path        string `json:"path"`
	Total       int    `json:"total"`
	Valid       int    `json:"valid"`
	Malformed   int    `json:"malformed"`
	Quarantine  string `json:"quarantine,omitempty"`
	Repaired    bool   `json:"repaired,omitempty"`
	SchemaError int    `json:"schemaErrors,omitempty"`
}

// VerifyLockStatus reports the active audit lock file if present.
type VerifyLockStatus struct {
	Path    string `json:"path,omitempty"`
	Present bool   `json:"present"`
	Content string `json:"content,omitempty"`
}

// Verify scans active and rotated audit files for malformed entries and basic
// schema/timestamp invariants.
func Verify(path string, opts VerifyOptions) (VerifyResult, error) {
	result := VerifyResult{Files: []VerifyFileResult{}, Lock: readLockStatus(path)}
	files, err := queryFiles(path)
	if err != nil {
		return result, err
	}
	var previous time.Time
	for _, filePath := range files {
		fileResult, last, violations, err := verifyOneFile(filePath, opts, previous)
		if err != nil {
			return result, err
		}
		if last != nil {
			previous = *last
		}
		result.Files = append(result.Files, fileResult)
		result.Total += fileResult.Total
		result.Valid += fileResult.Valid
		result.Malformed += fileResult.Malformed
		result.SchemaErrors += fileResult.SchemaError
		result.TimestampOrderViolations += violations
	}
	return result, nil
}

//nolint:gocyclo // Single-pass streaming keeps repair/quarantine behavior atomic per file.
func verifyOneFile(path string, opts VerifyOptions, previous time.Time) (VerifyFileResult, *time.Time, int, error) {
	fileResult := VerifyFileResult{Path: path}
	file, err := os.Open(path) //nolint:gosec // path is user-supplied audit log location.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fileResult, nil, 0, nil
		}
		return fileResult, nil, 0, apperrors.New(apperrors.CodeLocalIOError, "failed to open audit log", err)
	}
	defer func() { _ = file.Close() }()

	var kept bytes.Buffer
	var quarantine bytes.Buffer
	last := previous
	violations := 0
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fileResult.Total++
		fields, malformed, err := verifyLine(line, opts)
		if err != nil {
			return fileResult, nil, violations, err
		}
		if malformed {
			fileResult.Malformed++
			quarantine.WriteString(raw)
			quarantine.WriteByte('\n')
			continue
		}
		fileResult.Valid++
		if fields.Timestamp.IsZero() || fields.EventType == "" || fields.Operator == "" {
			fileResult.SchemaError++
		}
		if !last.IsZero() && !fields.Timestamp.IsZero() && fields.Timestamp.Before(last) {
			violations++
		}
		if !fields.Timestamp.IsZero() {
			last = fields.Timestamp
		}
		kept.WriteString(raw)
		kept.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return fileResult, nil, violations, apperrors.New(apperrors.CodeLocalIOError, "failed to read audit log", err)
	}
	if opts.Repair && opts.Confirm && fileResult.Malformed > 0 {
		quarantinePath := fmt.Sprintf("%s.quarantine.%s.log", path, time.Now().UTC().Format("20060102-150405"))
		if err := os.WriteFile(quarantinePath, quarantine.Bytes(), 0o600); err != nil {
			return fileResult, nil, violations, apperrors.New(apperrors.CodeLocalIOError, "failed to write audit quarantine file", err)
		}
		if err := os.WriteFile(path, kept.Bytes(), 0o600); err != nil {
			return fileResult, nil, violations, apperrors.New(apperrors.CodeLocalIOError, "failed to repair audit log", err)
		}
		fileResult.Quarantine = quarantinePath
		fileResult.Repaired = true
	}
	if last.IsZero() {
		return fileResult, nil, violations, nil
	}
	return fileResult, &last, violations, nil
}

func verifyLine(line string, opts VerifyOptions) (rawRecordFields, bool, error) {
	plain := []byte(line)
	if opts.Decrypt {
		var err error
		plain, err = decryptAuditLine(line, opts.PrivateKey)
		if err != nil {
			return rawRecordFields{}, false, err
		}
	}
	fields, ok := parseRawRecordFields(plain)
	if !ok {
		return rawRecordFields{}, true, nil
	}
	return fields, false, nil
}

func readLockStatus(path string) VerifyLockStatus {
	lockPath := path + ".lock"
	data, err := os.ReadFile(lockPath) //nolint:gosec // lock path is derived from audit path.
	if err != nil {
		return VerifyLockStatus{Path: lockPath, Present: false}
	}
	return VerifyLockStatus{Path: lockPath, Present: true, Content: strings.TrimSpace(string(data))}
}
