package audit

import (
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/lockfile"
)

// Filter is the set of optional predicates applied to audit log entries.
// All fields are AND-combined. Empty string fields mean "no filter".
type Filter struct {
	Since            *time.Time
	Until            *time.Time
	EventType        string
	Operator         string
	ContextName      string
	Env              string
	Protected        *bool
	Ticket           string
	App              string
	ResourceType     string
	Resource         string
	Status           string
	Limit            int
	Reverse          bool
	PrivateKey       string
	IntegrityKeyPath string
}

// Result aggregates matched events and a count of unparseable lines skipped.
type Result struct {
	Events           []Event
	MalformedEntries int
}

// RawRecord is one matched audit row plus the fields parsed for filtering.
type RawRecord struct {
	Line      string
	Timestamp time.Time
	EventType string
	Operator  string
}

// RawResult aggregates matched raw rows and a count of unparseable lines skipped.
type RawResult struct {
	Records          []RawRecord
	MalformedEntries int
}

var relativeTimeRE = regexp.MustCompile(`^(\d+)(s|m|h|d|w)$`)

// ParseTime parses a --since/--until value. Accepts either a relative offset
// (24h / 7d / 30m / 90s / 2w) interpreted as "now minus duration", or an
// absolute RFC3339 timestamp.
func ParseTime(value string, now time.Time) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, fmt.Errorf("empty time value")
	}
	if matches := relativeTimeRE.FindStringSubmatch(value); matches != nil {
		n, err := strconv.Atoi(matches[1])
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid relative time %q", value)
		}
		var unit time.Duration
		switch matches[2] {
		case "s":
			unit = time.Second
		case "m":
			unit = time.Minute
		case "h":
			unit = time.Hour
		case "d":
			unit = 24 * time.Hour
		case "w":
			unit = 7 * 24 * time.Hour
		}
		return now.Add(-time.Duration(n) * unit), nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid time %q: expected relative (24h/7d/30m) or RFC3339", value)
	}
	return t, nil
}

// Query streams an audit log file, returning entries that satisfy the filter.
// File-not-exist is not an error: callers get an empty Result.
// Lines that fail JSON decode are skipped and counted in Result.MalformedEntries.
func Query(path string, filter Filter) (Result, error) {
	result := Result{Events: []Event{}}
	err := withAuditReadSnapshot(path, filter.IntegrityKeyPath, func() error {
		files, err := queryFiles(path)
		if err != nil {
			return err
		}
		integrity, err := newIntegrityReadState(path, filter.IntegrityKeyPath)
		if err != nil {
			return err
		}
		for _, filePath := range files {
			if err := queryOneFile(filePath, filter, integrity, &result); err != nil {
				return err
			}
		}
		return integrity.finish()
	})
	if err != nil {
		return result, err
	}
	if filter.Reverse {
		sort.SliceStable(result.Events, func(i, j int) bool {
			return result.Events[i].Timestamp.After(result.Events[j].Timestamp)
		})
		if filter.Limit > 0 && len(result.Events) > filter.Limit {
			result.Events = result.Events[:filter.Limit]
		}
	}
	return result, nil
}

// QueryRaw streams audit logs and returns matching raw JSONL rows.
func QueryRaw(path string, filter Filter) (RawResult, error) {
	result := RawResult{Records: []RawRecord{}}
	err := withAuditReadSnapshot(path, filter.IntegrityKeyPath, func() error {
		files, err := queryFiles(path)
		if err != nil {
			return err
		}
		integrity, err := newIntegrityReadState(path, filter.IntegrityKeyPath)
		if err != nil {
			return err
		}
		for _, filePath := range files {
			if err := queryOneFileRaw(filePath, filter, integrity, &result); err != nil {
				return err
			}
		}
		return integrity.finish()
	})
	if err != nil {
		return result, err
	}
	if filter.Reverse {
		sort.SliceStable(result.Records, func(i, j int) bool {
			return result.Records[i].Timestamp.After(result.Records[j].Timestamp)
		})
		if filter.Limit > 0 && len(result.Records) > filter.Limit {
			result.Records = result.Records[:filter.Limit]
		}
	}
	return result, nil
}

func withAuditReadSnapshot(path, keyOverride string, read func() error) error {
	keyPath := effectiveIntegrityKeyPath(path, keyOverride)
	if err := validateIntegrityKeyPath(path, keyPath); err != nil {
		return err
	}
	hasArtifacts, err := auditArtifactsExist(path, keyPath)
	if err != nil {
		return err
	}
	if !hasArtifacts {
		return nil
	}
	if err := validateAuditArtifactParent(path); err != nil {
		return err
	}
	lock := lockfile.New(path)
	if err := lock.Acquire(); err != nil {
		return err
	}
	defer func() { _ = lock.Release() }()
	return read()
}

func queryFiles(path string) ([]string, error) {
	rotated, err := RotatedFiles(path)
	if err != nil {
		return nil, err
	}
	files := append([]string{}, rotated...)
	files = append(files, path)
	return files, nil
}

type integrityReadState struct {
	key              []byte
	checkpoint       auditCheckpoint
	checkpointExists bool
	seenV2           bool
	sequence         uint64
	mac              []byte
}

func newIntegrityReadState(path, keyOverride string) (*integrityReadState, error) {
	state := &integrityReadState{}
	keyPath := effectiveIntegrityKeyPath(path, keyOverride)
	if err := validateIntegrityKeyPath(path, keyPath); err != nil {
		return nil, err
	}
	checkpointExists, err := pathExists(checkpointPath(path))
	if err != nil {
		return nil, err
	}
	keyExists, err := pathExists(keyPath)
	if err != nil {
		return nil, err
	}
	if checkpointExists && !keyExists {
		return nil, apperrors.New(
			apperrors.CodeValidationFailed,
			"audit integrity key is missing for authenticated audit history",
			nil,
		)
	}
	if !keyExists {
		return state, nil
	}
	state.key, err = loadIntegrityKey(keyPath)
	if err != nil {
		return nil, err
	}
	if !checkpointExists {
		return state, nil
	}
	state.checkpoint, state.checkpointExists, err = loadCheckpoint(path, state.key)
	if err != nil {
		return nil, err
	}
	state.sequence, state.mac, err = checkpointBase(state.checkpoint)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeValidationFailed, "invalid audit checkpoint base", err)
	}
	state.seenV2 = state.sequence > 0
	return state, nil
}

func (state *integrityReadState) decode(line, privateKey string) ([]byte, error) {
	env, payload, isEnvelope, err := parseEnvelope([]byte(line))
	if err != nil {
		return nil, apperrors.New(apperrors.CodeValidationFailed, "invalid audit envelope", err)
	}
	if !isEnvelope {
		if state.seenV2 {
			return nil, apperrors.New(
				apperrors.CodeValidationFailed,
				"unauthenticated audit record follows authenticated history",
				nil,
			)
		}
		return decryptAuditLine(line, privateKey)
	}
	if len(state.key) == 0 {
		return nil, apperrors.New(
			apperrors.CodeValidationFailed,
			"audit integrity key is missing for authenticated audit history",
			nil,
		)
	}
	if !state.checkpointExists {
		return nil, apperrors.New(
			apperrors.CodeValidationFailed,
			"audit checkpoint is missing for authenticated audit history",
			nil,
		)
	}
	prevMAC, mac, err := verifyEnvelope(env, payload, state.key)
	if err != nil {
		return nil, apperrors.New(apperrors.CodeValidationFailed, "audit envelope authentication failed", err)
	}
	if env.Sequence != state.sequence+1 || !hmac.Equal(prevMAC, state.mac) {
		return nil, apperrors.New(apperrors.CodeValidationFailed, "audit envelope chain is discontinuous", nil)
	}
	state.seenV2 = true
	state.sequence = env.Sequence
	state.mac = mac
	if payload.encoding == payloadEncodingAge {
		return decryptAgePayload(payload.ciphertext, privateKey)
	}
	return payload.plain, nil
}

func (state *integrityReadState) finish() error {
	if !state.checkpointExists {
		return nil
	}
	headSequence, headMAC, err := checkpointHead(state.checkpoint)
	if err != nil {
		return apperrors.New(apperrors.CodeValidationFailed, "invalid audit checkpoint head", err)
	}
	if state.sequence != headSequence || !hmac.Equal(state.mac, headMAC) {
		return apperrors.New(
			apperrors.CodeValidationFailed,
			"audit history does not match its checkpoint head",
			nil,
		)
	}
	return nil
}

func queryOneFile(path string, filter Filter, integrity *integrityReadState, result *Result) error {
	file, err := openAuditReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer func() { _ = file.Close() }()

	scanner := newAuditScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		plain, err := integrity.decode(line, filter.PrivateKey)
		if err != nil {
			return err
		}
		fields, ok := parseRawRecordFields(plain)
		if !ok {
			result.MalformedEntries++
			continue
		}
		if !matchesRawFilter(fields, filter) {
			continue
		}
		var event Event
		if err := json.Unmarshal(plain, &event); err != nil {
			result.MalformedEntries++
			continue
		}
		if !matchesFilter(event, filter) {
			continue
		}
		if filter.Reverse || filter.Limit <= 0 || len(result.Events) < filter.Limit {
			result.Events = append(result.Events, event)
		}
	}
	if err := scanner.Err(); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to read audit log", err)
	}
	return nil
}

func queryOneFileRaw(path string, filter Filter, integrity *integrityReadState, result *RawResult) error {
	file, err := openAuditReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer func() { _ = file.Close() }()

	scanner := newAuditScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		plain, err := integrity.decode(line, filter.PrivateKey)
		if err != nil {
			return err
		}
		fields, ok := parseRawRecordFields(plain)
		if !ok {
			result.MalformedEntries++
			continue
		}
		if !matchesRawFilter(fields, filter) {
			continue
		}
		if filter.Reverse || filter.Limit <= 0 || len(result.Records) < filter.Limit {
			result.Records = append(result.Records, RawRecord{
				Line:      string(plain),
				Timestamp: fields.Timestamp,
				EventType: fields.EventType,
				Operator:  fields.Operator,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to read audit log", err)
	}
	return nil
}

//nolint:gocyclo // Fan-out predicate; each branch is a trivial equality compare.
func matchesFilter(e Event, f Filter) bool {
	if f.Since != nil && e.Timestamp.Before(*f.Since) {
		return false
	}
	if f.Until != nil && e.Timestamp.After(*f.Until) {
		return false
	}
	if f.EventType != "" && string(e.EventType) != f.EventType {
		return false
	}
	if f.Operator != "" && e.Operator != f.Operator {
		return false
	}
	if f.ContextName != "" && e.Context.Name != f.ContextName {
		return false
	}
	if f.Env != "" && e.Context.Env != f.Env {
		return false
	}
	if f.Protected != nil && e.Context.Protected != *f.Protected {
		return false
	}
	if f.Ticket != "" && e.Ticket != f.Ticket {
		return false
	}
	// Role events intentionally leave Target empty; query them with
	// --type=role.assign or --type=role.revoke instead of target filters.
	if f.App != "" && e.Target.App != f.App {
		return false
	}
	if f.ResourceType != "" && e.Target.ResourceType != f.ResourceType {
		return false
	}
	if f.Resource != "" && e.Target.Resource != f.Resource {
		return false
	}
	if f.Status != "" && e.Status != f.Status {
		return false
	}
	return true
}
