package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/JiangHe12/opskit-core/apperrors"
)

// Filter is the set of optional predicates applied to audit log entries.
// All fields are AND-combined. Empty string fields mean "no filter".
type Filter struct {
	Since        *time.Time
	Until        *time.Time
	EventType    string
	Operator     string
	ContextName  string
	Env          string
	Protected    *bool
	Ticket       string
	App          string
	ResourceType string
	Resource     string
	Status       string
	Limit        int
	Reverse      bool
	PrivateKey   string
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
	files, err := queryFiles(path)
	if err != nil {
		return result, err
	}
	for _, filePath := range files {
		if err := queryOneFile(filePath, filter, &result); err != nil {
			return result, err
		}
		if !filter.Reverse && filter.Limit > 0 && len(result.Events) >= filter.Limit {
			break
		}
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
	files, err := queryFiles(path)
	if err != nil {
		return result, err
	}
	for _, filePath := range files {
		if err := queryOneFileRaw(filePath, filter, &result); err != nil {
			return result, err
		}
		if !filter.Reverse && filter.Limit > 0 && len(result.Records) >= filter.Limit {
			break
		}
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

func queryFiles(path string) ([]string, error) {
	rotated, err := RotatedFiles(path)
	if err != nil {
		return nil, err
	}
	files := append([]string{}, rotated...)
	files = append(files, path)
	return files, nil
}

func queryOneFile(path string, filter Filter, result *Result) error {
	file, err := os.Open(path) //nolint:gosec // path is user-supplied audit log location.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return apperrors.New(apperrors.CodeLocalIOError, "failed to open audit log", err)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		plain, err := decryptAuditLine(line, filter.PrivateKey)
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
		result.Events = append(result.Events, event)
		if !filter.Reverse && filter.Limit > 0 && len(result.Events) >= filter.Limit {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to read audit log", err)
	}
	return nil
}

func queryOneFileRaw(path string, filter Filter, result *RawResult) error {
	file, err := os.Open(path) //nolint:gosec // path is user-supplied audit log location.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return apperrors.New(apperrors.CodeLocalIOError, "failed to open audit log", err)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		plain, err := decryptAuditLine(line, filter.PrivateKey)
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
		result.Records = append(result.Records, RawRecord{
			Line:      string(plain),
			Timestamp: fields.Timestamp,
			EventType: fields.EventType,
			Operator:  fields.Operator,
		})
		if !filter.Reverse && filter.Limit > 0 && len(result.Records) >= filter.Limit {
			break
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
