package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type foreignAuditRecord struct {
	APIVersion string                 `json:"apiVersion"`
	Kind       string                 `json:"kind"`
	EventID    string                 `json:"eventId"`
	Timestamp  time.Time              `json:"timestamp"`
	Type       string                 `json:"type"`
	Operator   string                 `json:"operator"`
	Context    map[string]string      `json:"context,omitempty"`
	Target     map[string]string      `json:"target,omitempty"`
	Status     string                 `json:"status"`
	Extra      map[string]interface{} `json:"extra,omitempty"`
}

func TestAppendRecordVerifyAndQueryRawForeignRecord(t *testing.T) {
	Configure(Config{
		EventTypeJSONName: "type",
	})
	t.Cleanup(func() {
		Configure(Config{
			TimestampJSONName: "timestamp",
			EventTypeJSONName: "eventType",
			OperatorJSONName:  "operator",
		})
	})

	path := filepath.Join(t.TempDir(), "audit.log")
	record := foreignAuditRecord{
		APIVersion: "foreign.io/audit/v1",
		Kind:       "AuditEvent",
		EventID:    "evt-1",
		Timestamp:  time.Date(2026, 6, 1, 1, 2, 3, 0, time.UTC),
		Type:       "config.write",
		Operator:   "alice",
		Context:    map[string]string{"name": "prod"},
		Target:     map[string]string{"dataId": "app.yaml"},
		Status:     "success",
	}
	wantLine, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Marshal(record) error = %v", err)
	}

	if err := AppendRecord(path, record, Options{}); err != nil {
		t.Fatalf("AppendRecord() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != string(wantLine) {
		t.Fatalf("audit line = %s, want %s", got, wantLine)
	}
	if !strings.Contains(string(data), `"apiVersion":"foreign.io/audit/v1","kind":"AuditEvent","eventId":"evt-1","timestamp"`) {
		t.Fatalf("audit line lost foreign field order: %s", data)
	}
	if !strings.Contains(string(data), `"type":"config.write"`) || strings.Contains(string(data), `"eventType"`) {
		t.Fatalf("audit line did not use foreign type key: %s", data)
	}

	verify, err := Verify(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if verify.Valid != 1 || verify.SchemaErrors != 0 || verify.Malformed != 0 {
		t.Fatalf("Verify() = %+v, want one valid foreign record", verify)
	}

	result, err := QueryRaw(path, Filter{EventType: "config.write"})
	if err != nil {
		t.Fatalf("QueryRaw() error = %v", err)
	}
	if len(result.Records) != 1 || result.MalformedEntries != 0 {
		t.Fatalf("QueryRaw() = %+v, want one raw record", result)
	}
	if strings.TrimSpace(result.Records[0].Line) != string(wantLine) {
		t.Fatalf("raw line = %s, want %s", result.Records[0].Line, wantLine)
	}
	if result.Records[0].EventType != "config.write" || result.Records[0].Operator != "alice" {
		t.Fatalf("raw parsed fields = %+v", result.Records[0])
	}
	var decoded foreignAuditRecord
	if err := json.Unmarshal([]byte(result.Records[0].Line), &decoded); err != nil {
		t.Fatalf("Unmarshal(raw line) error = %v", err)
	}
	if decoded.EventID != record.EventID || decoded.Type != record.Type {
		t.Fatalf("decoded = %+v, want %+v", decoded, record)
	}
}

func TestAppendRecordDoesNotDefaultTimestamp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	record := struct {
		Type     string `json:"type"`
		Operator string `json:"operator"`
	}{
		Type:     "config.write",
		Operator: "alice",
	}

	if err := AppendRecord(path, record, Options{}); err != nil {
		t.Fatalf("AppendRecord() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if strings.Contains(string(data), "timestamp") {
		t.Fatalf("AppendRecord defaulted timestamp unexpectedly: %s", data)
	}
}
