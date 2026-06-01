package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeAuditFile(t *testing.T, events []Event) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			t.Fatalf("encode event: %v", err)
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write audit file: %v", err)
	}
	return path
}

func sampleEvents(now time.Time) []Event {
	return []Event{
		{
			Timestamp: now.Add(-3 * time.Hour),
			EventType: EventType("resource.create"),
			Operator:  "alice",
			Context:   EventContext{Name: "dev", Env: "dev"},
			Target:    EventTarget{App: "demo", ResourceType: "flow", Resource: "createOrder"},
			Status:    "success",
		},
		{
			Timestamp: now.Add(-2 * time.Hour),
			EventType: EventType("resource.update"),
			Operator:  "bob",
			Context:   EventContext{Name: "prod", Env: "prod", Protected: true},
			Target:    EventTarget{App: "demo", ResourceType: "flow", Resource: "createOrder"},
			Status:    "success",
			Ticket:    "OPS-1",
		},
		{
			Timestamp: now.Add(-1 * time.Hour),
			EventType: EventType("resource.delete"),
			Operator:  "alice",
			Context:   EventContext{Name: "prod", Env: "prod", Protected: true},
			Target:    EventTarget{App: "demo", ResourceType: "degrade", Resource: "payOrder"},
			Status:    "failure",
		},
		{
			Timestamp: now.Add(-30 * time.Minute),
			EventType: EventAuthorizationDenied,
			Operator:  "carol",
			Context:   EventContext{Name: "prod", Env: "prod", Protected: true},
			Target:    EventTarget{App: "demo", ResourceType: "flow", Resource: "createOrder"},
			Status:    "failure",
		},
		{
			Timestamp: now.Add(-5 * time.Minute),
			EventType: EventType("resource.import"),
			Operator:  "alice",
			Context:   EventContext{Name: "staging", Env: "staging"},
			Target:    EventTarget{App: "demo", ResourceType: "flow"},
			Status:    "success",
			Ticket:    "OPS-2",
		},
	}
}

func TestQueryNoFilterReturnsAll(t *testing.T) {
	now := time.Now().UTC()
	path := writeAuditFile(t, sampleEvents(now))
	got, err := Query(path, Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got.Events) != 5 {
		t.Errorf("expected 5 events, got %d", len(got.Events))
	}
}

func TestQueryIncludesRotatedLogs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	older := Event{
		Timestamp: time.Now().UTC().Add(-time.Hour),
		EventType: EventType("resource.create"),
		Operator:  "alice",
		Status:    StatusSuccess,
	}
	newer := Event{
		Timestamp: time.Now().UTC(),
		EventType: EventType("resource.update"),
		Operator:  "bob",
		Status:    StatusSuccess,
	}
	for filePath, event := range map[string]Event{
		path + ".20260524-010203.log": older,
		path:                          newer,
	} {
		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatalf("OpenFile(%s): %v", filePath, err)
		}
		if err := json.NewEncoder(file).Encode(event); err != nil {
			_ = file.Close()
			t.Fatalf("Encode(%s): %v", filePath, err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("Close(%s): %v", filePath, err)
		}
	}
	got, err := Query(path, Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got.Events) != 2 {
		t.Fatalf("events = %d, want 2", len(got.Events))
	}
	if got.Events[0].Operator != "alice" || got.Events[1].Operator != "bob" {
		t.Fatalf("events order = %+v", got.Events)
	}
}

func TestQueryFilterByOperator(t *testing.T) {
	now := time.Now().UTC()
	path := writeAuditFile(t, sampleEvents(now))
	got, err := Query(path, Filter{Operator: "alice"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got.Events) != 3 {
		t.Errorf("expected 3 alice events, got %d", len(got.Events))
	}
	for _, e := range got.Events {
		if e.Operator != "alice" {
			t.Errorf("non-alice event slipped through: %+v", e)
		}
	}
}

func TestQueryFilterByEventType(t *testing.T) {
	now := time.Now().UTC()
	path := writeAuditFile(t, sampleEvents(now))
	got, err := Query(path, Filter{EventType: "resource.delete"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got.Events) != 1 || got.Events[0].EventType != EventType("resource.delete") {
		t.Errorf("expected 1 resource.delete event, got %+v", got.Events)
	}
}

func TestQueryFilterBySinceParsesRelative(t *testing.T) {
	now := time.Now().UTC()
	path := writeAuditFile(t, sampleEvents(now))
	since, err := ParseTime("90m", now)
	if err != nil {
		t.Fatalf("ParseTime: %v", err)
	}
	got, err := Query(path, Filter{Since: &since})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got.Events) != 3 {
		t.Errorf("expected 3 events in last 90 minutes, got %d", len(got.Events))
	}
}

func TestQueryFilterBySinceParsesRFC3339(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	path := writeAuditFile(t, sampleEvents(now))
	rfcValue := now.Add(-2 * time.Hour).Format(time.RFC3339)
	since, err := ParseTime(rfcValue, now)
	if err != nil {
		t.Fatalf("ParseTime: %v", err)
	}
	got, err := Query(path, Filter{Since: &since})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got.Events) != 4 {
		t.Errorf("expected 4 events >= 2h ago, got %d", len(got.Events))
	}
}

func TestQueryFilterByUntilInclusive(t *testing.T) {
	now := time.Now().UTC()
	events := sampleEvents(now)
	path := writeAuditFile(t, events)
	until := events[2].Timestamp
	got, err := Query(path, Filter{Until: &until})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got.Events) != 3 {
		t.Errorf("expected 3 events <= until (inclusive), got %d", len(got.Events))
	}
}

func TestQueryLimitTruncates(t *testing.T) {
	now := time.Now().UTC()
	path := writeAuditFile(t, sampleEvents(now))
	got, err := Query(path, Filter{Limit: 2})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got.Events) != 2 {
		t.Errorf("expected 2 events with limit=2, got %d", len(got.Events))
	}
}

func TestQueryReverseChangesOrder(t *testing.T) {
	now := time.Now().UTC()
	path := writeAuditFile(t, sampleEvents(now))
	got, err := Query(path, Filter{Reverse: true})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got.Events) != 5 {
		t.Fatalf("expected 5 events, got %d", len(got.Events))
	}
	for i := 1; i < len(got.Events); i++ {
		if got.Events[i].Timestamp.After(got.Events[i-1].Timestamp) {
			t.Errorf("reverse order broken at index %d", i)
		}
	}
}

func TestQueryProtectedTriState(t *testing.T) {
	now := time.Now().UTC()
	path := writeAuditFile(t, sampleEvents(now))

	noFilter, err := Query(path, Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(noFilter.Events) != 5 {
		t.Errorf("no filter expected 5, got %d", len(noFilter.Events))
	}

	truthy := true
	onlyProtected, err := Query(path, Filter{Protected: &truthy})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(onlyProtected.Events) != 3 {
		t.Errorf("protected=true expected 3 (prod x3), got %d", len(onlyProtected.Events))
	}

	falsy := false
	notProtected, err := Query(path, Filter{Protected: &falsy})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(notProtected.Events) != 2 {
		t.Errorf("protected=false expected 2 (dev + staging), got %d", len(notProtected.Events))
	}
}

func TestQueryEmptyFilePathReturnsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.log")
	got, err := Query(path, Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got.Events) != 0 {
		t.Errorf("expected empty result, got %d events", len(got.Events))
	}
	if got.Events == nil {
		t.Fatal("events slice = nil, want empty slice")
	}
}

func TestQueryNoMatchesReturnsEmptyEventsArray(t *testing.T) {
	path := writeAuditFile(t, sampleEvents(time.Now().UTC()))
	got, err := Query(path, Filter{App: "missing"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if got.Events == nil {
		t.Fatal("events slice = nil, want empty slice")
	}
	data, err := json.Marshal(map[string]any{"events": got.Events})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(data) != `{"events":[]}` {
		t.Fatalf("json = %s, want {\"events\":[]}", data)
	}
}

func TestQueryMalformedLineSkipped(t *testing.T) {
	now := time.Now().UTC()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	good, _ := json.Marshal(Event{Timestamp: now, EventType: EventType("resource.create"), Operator: "alice"})
	content := string(good) + "\nnot-json-at-all\n" + string(good) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := Query(path, Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got.Events) != 2 {
		t.Errorf("expected 2 good events, got %d", len(got.Events))
	}
	if got.MalformedEntries != 1 {
		t.Errorf("expected 1 malformed entry counted, got %d", got.MalformedEntries)
	}
}

func TestQueryReportsZeroMalformedForValidLog(t *testing.T) {
	now := time.Now().UTC()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	enc := json.NewEncoder(file)
	for i := 0; i < 10_000; i++ {
		event := Event{
			Timestamp: now,
			EventType: EventType("resource.update"),
			Operator:  "alice",
			Context:   EventContext{Name: "prod", Env: "prod", Protected: true},
			Target:    EventTarget{App: "demo", ResourceType: "flow", Resource: "createOrder"},
			Status:    StatusSuccess,
		}
		if err := enc.Encode(event); err != nil {
			_ = file.Close()
			t.Fatalf("Encode(%d): %v", i, err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got, err := Query(path, Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if got.MalformedEntries != 0 {
		t.Fatalf("MalformedEntries = %d, want 0", got.MalformedEntries)
	}
	if len(got.Events) != 10_000 {
		t.Fatalf("events = %d, want 10000", len(got.Events))
	}
}

func TestQueryAndFilterSemantics(t *testing.T) {
	now := time.Now().UTC()
	path := writeAuditFile(t, sampleEvents(now))
	since := now.Add(-2 * time.Hour)
	got, err := Query(path, Filter{
		Operator:  "alice",
		EventType: "resource.delete",
		Since:     &since,
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got.Events) != 1 {
		t.Errorf("expected 1 event matching all 3 filters, got %d", len(got.Events))
	}
}

func TestParseTimeRejectsGarbage(t *testing.T) {
	_, err := ParseTime("garbage", time.Now())
	if err == nil {
		t.Fatal("expected error for garbage input")
	}
}
