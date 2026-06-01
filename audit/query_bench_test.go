package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func BenchmarkQuery_100k(b *testing.B) {
	benchmarkQuerySize(b, 100_000)
}

func BenchmarkQuery_1M(b *testing.B) {
	benchmarkQuerySize(b, 1_000_000)
}

func benchmarkQuerySize(b *testing.B, n int) {
	path := writeBenchmarkAuditLog(b, n)
	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	since := now.Add(-24 * time.Hour)
	for _, tc := range []struct {
		name   string
		filter Filter
	}{
		{name: "no_filter", filter: Filter{}},
		{name: "by_app", filter: Filter{App: "demo-3"}},
		{name: "by_operator", filter: Filter{Operator: "alice"}},
		{name: "by_since", filter: Filter{Since: &since}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				result, err := Query(path, tc.filter)
				if err != nil {
					b.Fatalf("Query: %v", err)
				}
				if result.MalformedEntries != 0 {
					b.Fatalf("MalformedEntries = %d, want 0", result.MalformedEntries)
				}
			}
		})
	}
}

func writeBenchmarkAuditLog(tb testing.TB, n int) string {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "audit.log")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		tb.Fatalf("OpenFile: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			tb.Fatalf("Close: %v", err)
		}
	}()
	enc := json.NewEncoder(file)
	base := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	operators := []string{"alice", "bob", "carol", "dave"}
	statuses := []string{StatusSuccess, StatusFailed, StatusPending}
	for i := 0; i < n; i++ {
		event := Event{
			Timestamp: base.Add(-time.Duration(i%172800) * time.Second),
			EventType: EventType("resource.update"),
			Operator:  operators[i%len(operators)],
			Context:   EventContext{Name: "prod", Env: "prod", Protected: true},
			Ticket:    "OPS-1234",
			Reason:    "benchmark",
			Target: EventTarget{
				App:          fmt.Sprintf("demo-%d", i%10),
				ResourceType: "flow",
				Resource:     fmt.Sprintf("resource-%d", i%10),
			},
			Status: statuses[i%len(statuses)],
		}
		if err := enc.Encode(event); err != nil {
			tb.Fatalf("Encode(%d): %v", i, err)
		}
	}
	return path
}
