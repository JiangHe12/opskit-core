package audit

import "testing"

func TestParseRawRecordFieldsRejectsDuplicateTopLevelKeys(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "exact duplicate",
			raw:  `{"timestamp":"2026-07-21T01:00:00Z","eventType":"x","eventType":"y","operator":"tester"}`,
		},
		{
			name: "case-fold duplicate",
			raw:  `{"timestamp":"2026-07-21T01:00:00Z","eventType":"x","operator":"tester","OPERATOR":"other"}`,
		},
		{
			name: "unicode simple-fold duplicate",
			raw:  `{"timestamp":"2026-07-21T01:00:00Z","eventType":"x","operator":"tester","kind":1,"Kind":2}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, ok := parseRawRecordFields([]byte(test.raw)); ok {
				t.Fatalf("parseRawRecordFields(%s) accepted duplicate top-level keys", test.raw)
			}
		})
	}
}
