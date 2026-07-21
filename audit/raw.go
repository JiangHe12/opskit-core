package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

type rawRecordFields struct {
	Timestamp time.Time
	EventType string
	Operator  string
}

func parseRawRecordFields(plain []byte) (rawRecordFields, bool) {
	if !json.Valid(plain) {
		return rawRecordFields{}, false
	}
	if err := rejectDuplicateRawTopLevelKeys(plain); err != nil {
		return rawRecordFields{}, false
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(plain, &object); err != nil {
		return rawRecordFields{}, false
	}
	var fields rawRecordFields
	if raw := object[config.TimestampJSONName]; len(raw) > 0 {
		_ = json.Unmarshal(raw, &fields.Timestamp)
	}
	if raw := object[config.EventTypeJSONName]; len(raw) > 0 {
		_ = json.Unmarshal(raw, &fields.EventType)
	}
	if raw := object[config.OperatorJSONName]; len(raw) > 0 {
		_ = json.Unmarshal(raw, &fields.Operator)
	}
	return fields, true
}

func rejectDuplicateRawTopLevelKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return fmt.Errorf("expected JSON object")
	}
	seen := []string{}
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("expected JSON object key")
		}
		if previous, exists := equalFoldJSONField(seen, key); exists {
			return fmt.Errorf("semantically duplicate JSON keys %q and %q", previous, key)
		}
		seen = append(seen, key)
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func matchesRawFilter(fields rawRecordFields, filter Filter) bool {
	if filter.Since != nil && fields.Timestamp.Before(*filter.Since) {
		return false
	}
	if filter.Until != nil && fields.Timestamp.After(*filter.Until) {
		return false
	}
	if filter.EventType != "" && fields.EventType != filter.EventType {
		return false
	}
	if filter.Operator != "" && fields.Operator != filter.Operator {
		return false
	}
	return true
}
