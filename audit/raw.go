package audit

import (
	"encoding/json"
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
