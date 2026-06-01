package printer

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestPlainTableWithHeader(t *testing.T) {
	var out bytes.Buffer
	p := NewWithWriters(FormatPlain, &out, &bytes.Buffer{})
	p.PlainHead = true

	p.Table([]string{"NAME", "ENV"}, [][]string{{"dev", "dev"}})

	if got, want := out.String(), "NAME\tENV\ndev\tdev\n"; got != want {
		t.Fatalf("plain table = %q, want %q", got, want)
	}
}

func TestPlainTableWithoutHeader(t *testing.T) {
	var out bytes.Buffer
	p := NewWithWriters(FormatPlain, &out, &bytes.Buffer{})
	p.Table([]string{"NAME", "ENV"}, [][]string{{"dev", "staging"}})
	if !strings.Contains(out.String(), "dev") || strings.Contains(out.String(), "NAME") {
		t.Fatalf("plain table without header = %q", out.String())
	}
}

func TestJSONDataNakedObject(t *testing.T) {
	var out bytes.Buffer
	p := NewWithWriters(FormatJSON, &out, &bytes.Buffer{})

	if err := p.JSONData("Thing", map[string]string{"name": "demo"}); err != nil {
		t.Fatalf("JSONData() error = %v", err)
	}

	var payload map[string]string
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload["name"] != "demo" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestJSONListNakedArray(t *testing.T) {
	var out bytes.Buffer
	p := NewWithWriters(FormatJSON, &out, &bytes.Buffer{})

	items := []map[string]string{{"a": "1"}, {"b": "2"}}
	if err := p.JSONList("Items", items, 2, 1, 10, false); err != nil {
		t.Fatalf("JSONList() error = %v", err)
	}
	var decoded []map[string]string
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if len(decoded) != 2 {
		t.Fatalf("len = %d, want 2", len(decoded))
	}
}

func TestTableOutputContainsRows(t *testing.T) {
	var out bytes.Buffer
	p := NewWithWriters(FormatTable, &out, &bytes.Buffer{})

	p.Table([]string{"NAME"}, [][]string{{"dev"}})

	if !strings.Contains(out.String(), "dev") {
		t.Fatalf("table output %q does not contain row", out.String())
	}
}

func TestTableMultiRowAlternates(t *testing.T) {
	var out bytes.Buffer
	p := NewWithWriters(FormatTable, &out, &bytes.Buffer{})
	p.Table([]string{"NAME"}, [][]string{{"row0"}, {"row1"}, {"row2"}})
	for _, want := range []string{"row0", "row1", "row2"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("table output missing %q: %q", want, out.String())
		}
	}
}

func TestTableJSONFormat(t *testing.T) {
	var out bytes.Buffer
	p := NewWithWriters(FormatJSON, &out, &bytes.Buffer{})
	p.Table([]string{"Name", "Env"}, [][]string{{"dev", "dev"}})
	var decoded []map[string]string
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v; output=%q", err, out.String())
	}
	if decoded[0]["name"] != "dev" || decoded[0]["env"] != "dev" {
		t.Fatalf("decoded = %+v", decoded)
	}
}

func TestKVJSONFormat(t *testing.T) {
	var out bytes.Buffer
	p := NewWithWriters(FormatJSON, &out, &bytes.Buffer{})
	p.KV([][2]string{{"Server", "http://localhost"}, {"Group", "DEFAULT_GROUP"}})
	var decoded map[string]string
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v; output=%q", err, out.String())
	}
	if decoded["server"] != "http://localhost" {
		t.Fatalf("server = %q", decoded["server"])
	}
	if decoded["group"] != "DEFAULT_GROUP" {
		t.Fatalf("group = %q", decoded["group"])
	}
}

func TestKVPlainFormat(t *testing.T) {
	var out bytes.Buffer
	p := NewWithWriters(FormatPlain, &out, &bytes.Buffer{})
	p.KV([][2]string{{"Key", "value123"}})
	if !strings.Contains(out.String(), "Key") || !strings.Contains(out.String(), "value123") {
		t.Fatalf("KV plain = %q", out.String())
	}
}

func TestKVMultiWordHeaderCamelCase(t *testing.T) {
	var out bytes.Buffer
	p := NewWithWriters(FormatJSON, &out, &bytes.Buffer{})
	p.KV([][2]string{{"Limit App", "appA"}})
	var decoded map[string]string
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if decoded["limitApp"] != "appA" {
		t.Fatalf("decoded = %+v", decoded)
	}
}

func TestSuccessWritesToOut(t *testing.T) {
	var out bytes.Buffer
	p := NewWithWriters(FormatPlain, &out, &bytes.Buffer{})
	p.Success("everything ok")
	if !strings.Contains(out.String(), "everything ok") {
		t.Fatalf("Success() output = %q", out.String())
	}
}

func TestInfoWritesToOut(t *testing.T) {
	var out bytes.Buffer
	p := NewWithWriters(FormatPlain, &out, &bytes.Buffer{})
	p.Info("hello world")
	if !strings.Contains(out.String(), "hello world") {
		t.Fatalf("Info() output = %q", out.String())
	}
}

func TestTableEmptyRows(t *testing.T) {
	var out bytes.Buffer
	p := NewWithWriters(FormatPlain, &out, &bytes.Buffer{})
	p.Table([]string{"X"}, [][]string{})
	// Should not panic; with no rows the output is just the (omitted) header.
}
