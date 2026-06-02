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

func TestJSONDataEnvelopeUsesConfiguredAPIVersion(t *testing.T) {
	Configure(Options{APIVersion: "example.io/v1"})
	t.Cleanup(func() { Configure(Options{APIVersion: "opskit-core.io/v1"}) })

	var out bytes.Buffer
	p := NewWithWriters(FormatJSON, &out, &bytes.Buffer{})
	if err := p.JSONDataEnvelope(JSONDataEnvelope{
		Kind: "Object",
		Data: map[string]string{"name": "demo"},
	}); err != nil {
		t.Fatalf("JSONDataEnvelope() error = %v", err)
	}

	var decoded struct {
		APIVersion string            `json:"apiVersion"`
		Kind       string            `json:"kind"`
		Success    bool              `json:"success"`
		Data       map[string]string `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v; output = %s", err, out.String())
	}
	if decoded.APIVersion != "example.io/v1" || decoded.Kind != "Object" || !decoded.Success || decoded.Data["name"] != "demo" {
		t.Fatalf("decoded = %+v", decoded)
	}
}

func TestNacosStyleJSONDataUsesEnvelopeByDefault(t *testing.T) {
	Configure(Options{APIVersion: "nacos-cli.io/v1", JSONEnvelopeByDefault: true})
	t.Cleanup(func() { Configure(Options{APIVersion: "opskit-core.io/v1"}) })

	var out bytes.Buffer
	p := NewWithWriters(FormatJSON, &out, &bytes.Buffer{})
	if err := p.JSONData("ConfigItem", map[string]string{"key": "value"}); err != nil {
		t.Fatalf("JSONData() error = %v", err)
	}

	var decoded struct {
		APIVersion string            `json:"apiVersion"`
		Kind       string            `json:"kind"`
		Success    bool              `json:"success"`
		Data       map[string]string `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v; output = %s", err, out.String())
	}
	if decoded.APIVersion != "nacos-cli.io/v1" || decoded.Kind != "ConfigItem" || !decoded.Success || decoded.Data["key"] != "value" {
		t.Fatalf("decoded = %+v", decoded)
	}
}

func TestJSONListEnvelopeWrapsPagination(t *testing.T) {
	Configure(Options{APIVersion: "example.io/v1"})
	t.Cleanup(func() { Configure(Options{APIVersion: "opskit-core.io/v1"}) })

	var out bytes.Buffer
	p := NewWithWriters(FormatJSON, &out, &bytes.Buffer{})
	if err := p.JSONListEnvelope(JSONListEnvelope{
		Kind:      "Table",
		Items:     []map[string]string{{"name": "demo"}},
		Total:     3,
		Page:      2,
		PageSize:  1,
		Truncated: true,
	}); err != nil {
		t.Fatalf("JSONListEnvelope() error = %v", err)
	}

	var decoded struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Success    bool   `json:"success"`
		Data       struct {
			Items     []map[string]string `json:"items"`
			Total     int                 `json:"total"`
			Page      int                 `json:"page"`
			PageSize  int                 `json:"pageSize"`
			Truncated bool                `json:"truncated"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v; output = %s", err, out.String())
	}
	if decoded.APIVersion != "example.io/v1" || decoded.Kind != "Table" || !decoded.Success {
		t.Fatalf("decoded envelope = %+v", decoded)
	}
	if decoded.Data.Total != 3 || decoded.Data.Page != 2 || decoded.Data.PageSize != 1 || !decoded.Data.Truncated {
		t.Fatalf("decoded pagination = %+v", decoded.Data)
	}
	if len(decoded.Data.Items) != 1 || decoded.Data.Items[0]["name"] != "demo" {
		t.Fatalf("decoded items = %+v", decoded.Data.Items)
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

func TestNacosStyleTableJSONUsesEnvelopeAndSnakeKeys(t *testing.T) {
	Configure(Options{
		APIVersion:            "example.io/v1",
		JSONEnvelopeByDefault: true,
		JSONKeyStyle:          JSONKeyStyleSnake,
		JSONKeyOverrides: map[string]string{
			"RESOURCE ID": "resourceId",
		},
	})
	t.Cleanup(func() { Configure(Options{APIVersion: "opskit-core.io/v1"}) })

	var out bytes.Buffer
	p := NewWithWriters(FormatJSON, &out, &bytes.Buffer{})
	p.Table([]string{"Resource ID", "Status Code"}, [][]string{{"app.yaml", "200"}})

	var decoded struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Success    bool   `json:"success"`
		Data       struct {
			Items []map[string]string `json:"items"`
			Total int                 `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v; output=%q", err, out.String())
	}
	if decoded.APIVersion != "example.io/v1" || decoded.Kind != "Table" || !decoded.Success || decoded.Data.Total != 1 {
		t.Fatalf("decoded envelope = %+v", decoded)
	}
	if decoded.Data.Items[0]["resourceId"] != "app.yaml" || decoded.Data.Items[0]["status_code"] != "200" {
		t.Fatalf("decoded items = %+v", decoded.Data.Items)
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

func TestNacosStyleKVTableAndContentAndMessages(t *testing.T) {
	Configure(Options{DecoratedKVTable: true, DecoratedContent: true})
	t.Cleanup(func() { Configure(Options{APIVersion: "opskit-core.io/v1"}) })

	var out bytes.Buffer
	var errOut bytes.Buffer
	p := NewWithWriters(FormatTable, &out, &errOut)
	p.KV([][2]string{{"Key", "value123"}})
	p.Content("app.yml", "hello")
	p.Warn("warning")
	p.Error("failed")

	got := out.String()
	if !strings.Contains(got, "Key") || !strings.Contains(got, "value123") {
		t.Fatalf("decorated KV table = %q", got)
	}
	if !strings.Contains(got, "── app.yml ──") || !strings.Contains(got, "── end ──") {
		t.Fatalf("decorated content = %q", got)
	}
	if !strings.Contains(errOut.String(), "warning") || !strings.Contains(errOut.String(), "failed") {
		t.Fatalf("stderr = %q", errOut.String())
	}
}

func TestNacosStyleTableFooter(t *testing.T) {
	Configure(Options{TablePadding: "  ", TableNoWhiteSpace: true, TableFooter: true, TableHeaderColor: true})
	t.Cleanup(func() { Configure(Options{APIVersion: "opskit-core.io/v1"}) })

	var out bytes.Buffer
	p := NewWithWriters(FormatTable, &out, &bytes.Buffer{})
	p.Table([]string{"Name"}, [][]string{{"app"}, {"api"}})
	if !strings.Contains(out.String(), "Total: 2 item(s)") {
		t.Fatalf("table footer missing: %q", out.String())
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
