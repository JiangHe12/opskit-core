// Package printer provides table, JSON, and plain output helpers.
package printer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/mattn/go-isatty"
	"github.com/olekukonko/tablewriter"
)

// Format is a supported output format.
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatPlain Format = "plain"
)

var (
	ColorTitle   = color.New(color.FgCyan, color.Bold)
	ColorSuccess = color.New(color.FgGreen, color.Bold)
	ColorWarn    = color.New(color.FgYellow)
	ColorError   = color.New(color.FgRed, color.Bold)
	ColorDim     = color.New(color.Faint)
)

// Printer controls command output.
type Printer struct {
	Out       io.Writer
	Err       io.Writer
	Format    Format
	PlainHead bool
}

// Options controls optional printer response metadata.
type Options struct {
	APIVersion            string
	JSONEnvelopeByDefault bool
	JSONKeyStyle          JSONKeyStyle
	JSONKeyOverrides      map[string]string
	TablePadding          string
	TableNoWhiteSpace     bool
	TableFooter           bool
	TableHeaderColor      bool
	DecoratedKVTable      bool
	DecoratedContent      bool
}

var options = Options{APIVersion: "opskit-core.io/v1"}

// JSONKeyStyle controls how table/KV labels are converted to JSON keys.
type JSONKeyStyle string

const (
	JSONKeyStyleCamel JSONKeyStyle = ""
	JSONKeyStyleSnake JSONKeyStyle = "snake"
)

// Configure sets package-level printer defaults for optional helpers.
func Configure(next Options) {
	if next.APIVersion != "" {
		options.APIVersion = next.APIVersion
	}
	options.JSONEnvelopeByDefault = next.JSONEnvelopeByDefault
	options.JSONKeyStyle = next.JSONKeyStyle
	if next.JSONKeyOverrides != nil {
		options.JSONKeyOverrides = make(map[string]string, len(next.JSONKeyOverrides))
		for key, value := range next.JSONKeyOverrides {
			options.JSONKeyOverrides[normalizeHeaderKey(key)] = value
		}
	} else {
		options.JSONKeyOverrides = nil
	}
	options.TablePadding = next.TablePadding
	options.TableNoWhiteSpace = next.TableNoWhiteSpace
	options.TableFooter = next.TableFooter
	options.TableHeaderColor = next.TableHeaderColor
	options.DecoratedKVTable = next.DecoratedKVTable
	options.DecoratedContent = next.DecoratedContent
}

// JSONDataEnvelope is an opt-in enveloped single-object JSON response.
type JSONDataEnvelope struct {
	Kind string
	Data any
}

// JSONListEnvelope is an opt-in enveloped list JSON response.
type JSONListEnvelope struct {
	Kind      string
	Items     any
	Total     int
	Page      int
	PageSize  int
	Truncated bool
}

// New creates a Printer using stdout/stderr.
func New(format Format) *Printer {
	disableColorIfNeeded(os.Stdout)
	return NewWithWriters(format, os.Stdout, os.Stderr)
}

// NewWithWriters creates a testable Printer.
func NewWithWriters(format Format, out, errOut io.Writer) *Printer {
	return &Printer{Out: out, Err: errOut, Format: format}
}

// Success prints a success message.
func (p *Printer) Success(msg string) {
	_, _ = ColorSuccess.Fprintln(p.Out, "✓ "+msg)
}

// Error prints an error message to stderr.
func (p *Printer) Error(msg string) {
	_, _ = ColorError.Fprintln(p.Err, "✗ "+msg)
}

// Warn prints a warning message to stderr.
func (p *Printer) Warn(msg string) {
	_, _ = ColorWarn.Fprintln(p.Err, msg)
}

// Info prints a plain message.
func (p *Printer) Info(msg string) {
	_, _ = fmt.Fprintln(p.Out, msg)
}

// Table prints rows as table, JSON, or plain text.
func (p *Printer) Table(headers []string, rows [][]string) {
	switch p.Format {
	case FormatTable:
		table := tablewriter.NewWriter(p.Out)
		colored := make([]string, len(headers))
		for i, h := range headers {
			colored[i] = ColorTitle.Sprint(h)
		}
		table.SetHeader(colored)
		table.SetAutoWrapText(false)
		table.SetAutoFormatHeaders(false)
		table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.SetBorder(false)
		table.SetColumnSeparator("  ")
		table.SetHeaderLine(true)
		if options.TablePadding != "" {
			table.SetTablePadding(options.TablePadding)
		}
		if options.TableNoWhiteSpace {
			table.SetNoWhiteSpace(true)
		}
		if options.TableHeaderColor {
			headerColors := make([]tablewriter.Colors, len(headers))
			for i := range headers {
				headerColors[i] = tablewriter.Colors{tablewriter.Bold, tablewriter.FgCyanColor}
			}
			table.SetHeaderColor(headerColors...)
		}
		for i, row := range rows {
			if i%2 == 0 {
				table.Append(row)
				continue
			}
			dimmed := make([]string, len(row))
			for j, cell := range row {
				dimmed[j] = ColorDim.Sprint(cell)
			}
			table.Append(dimmed)
		}
		table.Render()
		if options.TableFooter {
			_, _ = ColorDim.Fprintf(p.Out, "\n  Total: %d item(s)\n", len(rows))
		}
	case FormatJSON:
		_ = p.JSONList("Table", tableItems(headers, rows), len(rows), 1, len(rows), false)
	case FormatPlain:
		p.tablePlain(headers, rows)
	}
}

// KV prints key/value pairs.
func (p *Printer) KV(pairs [][2]string) {
	if p.Format == FormatJSON {
		m := make(map[string]string, len(pairs))
		for _, pair := range pairs {
			m[jsonKey(pair[0])] = pair[1]
		}
		_ = p.JSONData("Object", m)
		return
	}
	if p.Format == FormatTable && options.DecoratedKVTable {
		maxKey := 0
		for _, pair := range pairs {
			if len(pair[0]) > maxKey {
				maxKey = len(pair[0])
			}
		}
		for _, pair := range pairs {
			key := ColorTitle.Sprintf("%-*s", maxKey, pair[0])
			_, _ = fmt.Fprintf(p.Out, "  %s  %s\n", key, pair[1])
		}
		return
	}
	for _, pair := range pairs {
		_, _ = fmt.Fprintf(p.Out, "%s\t%s\n", pair[0], pair[1])
	}
}

// Content prints a titled content block.
func (p *Printer) Content(title, content string) {
	if p.Format == FormatJSON {
		_ = p.JSONData("Content", map[string]string{"title": title, "content": content})
		return
	}
	if p.Format == FormatPlain {
		_, _ = fmt.Fprint(p.Out, content)
		return
	}
	if options.DecoratedContent {
		_, _ = ColorTitle.Fprintf(p.Out, "── %s ──\n", title)
		_, _ = fmt.Fprintln(p.Out, content)
		_, _ = ColorDim.Fprintf(p.Out, "── end ──\n")
		return
	}
	_, _ = fmt.Fprint(p.Out, content)
}

// JSONData prints data as naked JSON. The kind parameter is kept for future extension.
func (p *Printer) JSONData(kind string, data any) error {
	if options.JSONEnvelopeByDefault {
		return p.JSONDataEnvelope(JSONDataEnvelope{Kind: kind, Data: data})
	}
	_ = kind
	return p.printJSON(data)
}

// JSONDataEnvelope prints an opt-in enveloped single-object JSON response.
func (p *Printer) JSONDataEnvelope(payload JSONDataEnvelope) error {
	return p.printJSON(struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Success    bool   `json:"success"`
		Data       any    `json:"data"`
	}{
		APIVersion: options.APIVersion,
		Kind:       payload.Kind,
		Success:    true,
		Data:       payload.Data,
	})
}

// JSONList prints items as a naked JSON array. Pagination parameters are kept for API compatibility.
func (p *Printer) JSONList(kind string, items any, total, page, perPage int, truncated bool) error {
	if options.JSONEnvelopeByDefault {
		return p.JSONListEnvelope(JSONListEnvelope{
			Kind:      kind,
			Items:     items,
			Total:     total,
			Page:      page,
			PageSize:  perPage,
			Truncated: truncated,
		})
	}
	_, _, _, _, _ = kind, total, page, perPage, truncated
	return p.printJSON(items)
}

// JSONListEnvelope prints an opt-in enveloped list JSON response.
func (p *Printer) JSONListEnvelope(payload JSONListEnvelope) error {
	return p.printJSON(struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Success    bool   `json:"success"`
		Data       any    `json:"data"`
	}{
		APIVersion: options.APIVersion,
		Kind:       payload.Kind,
		Success:    true,
		Data: listEnvelopeData{
			Items:     payload.Items,
			Total:     payload.Total,
			Page:      payload.Page,
			PageSize:  payload.PageSize,
			Truncated: payload.Truncated,
		},
	})
}

type listEnvelopeData struct {
	Items     any
	Total     int
	Page      int
	PageSize  int
	Truncated bool
}

func (d listEnvelopeData) MarshalJSON() ([]byte, error) {
	var out bytes.Buffer
	out.WriteByte('{')
	if err := writeJSONField(&out, "items", d.Items); err != nil {
		return nil, err
	}
	if err := writeJSONField(&out, "total", d.Total); err != nil {
		return nil, err
	}
	if err := writeJSONField(&out, "page", d.Page); err != nil {
		return nil, err
	}
	if err := writeJSONField(&out, "page"+"Size", d.PageSize); err != nil {
		return nil, err
	}
	if err := writeJSONField(&out, "truncated", d.Truncated); err != nil {
		return nil, err
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

func writeJSONField(out *bytes.Buffer, name string, value any) error {
	if out.Len() > 1 {
		out.WriteByte(',')
	}
	nameBytes, err := json.Marshal(name)
	if err != nil {
		return err
	}
	valueBytes, err := json.Marshal(value)
	if err != nil {
		return err
	}
	out.Write(nameBytes)
	out.WriteByte(':')
	out.Write(valueBytes)
	return nil
}

func (p *Printer) tablePlain(headers []string, rows [][]string) {
	if p.PlainHead {
		_, _ = fmt.Fprintln(p.Out, strings.Join(headers, "\t"))
	}
	for _, row := range rows {
		_, _ = fmt.Fprintln(p.Out, strings.Join(row, "\t"))
	}
}

func (p *Printer) printJSON(v any) error {
	enc := json.NewEncoder(p.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func tableItems(headers []string, rows [][]string) []map[string]string {
	items := make([]map[string]string, 0, len(rows))
	for _, row := range rows {
		item := make(map[string]string)
		for i, h := range headers {
			if i < len(row) {
				item[jsonKey(h)] = row[i]
			}
		}
		items = append(items, item)
	}
	return items
}

func jsonKey(header string) string {
	if override, ok := options.JSONKeyOverrides[normalizeHeaderKey(header)]; ok {
		return override
	}
	if options.JSONKeyStyle == JSONKeyStyleSnake {
		key := strings.ToLower(strings.TrimSpace(header))
		return strings.ReplaceAll(key, " ", "_")
	}
	key := strings.ToLower(strings.TrimSpace(header))
	parts := strings.Fields(key)
	if len(parts) == 0 {
		return key
	}
	for i := 1; i < len(parts); i++ {
		parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
	}
	return strings.Join(parts, "")
}

func normalizeHeaderKey(header string) string {
	return strings.ToUpper(strings.TrimSpace(header))
}

func disableColorIfNeeded(out *os.File) {
	if os.Getenv("NO_COLOR") != "" || !isatty.IsTerminal(out.Fd()) {
		color.NoColor = true
	}
}
