// Package printer provides table, JSON, and plain output helpers.
package printer

import (
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
	colorTitle   = color.New(color.FgCyan, color.Bold)
	colorSuccess = color.New(color.FgGreen, color.Bold)
	colorDim     = color.New(color.Faint)
)

// Printer controls command output.
type Printer struct {
	Out       io.Writer
	Err       io.Writer
	Format    Format
	PlainHead bool
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
	_, _ = colorSuccess.Fprintln(p.Out, "✓ "+msg)
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
			colored[i] = colorTitle.Sprint(h)
		}
		table.SetHeader(colored)
		table.SetAutoWrapText(false)
		table.SetAutoFormatHeaders(false)
		table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.SetBorder(false)
		table.SetColumnSeparator("  ")
		table.SetHeaderLine(true)
		for i, row := range rows {
			if i%2 == 0 {
				table.Append(row)
				continue
			}
			dimmed := make([]string, len(row))
			for j, cell := range row {
				dimmed[j] = colorDim.Sprint(cell)
			}
			table.Append(dimmed)
		}
		table.Render()
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
	for _, pair := range pairs {
		_, _ = fmt.Fprintf(p.Out, "%s\t%s\n", pair[0], pair[1])
	}
}

// JSONData prints data as naked JSON. The kind parameter is kept for future extension.
func (p *Printer) JSONData(kind string, data any) error {
	_ = kind
	return p.printJSON(data)
}

// JSONList prints items as a naked JSON array. Pagination parameters are kept for API compatibility.
func (p *Printer) JSONList(kind string, items any, total, page, pageSize int, truncated bool) error {
	_, _, _, _, _ = kind, total, page, pageSize, truncated
	return p.printJSON(items)
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

func disableColorIfNeeded(out *os.File) {
	if os.Getenv("NO_COLOR") != "" || !isatty.IsTerminal(out.Fd()) {
		color.NoColor = true
	}
}
