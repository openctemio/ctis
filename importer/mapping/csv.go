package mapping

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Bounds of a CSV input.
const (
	// MaxCSVColumns is the most columns a header row may have.
	MaxCSVColumns = 1024
	// DefaultMaxCellBytes is the largest cell; a row with a longer cell is
	// skipped.
	DefaultMaxCellBytes = 64 << 10
	// maxColumnName bounds a header name, in bytes.
	maxColumnName = 256
	// sniffBytes is how much of the header row delimiter detection reads.
	sniffBytes = 64 << 10
)

// ErrEncoding is returned for an input that is not UTF-8 (a UTF-16 byte
// order mark).
var ErrEncoding = errors.New("mapping: the input is UTF-16; save it as UTF-8")

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// csvConfig is a compiled CSVSpec.
type csvConfig struct {
	delim rune // 0: detect
	skip  int
}

func compileCSV(s *CSVSpec) (csvConfig, error) {
	var c csvConfig
	if s == nil {
		return c, nil
	}
	switch s.Delimiter {
	case "", "auto":
	case ",", ";", "\t", "|":
		c.delim = rune(s.Delimiter[0])
	default:
		return c, fmt.Errorf(`delimiter %q, want ",", ";", "\t", "|" or "auto"`, s.Delimiter)
	}
	if s.SkipRows < 0 || s.SkipRows > MaxSkipRows {
		return c, fmt.Errorf("skip_rows outside 0..%d", MaxSkipRows)
	}
	c.skip = s.SkipRows
	return c, nil
}

// detectDelimiter picks the candidate that occurs most often outside double
// quotes in the first line of head. Ties go to the earlier candidate; a line
// with none is one column, read with ",".
func detectDelimiter(head []byte) rune {
	cands := []byte{',', ';', '\t', '|'}
	counts := make([]int, len(cands))
	inQuote := false
	for _, c := range head {
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if inQuote {
			continue
		}
		if c == '\n' || c == '\r' {
			break
		}
		for i, d := range cands {
			if c == d {
				counts[i]++
			}
		}
	}
	best := 0
	for i := range cands {
		if counts[i] > counts[best] {
			best = i
		}
	}
	return rune(cands[best])
}

// columnNames turns a header row into member names: trimmed and cleaned,
// an empty name becomes "column_<n>" (1-based) and a repeated one gets
// "_2", "_3", ... so every column is addressable.
func columnNames(header []string) ([]string, error) {
	if len(header) > MaxCSVColumns {
		return nil, fmt.Errorf("mapping: the header row has %d columns, at most %d", len(header), MaxCSVColumns)
	}
	out := make([]string, len(header))
	used := map[string]bool{}
	for i, h := range header {
		name, _ := sanitize(strings.TrimSpace(h), "").(string)
		name = strings.TrimSpace(truncate(name, maxColumnName))
		if name == "" {
			name = "column_" + strconv.Itoa(i+1)
		}
		base := name
		for k := 2; used[name]; k++ {
			name = base + "_" + strconv.Itoa(k)
		}
		used[name] = true
		out[i] = name
	}
	return out, nil
}

// csvInput maps a CSV input: one record per data row, an object of the
// row's non-empty cells keyed by column name. Records are numbered by the
// line their row starts on.
func (a *applier) csvInput(ctx context.Context, r *countingReader) error {
	br := bufio.NewReaderSize(r, sniffBytes)
	if b, _ := br.Peek(3); bytes.HasPrefix(b, utf8BOM) {
		_, _ = br.Discard(3)
	} else if len(b) >= 2 && ((b[0] == 0xFF && b[1] == 0xFE) || (b[0] == 0xFE && b[1] == 0xFF)) {
		return ErrEncoding
	}
	cfg := a.m.csv
	line := 0
	for i := 0; i < cfg.skip; i++ {
		_, _, err := readLine(br, a.opts.MaxRecordBytes)
		line++
		if err == io.EOF {
			a.issue(0, -1, "the input ends before the header row")
			return nil
		}
		if err != nil {
			return err
		}
	}
	delim := cfg.delim
	if delim == 0 {
		head, _ := br.Peek(sniffBytes)
		delim = detectDelimiter(head)
	}
	cr := csv.NewReader(br)
	cr.Comma = delim
	cr.FieldsPerRecord = -1
	header, err := cr.Read()
	if err == io.EOF {
		a.issue(0, -1, "the input has no header row")
		return nil
	}
	if err != nil {
		if r.n > a.opts.MaxInputBytes {
			return ErrInputTooLarge
		}
		return fmt.Errorf("mapping: header row: %s", cleanErr(err))
	}
	cols, err := columnNames(header)
	if err != nil {
		return err
	}
	if a.obs != nil {
		for _, c := range cols {
			a.obs.add("/" + escapeKey(c))
		}
	}
	for {
		if r.n > a.opts.MaxInputBytes {
			return ErrInputTooLarge
		}
		row, err := cr.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			var pe *csv.ParseError
			if !errors.As(err, &pe) {
				return err
			}
			a.issue(line+pe.StartLine, -1, "malformed row: "+pe.Err.Error())
			a.stats.Skipped++
			if stop, cerr := a.countRecord(); cerr != nil || stop {
				return cerr
			}
			continue
		}
		start, _ := cr.FieldPos(0)
		n := line + start
		rec, extra, msg := a.csvRow(cols, row)
		if msg != "" {
			a.issue(n, -1, msg)
			a.stats.Skipped++
			if stop, cerr := a.countRecord(); cerr != nil || stop {
				return cerr
			}
			continue
		}
		if extra > 0 {
			a.issue(n, -1, fmt.Sprintf("%d cells beyond the header row are ignored", extra))
		}
		if len(rec) == 0 {
			continue
		}
		if stop, err := a.decoded(ctx, n, rec); err != nil || stop {
			return err
		}
	}
}

// csvRow builds the record of one row. Whitespace-only cells are left out,
// so "exists" tells a filled cell from an empty one. A cell is kept as
// written (text, never evaluated: a cell starting with "=" is the text
// "=..."). msg is set when the row is refused.
func (a *applier) csvRow(cols, row []string) (rec map[string]any, extra int, msg string) {
	rec = make(map[string]any, len(row))
	total := 0
	for i, cell := range row {
		if i >= len(cols) {
			if strings.TrimSpace(cell) != "" {
				extra++
			}
			continue
		}
		if len(cell) > a.opts.MaxCellBytes {
			return nil, 0, fmt.Sprintf("cell %q is longer than %d bytes", truncate(cols[i], 64), a.opts.MaxCellBytes)
		}
		total += len(cell)
		if total > a.opts.MaxRecordBytes {
			return nil, 0, fmt.Sprintf("row longer than %d bytes", a.opts.MaxRecordBytes)
		}
		if strings.TrimSpace(cell) == "" {
			continue
		}
		rec[cols[i]] = cell
	}
	return rec, extra, ""
}
