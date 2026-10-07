package mapping

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/openctemio/ctis"
)

// Default bounds of Apply.
const (
	DefaultMaxInputBytes  = 64 << 20
	DefaultMaxRecordBytes = 1 << 20
	DefaultMaxRecords     = 200_000
	DefaultMaxOutputs     = 200_000
	DefaultMaxIssues      = 200
	MaxInputDepth         = 64

	// Text caps per member: long-text members keep 64 KiB, every other
	// string 4 KiB.
	longTextBytes  = 64 << 10
	shortTextBytes = 4 << 10
)

// longText are member names that hold free text; they keep tab, newline
// and carriage return and are capped at 64 KiB.
var longText = map[string]bool{
	"evidence": true, "description": true, "message": true, "snippet": true,
	"context_snippet": true, "banner": true, "impact": true, "recommendation": true,
}

// Errors of Apply.
var (
	ErrInputTooLarge = errors.New("mapping: input is larger than the limit")
	ErrNotAList      = errors.New("mapping: the each path does not name a list")
)

// Options bound and stamp one Apply.
type Options struct {
	// Now is the report clock; nil means time.Now. Inject it for
	// reproducible output.
	Now func() time.Time
	// Tool is copied into report.tool. A mapping never sets it from the
	// input, so a tool's output cannot claim to be another tool.
	Tool *ctis.Tool

	MaxInputBytes  int64 // whole input; default 64 MiB
	MaxRecordBytes int   // one JSON Lines line; default 1 MiB
	MaxRecords     int   // input records read; default 200 000
	MaxOutputs     int   // assets + findings + dependencies; default 200 000
	MaxIssues      int   // Stats.Issues kept; default 200
}

func (o Options) withDefaults() Options {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.MaxInputBytes <= 0 {
		o.MaxInputBytes = DefaultMaxInputBytes
	}
	if o.MaxRecordBytes <= 0 {
		o.MaxRecordBytes = DefaultMaxRecordBytes
	}
	if o.MaxRecords <= 0 {
		o.MaxRecords = DefaultMaxRecords
	}
	if o.MaxOutputs <= 0 {
		o.MaxOutputs = DefaultMaxOutputs
	}
	if o.MaxIssues <= 0 {
		o.MaxIssues = DefaultMaxIssues
	}
	return o
}

// Issue is a record that was skipped or a rule output that was dropped.
type Issue struct {
	// Record is the 1-based input record (the line for JSON Lines).
	Record int `json:"record"`
	// Rule is the index of the rule, or -1 for the record itself.
	Rule    int    `json:"rule"`
	Message string `json:"message"`
}

func (i Issue) String() string {
	if i.Rule < 0 {
		return fmt.Sprintf("record %d: %s", i.Record, i.Message)
	}
	return fmt.Sprintf("record %d, rule %d: %s", i.Record, i.Rule, i.Message)
}

// Stats count what Apply did.
type Stats struct {
	Records      int     `json:"records"`
	Assets       int     `json:"assets"`
	Findings     int     `json:"findings"`
	Dependencies int     `json:"dependencies"`
	Skipped      int     `json:"skipped"`
	Truncated    bool    `json:"truncated"`
	Issues       []Issue `json:"issues,omitempty"`
}

type applier struct {
	m      *Mapping
	opts   Options
	now    time.Time
	report *ctis.Report
	stats  Stats
}

// Apply reads the tool output from r and returns the CTIS report the
// mapping makes of it. Every rule whose predicates hold emits one record;
// a record that does not decode into its CTIS type or does not validate is
// skipped and counted. The output is deterministic for the same input,
// mapping and Options.Now.
//
// A record limit or output limit ends the read early with Stats.Truncated
// set; an input larger than MaxInputBytes, a malformed json document or a
// canceled ctx returns an error and no report.
func (m *Mapping) Apply(ctx context.Context, r io.Reader, opts Options) (*ctis.Report, Stats, error) {
	opts = opts.withDefaults()
	a := &applier{m: m, opts: opts, now: opts.Now().UTC()}
	a.report = &ctis.Report{
		Version:  ctis.SchemaVersion,
		Schema:   ctis.SchemaURL,
		Metadata: ctis.ReportMetadata{Timestamp: a.now, SourceType: "scanner"},
	}
	if opts.Tool != nil {
		t := *opts.Tool
		t.Capabilities = append([]string(nil), t.Capabilities...)
		a.report.Tool = &t
	}
	lr := &countingReader{r: io.LimitReader(r, opts.MaxInputBytes+1)}
	var err error
	switch m.doc.Source {
	case SourceJSONL:
		err = a.jsonl(ctx, lr)
	default:
		err = a.json(ctx, lr)
	}
	if err == nil && lr.n > opts.MaxInputBytes {
		err = ErrInputTooLarge
	}
	if err != nil {
		return nil, a.stats, err
	}
	return a.report, a.stats, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (a *applier) jsonl(ctx context.Context, r *countingReader) error {
	br := bufio.NewReaderSize(r, 64<<10)
	for line := 1; ; line++ {
		if r.n > a.opts.MaxInputBytes {
			return ErrInputTooLarge
		}
		data, tooLong, err := readLine(br, a.opts.MaxRecordBytes)
		if err != nil && err != io.EOF {
			return err
		}
		if tooLong {
			a.issue(line, -1, fmt.Sprintf("line longer than %d bytes", a.opts.MaxRecordBytes))
			a.stats.Skipped++
			if stop, cerr := a.countRecord(); cerr != nil || stop {
				return cerr
			}
		} else if len(bytes.TrimSpace(data)) > 0 {
			if stop, cerr := a.record(ctx, line, data); cerr != nil || stop {
				return cerr
			}
		}
		if err == io.EOF {
			return nil
		}
	}
}

// readLine reads one line without its newline. A line longer than max is
// consumed and reported as tooLong without being kept.
func readLine(br *bufio.Reader, max int) (line []byte, tooLong bool, err error) {
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(buf)+len(chunk) > max+1 { // +1: the newline
			tooLong = true
			buf = nil
		} else if !tooLong {
			buf = append(buf, chunk...)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return bytes.TrimRight(buf, "\r\n"), tooLong, err
	}
}

func (a *applier) json(ctx context.Context, r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if int64(len(data)) > a.opts.MaxInputBytes {
		return ErrInputTooLarge
	}
	if err := checkDepth(data, MaxInputDepth); err != nil {
		return fmt.Errorf("mapping: input %w", err)
	}
	doc, err := decodeValue(data)
	if err != nil {
		return fmt.Errorf("mapping: input: %w", err)
	}
	root, ok := a.m.each.get(doc)
	if !ok {
		a.issue(0, -1, "the each path is not in the document")
		return nil
	}
	records, ok := root.([]any)
	if !ok {
		if len(a.m.each) > 0 {
			return ErrNotAList
		}
		records = []any{root}
	}
	for i, rec := range records {
		if stop, err := a.decoded(ctx, i+1, rec); err != nil || stop {
			return err
		}
	}
	return nil
}

func decodeValue(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after the JSON value")
	}
	return v, nil
}

// record decodes one JSON Lines line and maps it.
func (a *applier) record(ctx context.Context, n int, data []byte) (bool, error) {
	if err := checkDepth(data, MaxInputDepth); err != nil {
		a.issue(n, -1, err.Error())
		a.stats.Skipped++
		return a.countRecord()
	}
	v, err := decodeValue(data)
	if err != nil {
		a.issue(n, -1, "not a JSON value: "+err.Error())
		a.stats.Skipped++
		return a.countRecord()
	}
	return a.decoded(ctx, n, v)
}

// countRecord counts a read record and reports whether to stop.
func (a *applier) countRecord() (bool, error) {
	a.stats.Records++
	if a.stats.Records >= a.opts.MaxRecords {
		a.stats.Truncated = true
		return true, nil
	}
	return false, nil
}

func (a *applier) decoded(ctx context.Context, n int, rec any) (bool, error) {
	if a.stats.Records%256 == 0 {
		if err := ctx.Err(); err != nil {
			return true, err
		}
	}
	for i, r := range a.m.rules {
		if !r.matches(rec) {
			continue
		}
		if a.stats.Assets+a.stats.Findings+a.stats.Dependencies >= a.opts.MaxOutputs {
			a.stats.Truncated = true
			return true, nil
		}
		if err := a.emit(r, rec); err != nil {
			a.issue(n, i, err.Error())
			a.stats.Skipped++
		}
	}
	return a.countRecord()
}

func (r rule) matches(rec any) bool {
	for _, p := range r.when {
		if !p.holds(rec) {
			return false
		}
	}
	return true
}

func (p predicate) holds(rec any) bool {
	v, ok := p.path.get(rec)
	if p.exists != nil {
		return (ok && v != nil) == *p.exists
	}
	if !ok {
		return false
	}
	s, ok := scalarString(v)
	if !ok {
		return false
	}
	switch {
	case p.equals != nil:
		return s == *p.equals
	case p.in != nil:
		return p.in[s]
	default:
		return p.re.MatchString(truncate(s, shortTextBytes))
	}
}

// emit builds one CTIS record from the rule's setters and appends it.
func (a *applier) emit(r rule, rec any) error {
	tree := map[string]any{}
	for _, s := range r.sets {
		v, ok := s.value.eval(rec)
		if !ok {
			continue
		}
		setPath(tree, s.target, sanitize(v, s.target[len(s.target)-1]))
	}
	raw, err := json.Marshal(tree)
	if err != nil {
		return err
	}
	probe := ctis.Report{Version: ctis.SchemaVersion, Metadata: ctis.ReportMetadata{Timestamp: a.now}}
	switch r.kind {
	case KindAsset:
		var as ctis.Asset
		if err := strictDecode(raw, &as); err != nil {
			return fmt.Errorf("asset: %s", cleanErr(err))
		}
		probe.Assets = []ctis.Asset{as}
		if err := probe.Validate(); err != nil {
			return err
		}
		a.report.Assets = append(a.report.Assets, as)
		a.stats.Assets++
	case KindFinding:
		var f ctis.Finding
		if err := strictDecode(raw, &f); err != nil {
			return fmt.Errorf("finding: %s", cleanErr(err))
		}
		if f.Type == "" {
			f.Type = ctis.FindingTypeVulnerability
		}
		if f.Type == ctis.FindingTypeSecret {
			ctis.RedactSecretFinding(&f)
		}
		probe.Findings = []ctis.Finding{f}
		if err := probe.Validate(); err != nil {
			return err
		}
		a.report.Findings = append(a.report.Findings, f)
		a.stats.Findings++
	case KindDependency:
		var d ctis.Dependency
		if err := strictDecode(raw, &d); err != nil {
			return fmt.Errorf("dependency: %s", cleanErr(err))
		}
		if strings.TrimSpace(d.Name) == "" {
			return errors.New("dependency: name is required")
		}
		a.report.Dependencies = append(a.report.Dependencies, d)
		a.stats.Dependencies++
	}
	return nil
}

// cleanErr keeps a decode error short; it may quote input.
func cleanErr(err error) string { return truncate(err.Error(), 200) }

func setPath(tree map[string]any, segs []string, v any) {
	cur := tree
	for _, s := range segs[:len(segs)-1] {
		next, ok := cur[s].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[s] = next
		}
		cur = next
	}
	cur[segs[len(segs)-1]] = v
}

// sanitize strips control characters from every string of v (long-text
// members keep tab, newline and carriage return), repairs invalid UTF-8 and
// caps the length.
func sanitize(v any, member string) any {
	long := longText[member]
	limit := shortTextBytes
	if long {
		limit = longTextBytes
	}
	clean := func(s string) string {
		s = strings.ToValidUTF8(s, "�")
		s = strings.Map(func(r rune) rune {
			if r == '\t' || r == '\n' || r == '\r' {
				if long {
					return r
				}
				return ' '
			}
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == ' ' || r == ' ' {
				return -1
			}
			return r
		}, s)
		return truncate(s, limit)
	}
	switch t := v.(type) {
	case string:
		return clean(t)
	case []any:
		out := make([]any, len(t))
		for i, it := range t {
			if s, ok := it.(string); ok {
				out[i] = clean(s)
			} else {
				out[i] = it
			}
		}
		return out
	}
	return v
}

func (a *applier) issue(record, rule int, msg string) {
	if len(a.stats.Issues) < a.opts.MaxIssues {
		// A message may quote the input: keep it one bounded, clean line.
		msg, _ = sanitize(msg, "message").(string)
		msg = strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(truncate(msg, 300))
		a.stats.Issues = append(a.stats.Issues, Issue{Record: record, Rule: rule, Message: msg})
	}
}
