package importer

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/ctis"
)

// Options configure Parse. The zero value detects the format and uses the
// default limits.
type Options struct {
	// Format of the input. Empty: Detect decides from the first bytes.
	Format Format

	// Limits on the input; zero fields take DefaultLimits.
	Limits Limits

	// Report timestamp. Zero: the time of the parse (UTC).
	Now time.Time

	// metadata.id of the report (an import or scan session id).
	ReportID string

	// metadata.source_type of the report. Empty: "manual" (a file someone
	// imports).
	SourceType string

	// tool.name of the report. Empty: the format's tool (nessus, qualys,
	// cyclonedx, ...).
	ToolName string

	// Findings below this severity are counted in Stats.Skipped and left
	// out. Empty keeps every finding.
	MinSeverity ctis.Severity

	// The asset of records that name none (a DefectDojo finding without an
	// endpoint). Nil: an unclassified asset named after the tool.
	DefaultAsset *ctis.Asset

	// The repository a code report (SARIF, semgrep, betterleaks, a trivy
	// file-system scan) is filed on, with its branch and commit. It wins
	// over what the file names (a SARIF versionControlProvenance, a trivy
	// artifact). A receiver that knows the repository from a verified
	// identity (a CI workload token) sets it from there and never from the
	// file; the importer only records the file's claim.
	Repository string
	Branch     string
	CommitSHA  string

	// SARIF only. ToolType is the kind of tool that wrote the log: "sast",
	// "sca", "secret", "iac" or "web3". It decides the type of every finding
	// and the tool's capabilities instead of the rule tags and the tool name
	// (a scanner runtime that knows what it ran sets it). Other values are
	// ignored. DefaultConfidence (1 to 100) is the confidence of a result
	// whose rule states no precision; zero or out of range: 90.
	ToolType          string
	DefaultConfidence int

	// The Qualys KnowledgeBase XML for a Qualys detection file. Optional:
	// without it, detections keep their QID and results but have no title
	// beyond the QID, CVEs or CVSS.
	QualysKnowledgeBase io.Reader
}

// Parse reads one exported file and converts it to CTIS.
//
// It returns a *ParseError (wrapping ErrUnknownFormat, ErrTooLarge,
// ErrUnsafe or ErrMalformed) when the input cannot be read at all. Problems
// with single records do not fail the parse; they are in Result.Issues and
// the record is skipped.
func Parse(ctx context.Context, r io.Reader, opts Options) (*Result, error) {
	res, _, err := parse(ctx, r, opts)
	return res, err
}

// parse is Parse that also returns the source field paths it saw.
func parse(ctx context.Context, r io.Reader, opts Options) (*Result, []string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	opts.Limits = opts.Limits.withDefaults()
	br := bufio.NewReaderSize(r, SniffLen)
	format := opts.Format
	if format == "" {
		head, err := br.Peek(SniffLen)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
			return nil, nil, &ParseError{Msg: "read input: " + err.Error(), Err: ErrMalformed}
		}
		f, ok := Detect(head)
		if !ok {
			return nil, nil, &ParseError{Msg: "the format is not recognized; supported: " + formatList(), Err: ErrUnknownFormat}
		}
		format = f
	}
	if format == FormatQualysKB {
		return nil, nil, &ParseError{Format: format, Msg: "a Qualys KnowledgeBase is read together with a detection file, not alone", Err: ErrUnknownFormat}
	}
	p, ok := parsers[format]
	if !ok {
		return nil, nil, &ParseError{Format: format, Msg: "not a supported format; supported: " + formatList(), Err: ErrUnknownFormat}
	}
	b := newBuilder(ctx, format, opts)
	if err := p(b, br); err != nil {
		return nil, nil, err
	}
	if err := b.guard(); err != nil {
		return nil, nil, err
	}
	return b.finish(), b.obs.paths(), nil
}

func formatList() string {
	var s []string
	for _, f := range AllFormats() {
		s = append(s, string(f))
	}
	return strings.Join(s, ", ")
}

// parsers are filled by the <format>.go files.
var parsers = map[Format]func(*builder, io.Reader) error{}

// companions name the spec of the document read together with the main
// document of a format (the Qualys KnowledgeBase).
var companions = map[Format]Format{FormatQualys: FormatQualysKB}

// tools are the default tool of each format.
var tools = map[Format]ctis.Tool{}

// builder collects one Result within the limits.
type builder struct {
	ctx    context.Context
	format Format
	opts   Options
	lim    Limits
	res    *Result
	obs    *observer
	assets map[string]int // asset id -> index
	ops    int
}

func newBuilder(ctx context.Context, format Format, opts Options) *builder {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	st := opts.SourceType
	if st == "" {
		st = "manual"
	}
	report := ctis.NewReport()
	report.Metadata.Timestamp = now
	report.Metadata.ID = opts.ReportID
	report.Metadata.SourceType = st
	tool := tools[format]
	if opts.ToolName != "" {
		tool.Name = opts.ToolName
	}
	if tool.Name != "" {
		t := tool
		t.Capabilities = append([]string(nil), tool.Capabilities...)
		report.Tool = &t
	}
	return &builder{
		ctx:    ctx,
		format: format,
		opts:   opts,
		lim:    opts.Limits,
		res:    &Result{Format: format, Report: report, Stats: Stats{BySeverity: map[ctis.Severity]int{}}},
		obs:    newObserver(opts.Limits.MaxObservedPaths),
		assets: map[string]int{},
	}
}

// tick checks the context every few thousand operations.
func (b *builder) tick() error {
	b.ops++
	if b.ops%4096 == 0 {
		if err := b.ctx.Err(); err != nil {
			return &ParseError{Format: b.format, Msg: "canceled", Err: err}
		}
	}
	return nil
}

func (b *builder) issue(is Issue) {
	if len(b.res.Issues) < b.lim.MaxIssues {
		b.res.Issues = append(b.res.Issues, is)
	}
}

func (b *builder) tooMany(what string, limit int) error {
	return &ParseError{Format: b.format, Msg: fmt.Sprintf("more than %d %s", limit, what), Err: ErrTooLarge}
}

// asset adds a (or returns the existing) asset by its id.
func (b *builder) asset(a ctis.Asset) (string, error) {
	if _, ok := b.assets[a.ID]; ok {
		return a.ID, nil
	}
	if len(b.res.Report.Assets) >= b.lim.MaxAssets {
		return "", b.tooMany("assets", b.lim.MaxAssets)
	}
	b.assets[a.ID] = len(b.res.Report.Assets)
	b.res.Report.Assets = append(b.res.Report.Assets, a)
	return a.ID, nil
}

// finding adds a finding unless it is below the minimum severity.
func (b *builder) finding(f ctis.Finding) error {
	if b.opts.MinSeverity != "" && f.Severity.Score() < b.opts.MinSeverity.Score() {
		b.res.Stats.Skipped++
		return nil
	}
	if len(b.res.Report.Findings) >= b.lim.MaxFindings {
		return b.tooMany("findings", b.lim.MaxFindings)
	}
	// Every format: a secret finding's unmasked snippet or masked value is
	// masked, here and wherever another field repeats it.
	ctis.RedactSecretFinding(&f)
	b.res.Report.Findings = append(b.res.Report.Findings, f)
	b.res.Stats.BySeverity[f.Severity]++
	return nil
}

// finish fills the counts and the unmapped paths.
func (b *builder) finish() *Result {
	r := b.res
	r.Stats.Assets = len(r.Report.Assets)
	r.Stats.Findings = len(r.Report.Findings)
	r.Stats.Components = len(r.Report.Dependencies)
	r.Stats.Statements = len(r.VEX)
	if spec, ok := specs[b.format]; ok {
		r.Unmapped = spec.Unmapped(b.obs.paths())
		// A companion document has its own spec.
		if comp, ok := specs[companions[b.format]]; ok {
			r.Unmapped = comp.Unmapped(r.Unmapped)
		}
	}
	if b.obs.overflow {
		b.issue(Issue{Message: fmt.Sprintf("more than %d distinct source fields; the unmapped list is incomplete", b.lim.MaxObservedPaths)})
	}
	if len(r.Stats.BySeverity) == 0 {
		r.Stats.BySeverity = nil
	}
	return r
}

// Text caps, the same as the CTIS receiver caps (spec section 7), so a
// report never carries more than a receiver keeps.
const (
	capTitle       = 500
	capCategory    = 255
	capDescription = 32 << 10
	capEvidence    = 64 << 10
	capRemediation = 16 << 10
	capReference   = 2 << 10
	maxReferences  = 100
	capTag         = 100
	maxTags        = 50
	capShort       = 255
)

const truncMarker = "…[truncated]"

// text cleans a source text: control characters other than tab, newline and
// carriage return are removed, the ends are trimmed, and a value longer than
// limit characters is cut with a marker.
func text(s string, limit int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return r
		}
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, s))
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	runes := []rune(s)
	return string(runes[:limit-utf8.RuneCountInString(truncMarker)]) + truncMarker
}

// line cleans a one-line value: like text, and newlines and tabs become
// spaces.
func line(s string, limit int) string {
	return text(strings.Join(strings.Fields(s), " "), limit)
}

// addRefs appends bounded, distinct references.
func addRefs(dst []string, refs ...string) []string {
	for _, r := range refs {
		r = line(r, capReference)
		if r == "" || len(dst) >= maxReferences {
			continue
		}
		dup := false
		for _, d := range dst {
			if d == r {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, r)
		}
	}
	return dst
}

// extra stores an unmapped source value on f (bounded by ctis.SetSourceExtra).
func extra(f *ctis.Finding, key, value string) {
	value = text(value, ctis.MaxSourceExtraValueLen)
	if value == "" {
		return
	}
	ctis.SetSourceExtra(f, key, value)
}

// extras stores key/value pairs in order (see extra).
func extras(f *ctis.Finding, kv ...string) {
	for i := 0; i+1 < len(kv); i += 2 {
		extra(f, kv[i], kv[i+1])
	}
}

// addVulnID adds a typed id to v once (canonical form), and keeps cve_ids in
// step.
func addVulnID(v *ctis.VulnerabilityDetails, raw string) {
	id, ok := ctis.NormalizeVulnerabilityID(strings.TrimSpace(raw))
	if !ok {
		return
	}
	for _, have := range v.IDs {
		if have.Type == id.Type && strings.EqualFold(have.ID, id.ID) {
			return
		}
	}
	if len(v.IDs) >= ctis.MaxVulnerabilityIDs {
		return
	}
	v.IDs = append(v.IDs, id)
	if id.Type == ctis.VulnerabilityIDCVE {
		v.CVEIDs = append(v.CVEIDs, id.ID)
		if v.CVEID == "" {
			v.CVEID = id.ID
		}
	}
}

// addScore appends a score if there is room and it is valid on its own.
func addScore(f *ctis.Finding, s ctis.Score) {
	if len(f.Scores) >= ctis.MaxScores {
		return
	}
	probe := ctis.Report{Version: ctis.SchemaVersion, Metadata: ctis.ReportMetadata{Timestamp: time.Unix(1, 0)}, Findings: []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "t", Severity: ctis.SeverityInfo, Scores: []ctis.Score{s}}}}
	if probe.Validate() != nil {
		return
	}
	f.Scores = append(f.Scores, s)
}
