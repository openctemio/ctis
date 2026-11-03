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

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/fingerprint"
)

// Options configure Parse. The zero value detects the format and uses the
// default limits.
type Options struct {
	// Format of the input. Empty: Detect decides from the first bytes.
	Format Format

	// Limits on the input; zero fields take DefaultLimits.
	Limits Limits

	// metadata.generated_at of the report. Zero: the time of the parse
	// (UTC).
	Now time.Time

	// metadata.id of the report: a lowercase UUIDv7 (ctis.NewReportID).
	// Empty: a new one. Anything else fails the parse.
	ReportID string

	// metadata.channel of the report. Empty: ChannelManual (a file someone
	// imports).
	Channel ctis.Channel

	// Key of the HMAC the secret fingerprint recipe needs
	// (fingerprint.NewSecretDigest), at least 16 bytes. With a key, a secret
	// finding the importer sees the raw secret of gets a recipe v2
	// fingerprint over its digest. Without one the fingerprint is left empty
	// and the receiver computes its own. The key and the secret never enter
	// the report.
	SecretKey []byte

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
	// and the tool's techniques instead of the rule tags and the tool name
	// (a scanner runtime that knows what it ran sets it). Other values are
	// ignored. DefaultConfidence (1 to 100) is the confidence of a result
	// whose rule states no precision; zero or out of range: 90.
	ToolType          string
	DefaultConfidence int

	// bounty_report only. The intake of records that carry none (the program
	// or platform the reports came from). Lower-cased; 1 to 64 characters of
	// a-z, 0-9, '.', '_' and '-', starting with a letter or digit. Empty:
	// "import". An invalid value fails the parse.
	BountyIntake string

	// ParseBundle only. Limits of a multi-file bundle; zero fields take
	// DefaultBundleLimits.
	Bundle BundleLimits

	// ParseBundle only. Domains the importing organization treats as its
	// own. A host of the bundle at or below one of them is marked
	// import_scope=in_target. Empty: the target domain the bundle names.
	ScopeDomains []string

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
	if opts.ReportID != "" && !ctis.IsReportID(opts.ReportID) {
		return nil, nil, &ParseError{Msg: "Options.ReportID must be a lowercase UUIDv7 (ctis.NewReportID)", Err: ErrMalformed}
	}
	if len(opts.SecretKey) > 0 && len(opts.SecretKey) < fingerprint.MinSecretKeyBytes {
		return nil, nil, &ParseError{Msg: fmt.Sprintf("Options.SecretKey must be at least %d bytes", fingerprint.MinSecretKeyBytes), Err: ErrMalformed}
	}
	if opts.Channel != "" && !opts.Channel.IsValid() {
		return nil, nil, &ParseError{Msg: fmt.Sprintf("Options.Channel %q is not a CTIS channel", line(string(opts.Channel), 32)), Err: ErrMalformed}
	}
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
	assets map[string]int    // asset id -> index
	byKey  map[string]string // asset key -> asset id
	rels   map[string]bool
	ops    int
}

func newBuilder(ctx context.Context, format Format, opts Options) *builder {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ch := opts.Channel
	if ch == "" {
		ch = ctis.ChannelManual
	}
	report := ctis.NewReport()
	report.Metadata.GeneratedAt = now
	if opts.ReportID != "" {
		report.Metadata.ID = opts.ReportID
	}
	report.Metadata.Channel = ch
	tool := tools[format]
	if opts.ToolName != "" {
		tool.Name = opts.ToolName
	}
	if tool.Name != "" {
		t := tool
		t.Techniques = append([]ctis.Technique(nil), tool.Techniques...)
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
		byKey:  map[string]string{},
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

// asset adds an asset, or returns the id of the one already there with the
// same id or the same type and canonical value. The value is made canonical
// for the type (ctis.CanonicalAssetValue); an asset whose value has no
// canonical form is left out with an issue and "" is returned (no error), so
// the caller skips what depends on it. An empty a.ID is derived from the
// type and the canonical value.
func (b *builder) asset(a ctis.Asset) (string, error) {
	c, err := ctis.CanonicalAssetValue(a.Type, a.Value)
	if err != nil {
		b.issue(Issue{Message: fmt.Sprintf("asset %s %q left out: %s", a.Type, line(a.Value, 200), line(err.Error(), 200))})
		return "", nil
	}
	a.Value = c
	key := string(a.Type) + "\x1f" + c
	if id, ok := b.byKey[key]; ok {
		return id, nil
	}
	if a.ID == "" {
		a.ID = docRef(string(a.Type), c)
	}
	if _, ok := b.assets[a.ID]; ok {
		return a.ID, nil
	}
	if len(b.res.Report.Assets) >= b.lim.MaxAssets {
		return "", b.tooMany("assets", b.lim.MaxAssets)
	}
	b.assets[a.ID] = len(b.res.Report.Assets)
	b.byKey[key] = a.ID
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
	r.Stats.Endpoints = len(r.Report.Endpoints)
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

// addVulnID adds a CVE, GHSA or OSV id to v once (canonical form); an id of
// another shape is dropped. Use addVendorID for a vendor's own id.
func addVulnID(v *ctis.VulnerabilityDetails, raw string) {
	if _, ok := ctis.NormalizeVulnerabilityID(strings.TrimSpace(raw)); !ok {
		return
	}
	v.AddID(raw, "")
}

// addVendorID adds an id the vendor named source issued (an advisory number,
// a plugin id the source treats as the vulnerability's) to v.
func addVendorID(v *ctis.VulnerabilityDetails, raw, source string) {
	id, ok := ctis.NormalizeVulnerabilityID(strings.TrimSpace(raw))
	if !ok || len(v.IDs) >= ctis.MaxVulnerabilityIDs {
		return
	}
	if id.Type == ctis.VulnerabilityIDVendor {
		id.Source = line(source, ctis.MaxScoreSourceLen)
	}
	for _, have := range v.IDs {
		if have.Type == id.Type && strings.EqualFold(have.ID, id.ID) {
			return
		}
	}
	v.IDs = append(v.IDs, id)
}

// sourceRef is a bounded source reference.
func sourceRef(system, id string) ctis.SourceRef {
	return ctis.SourceRef{System: system, ID: line(id, ctis.MaxSourceRefIDLen)}
}

// addScore appends a score if there is room and it is valid on its own.
func addScore(f *ctis.Finding, s ctis.Score) {
	if len(f.Scores) >= ctis.MaxScores {
		return
	}
	p := probe()
	p.Assets = []ctis.Asset{{ID: "probe", Type: ctis.AssetTypeHost, Value: "probe.invalid"}}
	p.Findings = []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "t", Severity: ctis.SeverityInfo, AssetRef: "probe", Scores: []ctis.Score{s}}}
	if p.Validate() != nil {
		return
	}
	f.Scores = append(f.Scores, s)
}
