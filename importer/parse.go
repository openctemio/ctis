package importer

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

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

	// NoPassthrough: the standard-format adapters leave out the members
	// their mapping does not list. By default they keep them under
	// extensions["org.ctis.interop.<format>"] (docs/interop.md).
	NoPassthrough bool

	// Observe lists the source field paths the input held in
	// Result.Fields (a mapping editor shows them next to Result.Unmapped).
	Observe bool

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
		if mod, isAdapter := adapterModules[format]; isAdapter {
			return nil, nil, &ParseError{Format: format, Msg: "this format is read by the adapter module " + mod + "; import it to read " + string(format), Err: ErrUnknownFormat}
		}
		return nil, nil, &ParseError{Format: format, Msg: "not a supported format; supported: " + formatList(), Err: ErrUnknownFormat}
	}
	b := newBuilder(ctx, format, opts)
	if err := p(b, br); err != nil {
		return nil, nil, err
	}
	if err := b.guard(); err != nil {
		return nil, nil, err
	}
	res, paths := b.finish(), b.obs.paths()
	if opts.Observe {
		res.Fields = paths
	}
	return res, paths, nil
}

func formatList() string {
	var s []string
	for _, f := range AllFormats() {
		s = append(s, string(f))
	}
	return strings.Join(s, ", ")
}

// parsers are filled by the <format>.go files.
var parsers = map[Format]func(*Builder, io.Reader) error{}

// companions name the spec of the document read together with the main
// document of a format (the Qualys KnowledgeBase).
var companions = map[Format]Format{FormatQualys: FormatQualysKB}

// tools are the default tool of each format.
var tools = map[Format]ctis.Tool{}

// builder collects one Result within the limits.
type Builder struct {
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

func newBuilder(ctx context.Context, format Format, opts Options) *Builder {
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
	return &Builder{
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
func (b *Builder) tick() error {
	b.ops++
	if b.ops%4096 == 0 {
		if err := b.ctx.Err(); err != nil {
			return &ParseError{Format: b.format, Msg: "canceled", Err: err}
		}
	}
	return nil
}

func (b *Builder) issue(is Issue) {
	if len(b.res.Issues) < b.lim.MaxIssues {
		b.res.Issues = append(b.res.Issues, is)
	}
}

func (b *Builder) tooMany(what string, limit int) error {
	return &ParseError{Format: b.format, Msg: fmt.Sprintf("more than %d %s", limit, what), Err: ErrTooLarge}
}

// asset adds an asset, or returns the id of the one already there with the
// same id or the same type and canonical value. The value is made canonical
// for the type (ctis.CanonicalAssetValue); an asset whose value has no
// canonical form is left out with an issue and "" is returned (no error), so
// the caller skips what depends on it. An empty a.ID is derived from the
// type and the canonical value.
func (b *Builder) asset(a ctis.Asset) (string, error) {
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
func (b *Builder) finding(f ctis.Finding) error {
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
func (b *Builder) finish() *Result {
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
