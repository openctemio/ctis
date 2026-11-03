package importer

import (
	"fmt"
	"io"
	"sync"

	"github.com/openctemio/ctis/v2"
)

// The standard formats (SARIF, CycloneDX, SPDX, CSAF, OpenVEX) are read by
// the interoperability adapters, each its own Go module:
// github.com/openctemio/ctis/v2/interop/<format>. An adapter registers its
// format here from its init function, so Parse, with format detection,
// reads that format in any program that imports the adapter:
//
//	import _ "github.com/openctemio/ctis/v2/interop/sarif"
//
// Without the adapter, Parse still detects the format and fails with an
// ErrUnknownFormat that names the module to import. This package never
// imports an adapter.

// Adapter is what an adapter registers for one format.
type Adapter struct {
	// Parse converts one input. It reads the input through the Builder
	// (ReadAll, ScanJSON) so the size, depth and UTF-8 limits apply, and
	// adds what it converts through the Builder (Asset, Finding,
	// Dependency, Statement), so the record limits, the minimum severity
	// and the secret masking apply.
	Parse func(b *Builder, r io.Reader) error

	// Tool is the format's default tool (tool.name of the report).
	Tool ctis.Tool

	// Spec lists every source field the adapter knows (Result.Unmapped,
	// docs/importers).
	Spec Spec
}

// adapterModules names the module of each format read by an adapter.
var adapterModules = map[Format]string{
	FormatSARIF:     "github.com/openctemio/ctis/v2/interop/sarif",
	FormatCycloneDX: "github.com/openctemio/ctis/v2/interop/cyclonedx",
	FormatSPDX:      "github.com/openctemio/ctis/v2/interop/spdx",
	FormatCSAF:      "github.com/openctemio/ctis/v2/interop/csaf",
	FormatOpenVEX:   "github.com/openctemio/ctis/v2/interop/openvex",
}

// AdapterModule returns the Go module whose adapter reads format, and false
// for a format this package reads itself.
func AdapterModule(f Format) (string, bool) {
	m, ok := adapterModules[f]
	return m, ok
}

var registerMu sync.Mutex

// Register makes Parse read format f with a. Only the formats an adapter
// module reads (AdapterModule) can be registered, each once; anything else
// panics, because it is a programming error in the adapter.
func Register(f Format, a Adapter) {
	registerMu.Lock()
	defer registerMu.Unlock()
	if _, ok := adapterModules[f]; !ok {
		panic(fmt.Sprintf("importer: %q is not a format an adapter registers", f))
	}
	if a.Parse == nil {
		panic(fmt.Sprintf("importer: adapter for %q has no Parse", f))
	}
	if _, dup := parsers[f]; dup {
		panic(fmt.Sprintf("importer: adapter for %q registered twice", f))
	}
	a.Spec.Format = f
	parsers[f] = a.Parse
	tools[f] = a.Tool
	registerSpec(a.Spec)
}

// Registered reports whether Parse can read f: a format of this package, or
// one whose adapter is linked into the program.
func Registered(f Format) bool {
	registerMu.Lock()
	defer registerMu.Unlock()
	_, ok := parsers[f]
	return ok
}

// --- Builder methods for adapters ------------------------------------------

// Format is the format being read.
func (b *Builder) Format() Format { return b.format }

// Options are the options of the parse.
func (b *Builder) Options() Options { return b.opts }

// Limits are the limits of the parse, defaults filled in.
func (b *Builder) Limits() Limits { return b.lim }

// Result is the result being built: the report, the VEX statements and the
// counts. An adapter sets the report's tool and metadata and counts
// Stats.Records and Stats.Skipped; it adds records only through the Builder.
func (b *Builder) Result() *Result { return b.res }

// ReadAll reads the whole input within Limits.MaxInputBytes and drops a
// UTF-8 byte order mark.
func (b *Builder) ReadAll(r io.Reader) ([]byte, error) { return readAll(r, b.format, b.lim) }

// ScanJSON checks a JSON input (UTF-8, syntax, depth, string length) in one
// streaming pass before anything is decoded, records the source field paths
// for Result.Unmapped, and the offsets of the elements of the arrays named
// in index ("/runs[]/results[]") for the line numbers of issues.
func (b *Builder) ScanJSON(data []byte, index ...string) (*JSONDoc, error) {
	d, err := scanJSON(data, b.format, b.lim, b.obs, index...)
	if err != nil {
		return nil, err
	}
	return &JSONDoc{d: d}, nil
}

// Tick checks the context every few thousand calls.
func (b *Builder) Tick() error { return b.tick() }

// Issue records a problem that does not stop the parse (at most
// Limits.MaxIssues are kept).
func (b *Builder) Issue(is Issue) { b.issue(is) }

// TooMany is the error of a record limit.
func (b *Builder) TooMany(what string, limit int) error { return b.tooMany(what, limit) }

// Asset adds an asset (value made canonical, deduplicated by type and
// canonical value) and returns its id; "" with no error when the value has
// no canonical form (an issue says why).
func (b *Builder) Asset(a ctis.Asset) (string, error) { return b.asset(a) }

// AssetByID returns the asset with the id, for in-place additions.
func (b *Builder) AssetByID(id string) *ctis.Asset { return b.assetByID(id) }

// Finding adds a finding unless it is below Options.MinSeverity; a secret
// finding is masked (ctis.RedactSecretFinding).
func (b *Builder) Finding(f ctis.Finding) error { return b.finding(f) }

// Dependency adds a component of the scanned asset.
func (b *Builder) Dependency(d ctis.Dependency) error { return b.dependency(d) }

// Statement adds a VEX statement.
func (b *Builder) Statement(s VEXStatement) error { return b.statement(s) }

// CodeAsset is the asset a code report is filed on: Options.Repository,
// else fromFile (what the file names), else Options.DefaultAsset, else an
// unclassified asset named after the tool.
func (b *Builder) CodeAsset(fromFile *ctis.Asset) ctis.Asset { return b.codeAsset(fromFile) }

// JSONDoc is a JSON input that passed Builder.ScanJSON.
type JSONDoc struct{ d *jsonDoc }

// Decode decodes the document into v.
func (d *JSONDoc) Decode(v any) error { return d.d.decode(v) }

// IssueAt returns an Issue at element i of the indexed array at path, with
// its line and column.
func (d *JSONDoc) IssueAt(path string, i int, pointer, msg string) Issue {
	return d.d.issueAt(path, i, pointer, msg)
}
