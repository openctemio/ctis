// Package engine runs the declarative mapping files of the CTIS
// interoperability adapters (github.com/openctemio/ctis/v2/interop/<format>).
//
// A mapping file describes one direction (import or export) of one upstream
// version of one standard format:
//
//	interop/<format>/<upstream-version>/import.json
//	interop/<format>/<upstream-version>/export.json
//
// It lists every member of the upstream format the adapter knows and what
// becomes of it (a CTIS member, a named Go hook, or a stated reason to drop
// it), the tables the conversion looks values up in (severity maps, enum
// tables), rules the engine applies itself (a source member copied to a CTIS
// member through named transforms), and how the adapter recognises a
// document of that version. The engine
//
//   - loads and checks a mapping strictly (Load);
//   - picks the mapping of the version a document declares (Select);
//   - keeps every member the mapping does not list (Collect), bounded and
//     scrubbed, so an adapter stores it under extensions["<namespace>"] and
//     the reverse adapter writes it back (Reemit): an upstream member added
//     before the adapter maps it is not lost;
//   - applies the copy rules ("set") to the records the adapter built.
//
// The structural parts of a conversion that are not field to field (SARIF
// code flows, a CycloneDX dependency graph, VEX product resolution) are Go
// functions of the adapter, registered by name as hooks; a mapping names the
// hook that maps each such member and Load refuses a hook the adapter does
// not register. The language has no expressions, loops, code, file or
// network access.
package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/openctemio/ctis/v2"
)

// APIVersion is the apiVersion of a mapping file.
const APIVersion = "openctem.io/interop/v1"

// Direction of a mapping.
type Direction string

// Directions.
const (
	Import Direction = "import"
	Export Direction = "export"
)

// Limits of a mapping file.
const (
	MaxMappingBytes  = 512 << 10
	MaxFields        = 2000
	MaxTables        = 64
	MaxTableEntries  = 512
	MaxDetect        = 8
	MaxRecords       = 16
	MaxTransforms    = 8
	MaxNotes         = 64
	MaxNoteBytes     = 4096
	maxTextBytes     = 2048
	maxFormatNameLen = 32
)

// Mapping is one mapping file.
type Mapping struct {
	APIVersion string    `json:"apiVersion"`
	Format     string    `json:"format"`
	Version    string    `json:"version"`
	Direction  Direction `json:"direction"`

	// Namespace is the extensions namespace the passthrough members are
	// kept under (reverse-DNS, ctis.IsExtensionNamespace).
	Namespace string `json:"namespace"`

	// Title and Source describe the upstream format for readers.
	Title  string `json:"title"`
	Source string `json:"source,omitempty"`

	// VersionPointer (import) points to the member that declares the
	// document's version; the passthrough records that version.
	VersionPointer string `json:"version_pointer,omitempty"`

	// Detect: every predicate must hold for a document of this version
	// (import only).
	Detect []Predicate `json:"detect,omitempty"`

	// Notes are normalization rules that are not per field.
	Notes []string `json:"notes,omitempty"`

	// Records name the source objects that become one CTIS record each.
	// The passthrough members below a record are kept on that record, and
	// the "set" rules apply to it.
	Records []Record `json:"records,omitempty"`

	// Fields list every member the adapter knows, in document order.
	Fields []Field `json:"fields"`

	// Tables are the value tables the conversion uses.
	Tables map[string]Table `json:"tables,omitempty"`

	// Hooks are the Go functions of the adapter this mapping relies on.
	Hooks []string `json:"hooks,omitempty"`

	// ReemitFrom (export) lists the other upstream versions whose
	// passthrough this mapping writes back: a later version that keeps the
	// members of an earlier one.
	ReemitFrom []string `json:"reemit_from,omitempty"`

	// Passthrough lowers the default passthrough limits.
	Passthrough *Limits `json:"passthrough,omitempty"`

	digest string
	hooks  map[string]bool
}

// Predicate tests one member of a document.
type Predicate struct {
	// Pointer is an RFC 6901 pointer to a member (no array indexes).
	Pointer string `json:"pointer"`
	// Exactly one of the tests.
	Equals  *string  `json:"equals,omitempty"`
	In      []string `json:"in,omitempty"`
	Prefix  *string  `json:"prefix,omitempty"`
	Matches *string  `json:"matches,omitempty"`
	// Absent: the member is not there (or null).
	Absent bool `json:"absent,omitempty"`
	// OrAbsent: the test also holds when the member is not there.
	OrAbsent bool `json:"or_absent,omitempty"`

	re *regexp.Regexp
}

// Record is a source object that becomes one CTIS record.
type Record struct {
	Name string `json:"name"`
	// Path of the record objects ("/runs[]/results[]").
	Path string `json:"path"`
	// Kind of CTIS record: finding, asset, dependency or vex.
	Kind string `json:"kind"`
}

// Field is one member of the upstream format.
type Field struct {
	// Path of the member (pattern syntax, see MatchPath). Import: in the
	// source document; export: in the output.
	Path string `json:"path"`

	// Target says what keeps the value (import) or where it comes from
	// (export), for readers. "(container)" marks a member that only
	// groups others.
	Target string `json:"target,omitempty"`

	// Ignored says why the member is dropped on purpose. An ignored
	// member, and everything below it, is never passed through.
	Ignored string `json:"ignored,omitempty"`

	// Hook names the Go function of the adapter that maps the member.
	Hook string `json:"hook,omitempty"`

	// Set (import) is a rule the engine applies: the value is copied to
	// this CTIS member of the record (dotted JSON member names, relative to
	// the record), through Transform. A value that a transform rejects
	// leaves the member unset.
	Set       string   `json:"set,omitempty"`
	Record    string   `json:"record,omitempty"`
	Transform []string `json:"transform,omitempty"`
}

// Container is the Target of a member that only groups others.
const Container = "(container)"

// Mapped reports whether the field's value is kept.
func (f Field) Mapped() bool {
	return (f.Target != "" && f.Target != Container) || f.Set != ""
}

// Table is a value table: a source value is looked up after the table's
// normalization.
type Table struct {
	// Match: "exact" (the default), "fold" (case-insensitive, trimmed) or
	// "token" (trimmed, lower case, '_', '-' and ' ' removed).
	Match string `json:"match,omitempty"`
	// Map from the normalized source value to the target value.
	Map map[string]string `json:"map"`
	// Default for a value the map does not hold; absent: no value.
	Default *string `json:"default,omitempty"`
}

// LoadOptions name what the adapter provides.
type LoadOptions struct {
	// Hooks the adapter registers for this direction. A mapping that names
	// another hook is refused.
	Hooks []string
	// Tables the adapter's Go code looks up. A mapping without one of them
	// is refused, so a table cannot go missing silently.
	Tables []string
}

var (
	formatRE  = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	versionRE = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,3}$`)
	nameRE    = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)
	memberRE  = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){0,7}$`)
)

// ErrMapping wraps every error of Load.
var ErrMapping = errors.New("interop mapping")

func mappingErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMapping, fmt.Sprintf(format, args...))
}

// Load parses and checks a mapping file. Unknown members are errors.
func Load(data []byte, opts LoadOptions) (*Mapping, error) {
	if len(data) > MaxMappingBytes {
		return nil, mappingErr("file is larger than %d bytes", MaxMappingBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Mapping
	if err := dec.Decode(&m); err != nil {
		return nil, mappingErr("%v", err)
	}
	if dec.More() {
		return nil, mappingErr("more than one JSON value")
	}
	if err := m.check(opts); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	m.digest = "sha256:" + hex.EncodeToString(sum[:])
	return &m, nil
}

// MustLoad is Load for the mapping files an adapter embeds; it panics on an
// error, which the adapter's tests catch.
func MustLoad(data []byte, opts LoadOptions) *Mapping {
	m, err := Load(data, opts)
	if err != nil {
		panic(err)
	}
	return m
}

func (m *Mapping) check(opts LoadOptions) error {
	if m.APIVersion != APIVersion {
		return mappingErr("apiVersion %q, want %q", short(m.APIVersion), APIVersion)
	}
	if len(m.Format) > maxFormatNameLen || !formatRE.MatchString(m.Format) {
		return mappingErr("format %q is not a lowercase name", short(m.Format))
	}
	if !versionRE.MatchString(m.Version) {
		return mappingErr("version %q is not a dotted version", short(m.Version))
	}
	if m.Direction != Import && m.Direction != Export {
		return mappingErr("direction %q, want import or export", short(string(m.Direction)))
	}
	if !ctis.IsExtensionNamespace(m.Namespace) {
		return mappingErr("namespace %q is not a reverse-DNS namespace", short(m.Namespace))
	}
	if m.Title == "" || len(m.Title) > maxTextBytes || len(m.Source) > maxTextBytes {
		return mappingErr("title is empty, or title or source is longer than %d bytes", maxTextBytes)
	}
	if len(m.Notes) > MaxNotes {
		return mappingErr("more than %d notes", MaxNotes)
	}
	for _, n := range m.Notes {
		if len(n) > MaxNoteBytes {
			return mappingErr("a note is longer than %d bytes", MaxNoteBytes)
		}
	}
	if m.Direction == Export && len(m.Detect) > 0 {
		return mappingErr("detect is for import mappings")
	}
	if m.Direction == Import && len(m.ReemitFrom) > 0 {
		return mappingErr("reemit_from is for export mappings")
	}
	for _, v := range m.ReemitFrom {
		if !versionRE.MatchString(v) {
			return mappingErr("reemit_from %q is not a dotted version", short(v))
		}
	}
	if m.VersionPointer != "" {
		if toks, ok := parsePointer(m.VersionPointer); !ok || len(toks) == 0 || m.Direction != Import {
			return mappingErr("version_pointer %q (an import mapping's pointer to a member)", short(m.VersionPointer))
		}
	}
	if len(m.Detect) > MaxDetect {
		return mappingErr("more than %d detect predicates", MaxDetect)
	}
	for i := range m.Detect {
		if err := m.Detect[i].check(); err != nil {
			return mappingErr("detect[%d]: %v", i, err)
		}
	}
	if len(m.Tables) > MaxTables {
		return mappingErr("more than %d tables", MaxTables)
	}
	for name, t := range m.Tables {
		if !nameRE.MatchString(name) {
			return mappingErr("table name %q", short(name))
		}
		if len(t.Map) == 0 || len(t.Map) > MaxTableEntries {
			return mappingErr("table %s: 1 to %d entries", name, MaxTableEntries)
		}
		switch t.Match {
		case "", "exact", "fold", "token":
		default:
			return mappingErr("table %s: match %q", name, short(t.Match))
		}
		for k, v := range t.Map {
			if len(k) > maxTextBytes || len(v) > maxTextBytes {
				return mappingErr("table %s: an entry is longer than %d bytes", name, maxTextBytes)
			}
			if normalize(t.Match, k) != k {
				return mappingErr("table %s: key %q is not in its %s form", name, short(k), matchName(t.Match))
			}
		}
	}
	for _, name := range opts.Tables {
		if _, ok := m.Tables[name]; !ok {
			return mappingErr("table %s is missing (the adapter looks it up)", name)
		}
	}
	m.hooks = map[string]bool{}
	known := map[string]bool{}
	for _, h := range opts.Hooks {
		known[h] = true
	}
	for _, h := range m.Hooks {
		if !known[h] {
			return mappingErr("hook %q is not registered by the adapter", short(h))
		}
		m.hooks[h] = true
	}
	if len(m.Records) > MaxRecords {
		return mappingErr("more than %d records", MaxRecords)
	}
	records := map[string]Record{}
	for _, r := range m.Records {
		if !nameRE.MatchString(r.Name) || !strings.HasPrefix(r.Path, "/") || len(r.Path) > MaxPathBytes {
			return mappingErr("record %q: name or path", short(r.Name))
		}
		switch r.Kind {
		case "finding", "asset", "dependency", "vex":
		default:
			return mappingErr("record %s: kind %q", r.Name, short(r.Kind))
		}
		if _, dup := records[r.Name]; dup {
			return mappingErr("record %s listed twice", r.Name)
		}
		records[r.Name] = r
	}
	if len(m.Fields) == 0 || len(m.Fields) > MaxFields {
		return mappingErr("1 to %d fields", MaxFields)
	}
	seen := map[string]bool{}
	for _, f := range m.Fields {
		if err := m.checkField(f, records); err != nil {
			return mappingErr("field %s: %v", short(f.Path), err)
		}
		if seen[f.Path] {
			return mappingErr("field %s listed twice", short(f.Path))
		}
		seen[f.Path] = true
	}
	for _, h := range m.Hooks {
		used := false
		for _, f := range m.Fields {
			if f.Hook == h {
				used = true
				break
			}
		}
		if !used {
			return mappingErr("hook %s maps no field", h)
		}
	}
	if m.Passthrough != nil {
		if err := m.Passthrough.check(); err != nil {
			return mappingErr("passthrough: %v", err)
		}
	}
	return nil
}

func (m *Mapping) checkField(f Field, records map[string]Record) error {
	if f.Path == "" || !strings.HasPrefix(f.Path, "/") || len(f.Path) > MaxPathBytes {
		return errors.New("path must start with / and be at most 1024 bytes")
	}
	if len(f.Target) > maxTextBytes || len(f.Ignored) > maxTextBytes {
		return fmt.Errorf("target or ignored longer than %d bytes", maxTextBytes)
	}
	kept := f.Target != "" || f.Set != "" || f.Hook != ""
	if kept == (f.Ignored != "") {
		return errors.New("set exactly one of a target (target, set or hook) and ignored")
	}
	if f.Hook != "" && !m.hooks[f.Hook] {
		return fmt.Errorf("hook %q is not listed in hooks", short(f.Hook))
	}
	if f.Set == "" {
		if f.Record != "" || len(f.Transform) > 0 {
			return errors.New("record and transform belong to a set rule")
		}
		return nil
	}
	if m.Direction != Import {
		return errors.New("set rules are for import mappings")
	}
	if f.Hook != "" {
		return errors.New("a set rule has no hook")
	}
	r, ok := records[f.Record]
	if !ok {
		return fmt.Errorf("record %q is not declared", short(f.Record))
	}
	if !strings.HasPrefix(f.Path, r.Path+"/") {
		return fmt.Errorf("path is not below record %s (%s)", r.Name, r.Path)
	}
	if strings.Contains(f.Path[len(r.Path):], "[]") || strings.Contains(f.Path, "*") {
		return errors.New("a set rule reads one member of its record: no arrays or wildcards below the record")
	}
	if !memberRE.MatchString(f.Set) {
		return fmt.Errorf("set %q is not a dotted CTIS member", short(f.Set))
	}
	if err := checkTarget(r.Kind, f.Set); err != nil {
		return err
	}
	if len(f.Transform) > MaxTransforms {
		return fmt.Errorf("more than %d transforms", MaxTransforms)
	}
	for _, t := range f.Transform {
		if err := m.checkTransform(t); err != nil {
			return err
		}
	}
	return nil
}

func (p *Predicate) check() error {
	toks, ok := parsePointer(p.Pointer)
	if !ok || len(toks) == 0 {
		return fmt.Errorf("pointer %q", short(p.Pointer))
	}
	n := 0
	if p.Equals != nil {
		n++
	}
	if len(p.In) > 0 {
		n++
	}
	if p.Prefix != nil {
		n++
	}
	if p.Matches != nil {
		n++
		if len(*p.Matches) > 256 {
			return errors.New("matches is longer than 256 bytes")
		}
		re, err := regexp.Compile(*p.Matches)
		if err != nil {
			return fmt.Errorf("matches: %v", err)
		}
		p.re = re
	}
	if p.Absent {
		n++
	}
	if n != 1 {
		return errors.New("exactly one of equals, in, prefix, matches and absent")
	}
	if p.OrAbsent && p.Absent {
		return errors.New("or_absent goes with a test, not with absent")
	}
	return nil
}

// Digest is "sha256:<hex>" of the mapping file.
func (m *Mapping) Digest() string { return m.digest }

// Lookup looks a value up in a table: the value is normalized by the
// table's match, then mapped; a value the map does not hold gets the
// default. ok is false when there is no value. Lookup panics for a table the
// mapping does not have: the adapter names its tables in LoadOptions.Tables.
func (m *Mapping) Lookup(table, value string) (string, bool) {
	t, ok := m.Tables[table]
	if !ok {
		panic("engine: table " + table + " is not loaded; list it in LoadOptions.Tables")
	}
	if v, ok := t.Map[normalize(t.Match, value)]; ok {
		return v, true
	}
	if t.Default != nil {
		return *t.Default, true
	}
	return "", false
}

// Reverse returns the keys of a table that map to value, sorted.
func (m *Mapping) Reverse(table, value string) []string {
	t := m.Tables[table]
	var out []string
	for k, v := range t.Map {
		if v == value {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Match returns the first field whose path matches p.
func (m *Mapping) Match(p string) (Field, bool) {
	for _, f := range m.Fields {
		if MatchPath(f.Path, p) {
			return f, true
		}
	}
	return Field{}, false
}

// Owns reports whether the export mapping lists the output member at the
// pointer, or one below it: the adapter writes it, and Reemit never sets it.
func (m *Mapping) Owns(pointer string) bool {
	p, ok := PointerPath(pointer)
	if !ok {
		return true
	}
	for _, f := range m.Fields {
		if MatchPath(f.Path, p) || matchBelow(f.Path, p) {
			return true
		}
	}
	return false
}

func normalize(match, s string) string {
	switch match {
	case "fold":
		return strings.ToLower(strings.TrimSpace(s))
	case "token":
		s = strings.ToLower(strings.TrimSpace(s))
		return strings.NewReplacer("_", "", "-", "", " ", "").Replace(s)
	}
	return s
}

func matchName(m string) string {
	if m == "" {
		return "exact"
	}
	return m
}

func short(s string) string {
	if len(s) > 64 {
		s = s[:64] + "..."
	}
	return strings.ToValidUTF8(s, "?")
}
