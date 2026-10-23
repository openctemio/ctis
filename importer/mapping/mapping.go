// Package mapping turns the JSON, JSON Lines, CSV or XML output of any tool
// into a CTIS report through a declarative mapping file, so a tool or an
// export needs no parser code.
//
// A mapping is a JSON document (apiVersion "openctem.io/mapping/v1"). Each
// rule selects input records with closed predicates and sets CTIS members
// from source paths with a closed set of transforms. The language has no
// expressions, loops, code or I/O: it cannot read files, reach the network
// or run for longer than the input it walks. A tool that keeps its mapping
// in YAML converts it to JSON before calling Load; the strict decoding here
// is the authority.
//
// The full language is in docs/mapping.md.
package mapping

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/openctemio/ctis"
)

// APIVersion is the only mapping format version this package reads.
const APIVersion = "openctem.io/mapping/v1"

// Bounds on a mapping file.
const (
	MaxMappingBytes  = 256 << 10
	MaxRules         = 200
	MaxSetsPerRule   = 100
	MaxPredicates    = 16
	MaxRegexLen      = 256
	MaxMapEntries    = 256
	MaxInValues      = 256
	MaxTemplateBytes = 1024
	MaxIdentity      = 8
	MaxSkipRows      = 100
	maxMappingDepth  = 32
)

// Source formats.
const (
	SourceJSON  = "json"
	SourceJSONL = "jsonl"
	SourceCSV   = "csv"
	SourceXML   = "xml"
)

// Record kinds.
const (
	KindAsset      = "asset"
	KindFinding    = "finding"
	KindDependency = "dependency"
)

// Mapping is a loaded, validated mapping file.
type Mapping struct {
	doc    document
	each   path
	xmlSel xmlSelector
	csv    csvConfig
	rules  []rule
	refs   []string   // referenced source paths, normalized (observe.go)
	ident  [][]string // the identity members, split at dots
	digest string
}

// document is the file as written.
type document struct {
	APIVersion string     `json:"apiVersion"`
	Source     string     `json:"source"`
	Each       string     `json:"each,omitempty"`
	CSV        *CSVSpec   `json:"csv,omitempty"`
	Identity   []string   `json:"identity,omitempty"`
	Records    []RuleSpec `json:"records"`
	Notes      string     `json:"notes,omitempty"`
}

// CSVSpec reads a CSV input (source "csv").
type CSVSpec struct {
	// Delimiter is ",", ";", "\t", "|" or "auto" (the default): the one
	// of these that occurs most often, outside quotes, in the header row.
	Delimiter string `json:"delimiter,omitempty"`
	// SkipRows are lines before the header row (a report title, an export
	// date), 0 to MaxSkipRows.
	SkipRows int `json:"skip_rows,omitempty"`
}

// RuleSpec is one rule as written in the file.
type RuleSpec struct {
	When Predicates           `json:"when,omitempty"`
	Kind string               `json:"kind"`
	Set  map[string]ValueSpec `json:"set"`
}

// Predicate is one closed condition on an input record. Exactly one of
// Exists, Equals, In and Matches is set.
type Predicate struct {
	Path    string `json:"path"`
	Exists  *bool  `json:"exists,omitempty"`
	Equals  any    `json:"equals,omitempty"`
	In      []any  `json:"in,omitempty"`
	Matches string `json:"matches,omitempty"`
}

// Predicates is "when": one predicate object or a list that must all hold.
type Predicates []Predicate

// UnmarshalJSON accepts an object or an array of objects.
func (p *Predicates) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '{' {
		var one Predicate
		if err := strictDecode(b, &one); err != nil {
			return err
		}
		*p = Predicates{one}
		return nil
	}
	var many []Predicate
	if err := strictDecode(b, &many); err != nil {
		return err
	}
	*p = many
	return nil
}

// ValueSpec is how one CTIS member gets its value: a bare string is a
// source path; an object takes exactly one of Path, Const and Template, then
// the transforms in this order: First, Trim, Lower, Upper, Split, Map, Join,
// As, MaxBytes. Default applies when the result is missing or empty.
type ValueSpec struct {
	Path     string            `json:"path,omitempty"`
	Const    any               `json:"const,omitempty"`
	Template string            `json:"template,omitempty"`
	Vars     map[string]string `json:"vars,omitempty"`
	Default  any               `json:"default,omitempty"`
	First    bool              `json:"first,omitempty"`
	Trim     bool              `json:"trim,omitempty"`
	Lower    bool              `json:"lower,omitempty"`
	Upper    bool              `json:"upper,omitempty"`
	Split    string            `json:"split,omitempty"`
	Map      map[string]string `json:"map,omitempty"`
	Join     *string           `json:"join,omitempty"`
	As       string            `json:"as,omitempty"`
	MaxBytes int               `json:"max_bytes,omitempty"`

	bare bool
}

// UnmarshalJSON accepts a bare path string or an object.
func (v *ValueSpec) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*v = ValueSpec{Path: s, bare: true}
		return nil
	}
	type plain ValueSpec
	var p plain
	if err := strictDecode(b, &p); err != nil {
		return err
	}
	*v = ValueSpec(p)
	return nil
}

// MarshalJSON writes a bare path back as a string, so the digest of a
// mapping does not depend on which spelling its author used.
func (v ValueSpec) MarshalJSON() ([]byte, error) {
	if v.bare {
		return json.Marshal(v.Path)
	}
	type plain ValueSpec
	return json.Marshal(plain(v))
}

func strictDecode(b []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// Load parses and validates a mapping file. Every error names the rule and
// member it is about.
func Load(data []byte) (*Mapping, error) {
	if len(data) > MaxMappingBytes {
		return nil, fmt.Errorf("mapping is %d bytes, more than %d", len(data), MaxMappingBytes)
	}
	if err := checkDepth(data, maxMappingDepth); err != nil {
		return nil, fmt.Errorf("mapping: %w", err)
	}
	var doc document
	if err := strictDecode(data, &doc); err != nil {
		return nil, fmt.Errorf("mapping: %w", err)
	}
	m := &Mapping{doc: doc}
	if err := m.compile(); err != nil {
		return nil, err
	}
	canon, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("mapping: %w", err)
	}
	sum := sha256.Sum256(canon)
	m.digest = "sha256:" + hex.EncodeToString(sum[:])
	return m, nil
}

// Digest is the SHA-256 of the mapping's canonical JSON form
// ("sha256:<hex>"): object members sorted, insignificant whitespace removed.
// Reformatting or reordering a file keeps it; any change of content does
// not. A tool descriptor records it, so the mapping is covered by the
// descriptor's own digest.
func (m *Mapping) Digest() string { return m.digest }

// Source is the input format: "json", "jsonl", "csv" or "xml".
func (m *Mapping) Source() string { return m.doc.Source }

// Identity is the list of finding members the mapping declares as the
// identity of a finding (empty when it declares none). A receiver compares
// it, and the value specs of these members (Rules), across versions of a
// mapping: a change of identity makes earlier findings and new ones keyed
// apart.
func (m *Mapping) Identity() []string { return append([]string(nil), m.doc.Identity...) }

// RuleSummary describes one rule for a receiver that checks a mapping
// against its own policy (members it reserves) or compares two versions.
type RuleSummary struct {
	Kind string `json:"kind"`
	// Targets are the members the rule sets, sorted.
	Targets []string `json:"targets"`
	// Specs is the canonical JSON of each target's value spec.
	Specs map[string]string `json:"specs"`
	// Const is true for a target whose value is a constant.
	Const map[string]bool `json:"const,omitempty"`
}

// Rules summarizes the rules in order.
func (m *Mapping) Rules() []RuleSummary {
	out := make([]RuleSummary, 0, len(m.doc.Records))
	for _, spec := range m.doc.Records {
		rs := RuleSummary{Kind: spec.Kind, Targets: sortedKeys(spec.Set), Specs: map[string]string{}}
		for _, t := range rs.Targets {
			b, _ := json.Marshal(spec.Set[t])
			rs.Specs[t] = string(b)
			if spec.Set[t].isConstant() {
				if rs.Const == nil {
					rs.Const = map[string]bool{}
				}
				rs.Const[t] = true
			}
		}
		out = append(out, rs)
	}
	return out
}

// isConstant: the value is the same for every record. A template always
// has a variable, so only a const is.
func (v ValueSpec) isConstant() bool {
	return v.Const != nil && v.Path == "" && !v.bare && v.Template == ""
}

func (m *Mapping) compile() error {
	d := m.doc
	if d.APIVersion != APIVersion {
		return fmt.Errorf("mapping: apiVersion %q, want %q", d.APIVersion, APIVersion)
	}
	if d.CSV != nil && d.Source != SourceCSV {
		return errors.New("mapping: csv is for source csv only")
	}
	switch d.Source {
	case SourceJSON:
		p, err := parsePath(d.Each)
		if err != nil {
			return fmt.Errorf("mapping: each: %w", err)
		}
		m.each = p
	case SourceJSONL, SourceCSV:
		if d.Each != "" {
			return errors.New("mapping: each is for source json or xml only")
		}
		if d.Source == SourceCSV {
			c, err := compileCSV(d.CSV)
			if err != nil {
				return fmt.Errorf("mapping: csv: %w", err)
			}
			m.csv = c
		}
	case SourceXML:
		sel, err := parseXMLSelector(d.Each)
		if err != nil {
			return fmt.Errorf("mapping: each: %w", err)
		}
		m.xmlSel = sel
	default:
		return fmt.Errorf("mapping: source %q, want json, jsonl, csv or xml", d.Source)
	}
	if len(d.Records) == 0 {
		return errors.New("mapping: records is empty")
	}
	if len(d.Records) > MaxRules {
		return fmt.Errorf("mapping: %d records rules, at most %d", len(d.Records), MaxRules)
	}
	for i, spec := range d.Records {
		r, err := compileRule(spec)
		if err != nil {
			return fmt.Errorf("mapping: records[%d]: %w", i, err)
		}
		m.rules = append(m.rules, r)
	}
	if err := m.compileIdentity(); err != nil {
		return err
	}
	m.refs = referencedPaths(d)
	return nil
}

// compileIdentity checks the declared identity: 1 to MaxIdentity distinct
// finding members, each set by every finding rule, and in no rule all set
// from constants (a constant identity would make every finding of the rule
// one finding). A constant fingerprint is refused for the same reason,
// with or without an identity.
func (m *Mapping) compileIdentity() error {
	d := m.doc
	findingRules := 0
	for i, spec := range d.Records {
		if spec.Kind != KindFinding {
			continue
		}
		findingRules++
		if fp, ok := spec.Set["fingerprint"]; ok && fp.isConstant() {
			return fmt.Errorf("mapping: records[%d]: a constant fingerprint makes every finding of the rule one finding", i)
		}
	}
	if len(d.Identity) == 0 {
		return nil
	}
	if len(d.Identity) > MaxIdentity {
		return fmt.Errorf("mapping: identity has %d members, at most %d", len(d.Identity), MaxIdentity)
	}
	if findingRules == 0 {
		return errors.New("mapping: identity needs a finding rule")
	}
	seen := map[string]bool{}
	for _, t := range d.Identity {
		if seen[t] {
			return fmt.Errorf("mapping: identity lists %q twice", t)
		}
		seen[t] = true
		segs := strings.Split(t, ".")
		if _, err := checkTarget(kindTypes[KindFinding], KindFinding, segs); err != nil {
			return fmt.Errorf("mapping: identity %q: %w", t, err)
		}
		m.ident = append(m.ident, segs)
	}
	for i, spec := range d.Records {
		if spec.Kind != KindFinding {
			continue
		}
		constant := true
		for _, t := range d.Identity {
			v, ok := spec.Set[t]
			if !ok {
				return fmt.Errorf("mapping: records[%d]: identity member %q is not set", i, t)
			}
			if !v.isConstant() {
				constant = false
			}
		}
		if constant {
			return fmt.Errorf("mapping: records[%d]: the identity is constant, so every finding of the rule would be one finding", i)
		}
	}
	return nil
}

// rule is a compiled RuleSpec.
type rule struct {
	kind string
	when []predicate
	sets []setter
}

type predicate struct {
	path   path
	exists *bool
	equals *string
	in     map[string]bool
	re     *regexp.Regexp
}

type setter struct {
	target []string
	value  value
	list   bool // the member is a list of strings
}

var kindTypes = map[string]reflect.Type{
	KindAsset:      reflect.TypeOf(ctis.Asset{}),
	KindFinding:    reflect.TypeOf(ctis.Finding{}),
	KindDependency: reflect.TypeOf(ctis.Dependency{}),
}

// Members a mapping may never set: identifiers and links the report
// builder owns, so a tool output cannot forge references between records.
var forbiddenTargets = map[string]map[string]bool{
	KindAsset:      {"id": true, "related_assets": true},
	KindFinding:    {"id": true, "asset_ref": true, "related_locations": true, "stacks": true, "attachments": true, "data_flow": true},
	KindDependency: {"id": true, "depends_on": true},
}

// Members a rule must set.
var requiredTargets = map[string][]string{
	KindAsset:      {"type", "value"},
	KindFinding:    {"title", "severity"},
	KindDependency: {"name"},
}

var targetSegRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,63}$`)

func compileRule(spec RuleSpec) (rule, error) {
	r := rule{kind: spec.Kind}
	root, ok := kindTypes[spec.Kind]
	if !ok {
		return r, fmt.Errorf("kind %q, want asset, finding or dependency", spec.Kind)
	}
	if len(spec.When) > MaxPredicates {
		return r, fmt.Errorf("when: %d predicates, at most %d", len(spec.When), MaxPredicates)
	}
	for j, p := range spec.When {
		cp, err := compilePredicate(p)
		if err != nil {
			return r, fmt.Errorf("when[%d]: %w", j, err)
		}
		r.when = append(r.when, cp)
	}
	if len(spec.Set) == 0 {
		return r, errors.New("set is empty")
	}
	if len(spec.Set) > MaxSetsPerRule {
		return r, fmt.Errorf("set: %d members, at most %d", len(spec.Set), MaxSetsPerRule)
	}
	targets := sortedKeys(spec.Set)
	for _, t := range targets {
		segs := strings.Split(t, ".")
		list, err := checkTarget(root, spec.Kind, segs)
		if err != nil {
			return r, fmt.Errorf("set %q: %w", t, err)
		}
		v, err := compileValue(spec.Set[t])
		if err != nil {
			return r, fmt.Errorf("set %q: %w", t, err)
		}
		r.sets = append(r.sets, setter{target: segs, value: v, list: list})
	}
	// One member set twice through a prefix ("location" and
	// "location.path") is ambiguous.
	for i := 0; i < len(targets); i++ {
		for j := i + 1; j < len(targets); j++ {
			if strings.HasPrefix(targets[j], targets[i]+".") {
				return r, fmt.Errorf("set %q and %q overlap", targets[i], targets[j])
			}
		}
	}
	for _, req := range requiredTargets[spec.Kind] {
		if _, ok := spec.Set[req]; !ok {
			return r, fmt.Errorf("a %s rule must set %q", spec.Kind, req)
		}
	}
	if spec.Kind == KindAsset {
		if c, ok := spec.Set["type"].Const.(string); ok && spec.Set["type"].Path == "" && spec.Set["type"].Template == "" {
			if !ctis.AssetType(c).IsValid() {
				return r, fmt.Errorf("set \"type\": %q is not a CTIS asset type", c)
			}
		}
	}
	return r, nil
}

// checkTarget resolves a dotted target against the CTIS Go type by JSON
// member names. It does not descend into lists; a free-form map (properties,
// details, source_extra) takes exactly one key level below it.
func checkTarget(t reflect.Type, kind string, segs []string) (list bool, err error) {
	if len(segs) == 0 {
		return false, errors.New("empty target")
	}
	for _, s := range segs {
		if !targetSegRE.MatchString(s) {
			return false, fmt.Errorf("segment %q", s)
		}
	}
	if forbiddenTargets[kind][segs[0]] {
		return false, fmt.Errorf("%q is set by the report builder, not by a mapping", segs[0])
	}
	for i, s := range segs {
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct {
			return false, fmt.Errorf("%q is below a %s", s, t.Kind())
		}
		f, ok := jsonField(t, s)
		if !ok {
			return false, fmt.Errorf("%s has no member %q", t.Name(), s)
		}
		t = f
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		if t.Kind() == reflect.Map {
			if t.Key().Kind() != reflect.String {
				return false, fmt.Errorf("%q is not settable", s)
			}
			if len(segs) != i+2 {
				return false, fmt.Errorf("%q takes exactly one key below it", s)
			}
			return false, nil
		}
	}
	switch t.Kind() {
	case reflect.Struct:
		// A whole object (location, network) is set member by member.
		if t.String() != "time.Time" {
			return false, errors.New("set the members of an object, not the object")
		}
	case reflect.Slice:
		el := t.Elem()
		if el.Kind() != reflect.String {
			return false, errors.New("only lists of strings can be set")
		}
		return true, nil
	}
	return false, nil
}

func jsonField(t reflect.Type, name string) (reflect.Type, bool) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if tag == name && tag != "-" {
			return f.Type, true
		}
	}
	return nil, false
}

func compilePredicate(p Predicate) (predicate, error) {
	cp := predicate{}
	path, err := parsePath(p.Path)
	if err != nil {
		return cp, fmt.Errorf("path: %w", err)
	}
	cp.path = path
	ops := 0
	if p.Exists != nil {
		ops++
		cp.exists = p.Exists
	}
	if p.Equals != nil {
		ops++
		s, ok := scalarString(p.Equals)
		if !ok {
			return cp, errors.New("equals takes a string, number or boolean")
		}
		cp.equals = &s
	}
	if p.In != nil {
		ops++
		if len(p.In) == 0 || len(p.In) > MaxInValues {
			return cp, fmt.Errorf("in takes 1 to %d values", MaxInValues)
		}
		cp.in = map[string]bool{}
		for _, v := range p.In {
			s, ok := scalarString(v)
			if !ok {
				return cp, errors.New("in takes strings, numbers or booleans")
			}
			cp.in[s] = true
		}
	}
	if p.Matches != "" {
		ops++
		if len(p.Matches) > MaxRegexLen {
			return cp, fmt.Errorf("matches is longer than %d bytes", MaxRegexLen)
		}
		re, err := regexp.Compile(p.Matches)
		if err != nil {
			return cp, fmt.Errorf("matches: %w", err)
		}
		cp.re = re
	}
	if ops != 1 {
		return cp, errors.New("a predicate takes exactly one of exists, equals, in, matches")
	}
	return cp, nil
}

func scalarString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case json.Number:
		return x.String(), true
	case bool:
		if x {
			return "true", true
		}
		return "false", true
	}
	return "", false
}
