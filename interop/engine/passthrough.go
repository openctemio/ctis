package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/openctemio/ctis/v2"
)

// Passthrough
//
// Every member of a source document that its mapping does not list is kept,
// as data, under extensions["<namespace>"] of the CTIS report (members
// outside any record) or of the record it belongs to:
//
//	{"version": "<upstream version>", "unmapped": {"<JSON pointer>": <value>}}
//
// The pointer is absolute for the report and relative to the record object
// for a record. A member below an ignored field is never kept. The kept
// values are bounded (Limits) and scrubbed before they are stored:
//
//   - a member whose name says it holds a credential (password, secret,
//     token, api key, authorization, cookie, private key, environment
//     variables, command line) is dropped, at any depth;
//   - a URL-like member (name ending in uri, url or href) whose value names
//     a scheme other than http or https is dropped;
//   - every string goes through ctis.RedactCodeSecrets, and the adapter
//     masks a secret finding's raw match in its record's values.
//
// A kept value is never interpreted and never placed into a core member.
// The reverse adapter writes it back with Reemit, only where the output has
// no member yet and the export mapping does not own the place.

// Limits bound the passthrough of one document.
type Limits struct {
	// Members kept per object (the report or one record).
	MaxEntries int `json:"max_entries,omitempty"`
	// Encoded bytes kept per object.
	MaxBytes int `json:"max_bytes,omitempty"`
	// Nesting depth inside one kept value.
	MaxDepth int `json:"max_depth,omitempty"`
	// Records that keep members.
	MaxRecords int `json:"max_records,omitempty"`
	// Encoded bytes kept for the whole document.
	MaxTotalBytes int `json:"max_total_bytes,omitempty"`
}

// DefaultLimits are the passthrough limits of a mapping without its own;
// HardLimits are the most a mapping can set. MaxBytes stays well below
// ctis.MaxExtensionsBytes, which bounds all namespaces of an object, and
// MaxDepth leaves room for ctis.RedactSecretFinding, which walks a finding
// to a depth of 32, to reach every kept string.
var (
	DefaultLimits = Limits{MaxEntries: 64, MaxBytes: 16 << 10, MaxDepth: 12, MaxRecords: 10000, MaxTotalBytes: 8 << 20}
	HardLimits    = Limits{MaxEntries: 256, MaxBytes: 32 << 10, MaxDepth: 16, MaxRecords: 100000, MaxTotalBytes: 32 << 20}
)

func (l *Limits) check() error {
	for _, c := range []struct {
		name     string
		v, hardV int
	}{
		{"max_entries", l.MaxEntries, HardLimits.MaxEntries},
		{"max_bytes", l.MaxBytes, HardLimits.MaxBytes},
		{"max_depth", l.MaxDepth, HardLimits.MaxDepth},
		{"max_records", l.MaxRecords, HardLimits.MaxRecords},
		{"max_total_bytes", l.MaxTotalBytes, HardLimits.MaxTotalBytes},
	} {
		if c.v < 0 || c.v > c.hardV {
			return fmt.Errorf("%s %d is outside 0-%d", c.name, c.v, c.hardV)
		}
	}
	return nil
}

// limits are the mapping's limits with the defaults filled in.
func (m *Mapping) limits() Limits {
	l := DefaultLimits
	if p := m.Passthrough; p != nil {
		if p.MaxEntries > 0 {
			l.MaxEntries = p.MaxEntries
		}
		if p.MaxBytes > 0 {
			l.MaxBytes = p.MaxBytes
		}
		if p.MaxDepth > 0 {
			l.MaxDepth = p.MaxDepth
		}
		if p.MaxRecords > 0 {
			l.MaxRecords = p.MaxRecords
		}
		if p.MaxTotalBytes > 0 {
			l.MaxTotalBytes = p.MaxTotalBytes
		}
	}
	return l
}

// Unmapped holds the kept members of one object.
type Unmapped struct {
	Entries   map[string]json.RawMessage
	Truncated bool
	bytes     int
}

// Passthrough is what Collect kept of one document.
type Passthrough struct {
	m       *Mapping
	lim     Limits
	Doc     Unmapped
	records map[string]*recordData
	// Dropped counts members left out by a limit or by the scrub rules.
	Dropped int
	total   int
	// version is the document's declared version (VersionPointer), else
	// the mapping's.
	version string
}

// Version is the upstream version the kept members belong to: the version
// the document declares (Mapping.VersionPointer), else the mapping's.
func (p *Passthrough) Version() string { return p.version }

type recordData struct {
	name string
	Unmapped
	sets map[int]json.RawMessage
}

// sensitiveName reports a member name that says it holds a credential.
var sensitiveName = regexp.MustCompile(`(?i)(passw|passwd|pwd$|secret|token|api[-_]?key|authori[sz]ation|cookie|credential|private[-_]?key|^env$|environment[-_]?variables|command[-_]?line|^arguments$)`)

// urlName reports a member name of a URL.
var urlName = regexp.MustCompile(`(?i)(uri|url|href)$`)

// schemeRE matches a URI scheme (RFC 3986 section 3.1).
var schemeRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)

// badURL reports a URL member value that names a scheme other than http or
// https. A relative reference (no scheme) is kept.
func badURL(name, v string) bool {
	if !urlName.MatchString(name) {
		return false
	}
	s := strings.TrimSpace(v)
	if !schemeRE.MatchString(s) {
		return false
	}
	scheme := strings.ToLower(s[:strings.IndexByte(s, ':')])
	return scheme != "http" && scheme != "https"
}

// ErrPassthrough is returned for an input the passthrough cannot walk.
var ErrPassthrough = errors.New("engine: passthrough")

type class struct {
	listed  bool // a field matches the path
	ignored bool // ... and drops it
	below   bool // a field matches a path below
	sets    []int
	record  int // index into m.Records + 1, 0 for none
}

// Collect walks a JSON document once and keeps every member its import
// mapping does not list, and the values of the set rules. It never fails on
// content it cannot keep (it drops it and counts it); it fails only on input
// that is not JSON or is nested deeper than 256.
func (m *Mapping) Collect(data []byte) (*Passthrough, error) {
	p := &Passthrough{m: m, lim: m.limits(), Doc: Unmapped{Entries: map[string]json.RawMessage{}}, records: map[string]*recordData{}, version: m.Version}
	if m.VersionPointer != "" {
		vals, err := lookupScalars(data, []string{m.VersionPointer})
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPassthrough, err)
		}
		if v := vals[m.VersionPointer]; v != nil && versionRE.MatchString(*v) {
			p.version = *v
		}
	}
	cache := map[string]class{}
	classify := func(path string) class {
		path = m.FoldPath(path)
		if c, ok := cache[path]; ok {
			return c
		}
		var c class
		for i, f := range m.Fields {
			if MatchPath(f.Path, path) {
				if !c.listed {
					c.listed = true
					c.ignored = f.Ignored != ""
				}
				if f.Set != "" {
					c.sets = append(c.sets, i)
				}
			} else if !c.below && matchBelow(f.Path, path) {
				c.below = true
			}
		}
		for i, r := range m.Records {
			if MatchPath(r.Path, path) {
				c.record = i + 1
				break
			}
		}
		if len(cache) < 8192 {
			cache[path] = c
		}
		return c
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var stack []walkFrame
	for {
		prevEnd := dec.InputOffset()
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPassthrough, err)
		}
		n := len(stack)
		if s, ok := tok.(string); ok && n > 0 && stack[n-1].object && stack[n-1].expectKey {
			stack[n-1].key, stack[n-1].expectKey = s, false
			continue
		}
		if dl, ok := tok.(json.Delim); ok && (dl == '}' || dl == ']') {
			stack = stack[:n-1]
			if m := len(stack); m > 0 {
				stack[m-1].afterValue()
			}
			continue
		}
		// A value: its pointer and path.
		var ptr, path, record, name string
		if n > 0 {
			top := &stack[n-1]
			record = top.record
			if top.object {
				name = top.key
				ptr = top.ptr + "/" + escapeToken(top.key)
				path = top.path + "/" + PathKey(top.key)
			} else {
				ptr = top.ptr + "/" + fmt.Sprint(top.index)
				path = top.path + "[]"
				if top.path == "" {
					path = "/[]"
				}
			}
		}
		var c class
		if n > 0 {
			c = classify(path)
		}
		if c.record > 0 && record == "" {
			record = ptr
		}
		delim, isDelim := tok.(json.Delim)
		switch {
		case n == 0:
			// The document itself.
		case c.listed && c.ignored:
			if err := skip(dec, isDelim); err != nil {
				return nil, err
			}
			stack[n-1].afterValue()
			continue
		case c.listed || c.below:
			if len(c.sets) > 0 && !isDelim && record != "" {
				raw, _ := json.Marshal(tok)
				p.recordData(record, m.Records).setValues(c.sets, raw)
			}
		default:
			// Not listed and nothing listed below: keep the whole value.
			start := valueStart(data, prevEnd)
			if err := skip(dec, isDelim); err != nil {
				return nil, err
			}
			raw := data[start:dec.InputOffset()]
			if record != "" {
				rd := p.recordData(record, m.Records)
				if rd == nil {
					p.Dropped++
				} else {
					p.keep(&rd.Unmapped, strings.TrimPrefix(ptr, record), name, raw)
				}
			} else {
				p.keep(&p.Doc, ptr, name, raw)
			}
			stack[n-1].afterValue()
			continue
		}
		if isDelim {
			if n+1 > 256 {
				return nil, fmt.Errorf("%w: values nested deeper than 256", ErrPassthrough)
			}
			stack = append(stack, walkFrame{object: delim == '{', expectKey: delim == '{', ptr: ptr, path: path, record: record})
			continue
		}
		if n > 0 {
			stack[n-1].afterValue()
		}
	}
	if len(stack) > 0 {
		return nil, fmt.Errorf("%w: unexpected end of input", ErrPassthrough)
	}
	return p, nil
}

// recordData returns the data of the record at ptr, nil past MaxRecords.
func (p *Passthrough) recordData(ptr string, records []Record) *recordData {
	if rd, ok := p.records[ptr]; ok {
		return rd
	}
	if len(p.records) >= p.lim.MaxRecords {
		return nil
	}
	rd := &recordData{Unmapped: Unmapped{Entries: map[string]json.RawMessage{}}, sets: map[int]json.RawMessage{}}
	p.records[ptr] = rd
	return rd
}

func (rd *recordData) setValues(fields []int, raw json.RawMessage) {
	if rd == nil {
		return
	}
	for _, i := range fields {
		rd.sets[i] = raw
	}
}

// keep scrubs and stores one member.
func (p *Passthrough) keep(u *Unmapped, ptr, name string, raw []byte) {
	// A member the scrub rules drop is left out silently (it is never
	// kept, whatever the limits); a member over a limit marks the object
	// truncated.
	if sensitiveName.MatchString(name) {
		p.Dropped++
		return
	}
	if len(raw) > p.lim.MaxBytes || len(u.Entries) >= p.lim.MaxEntries {
		p.Dropped++
		u.Truncated = true
		return
	}
	v, ok := scrubRaw(raw, name, p.lim.MaxDepth, nil)
	if !ok {
		p.Dropped++
		if tooDeepRaw(raw, p.lim.MaxDepth) {
			u.Truncated = true
		}
		return
	}
	size := len(ptr) + len(v) + 6
	if u.bytes+size > p.lim.MaxBytes || p.total+size > p.lim.MaxTotalBytes {
		p.Dropped++
		u.Truncated = true
		return
	}
	u.Entries[ptr] = v
	u.bytes += size
	p.total += size
}

// scrubRaw decodes a kept value, drops sensitive and bad URL members at any
// depth, masks credentials in strings (and, with scrub, the caller's own
// values), and encodes it again. ok is false for a value deeper than
// maxDepth, or one that is wholly dropped.
func scrubRaw(raw []byte, name string, maxDepth int, scrub func(string) string) (json.RawMessage, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	v, ok := scrubValue(v, name, 0, maxDepth, scrub)
	if !ok {
		return nil, false
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, false
	}
	return json.RawMessage(bytes.TrimRight(buf.Bytes(), "\n")), true
}

func scrubValue(v any, name string, depth, maxDepth int, scrub func(string) string) (any, bool) {
	if tooDeep(v, depth, maxDepth) {
		return nil, false
	}
	return scrubKept(v, name, scrub)
}

// tooDeep reports a value nested deeper than maxDepth.
func tooDeep(v any, depth, maxDepth int) bool {
	if depth > maxDepth {
		return true
	}
	switch t := v.(type) {
	case map[string]any:
		for _, c := range t {
			if tooDeep(c, depth+1, maxDepth) {
				return true
			}
		}
	case []any:
		for _, c := range t {
			if tooDeep(c, depth+1, maxDepth) {
				return true
			}
		}
	}
	return false
}

// scrubKept drops sensitive members and bad URLs and masks strings; ok is
// false when the value itself is dropped.
func scrubKept(v any, name string, scrub func(string) string) (any, bool) {
	switch t := v.(type) {
	case map[string]any:
		for k, c := range t {
			if sensitiveName.MatchString(k) {
				delete(t, k)
				continue
			}
			nc, ok := scrubKept(c, k, scrub)
			if !ok {
				delete(t, k)
				continue
			}
			t[k] = nc
		}
		return t, true
	case []any:
		out := t[:0]
		for _, c := range t {
			if nc, ok := scrubKept(c, name, scrub); ok {
				out = append(out, nc)
			}
		}
		return out, true
	case string:
		if badURL(name, t) {
			return nil, false
		}
		s := ctis.RedactCodeSecrets(t)
		if scrub != nil {
			s = scrub(s)
		}
		return s, true
	}
	return v, true
}

// walkFrame is an open object or array of Collect's walk.
type walkFrame struct {
	object    bool
	expectKey bool
	key       string
	index     int
	ptr, path string
	record    string // pointer of the enclosing record
}

// afterValue moves past one member or element.
func (f *walkFrame) afterValue() {
	if f.object {
		f.expectKey = true
	} else {
		f.index++
	}
}

// valueStart skips the separators before a value.
func valueStart(data []byte, off int64) int64 {
	for off < int64(len(data)) {
		switch data[off] {
		case ' ', '\t', '\r', '\n', ',', ':':
			off++
			continue
		}
		break
	}
	return off
}

// skip consumes the rest of a value whose first token was read.
func skip(dec *json.Decoder, opened bool) error {
	if !opened {
		return nil
	}
	depth := 1
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrPassthrough, err)
		}
		if dl, ok := tok.(json.Delim); ok {
			if dl == '{' || dl == '[' {
				depth++
			} else {
				depth--
			}
		}
	}
	return nil
}

// Empty reports whether nothing was kept.
func (p *Passthrough) Empty() bool {
	if len(p.Doc.Entries) > 0 || p.Doc.Truncated {
		return false
	}
	for _, rd := range p.records {
		if len(rd.Entries) > 0 || rd.Truncated {
			return false
		}
	}
	return true
}

// DocExtension is the extension value of the members outside the records,
// nil when there are none.
func (p *Passthrough) DocExtension() map[string]any {
	return p.extension(&p.Doc, nil)
}

// RecordExtension is the extension value of the record at ptr (the record
// object's pointer), nil when it kept nothing. scrub, when set, is applied
// to every kept string: an adapter masks a secret finding's raw match with
// it.
func (p *Passthrough) RecordExtension(ptr string, scrub func(string) string) map[string]any {
	rd, ok := p.records[ptr]
	if !ok {
		return nil
	}
	return p.extension(&rd.Unmapped, scrub)
}

func (p *Passthrough) extension(u *Unmapped, scrub func(string) string) map[string]any {
	if len(u.Entries) == 0 && !u.Truncated {
		return nil
	}
	entries := make(map[string]any, len(u.Entries))
	for k, raw := range u.Entries {
		if scrub != nil {
			nv, ok := scrubRaw(raw, lastToken(k), p.lim.MaxDepth, scrub)
			if !ok {
				continue
			}
			raw = nv
		}
		// Decoded, so ctis.RedactSecretFinding reaches the strings of a
		// record's kept members like any other member of the finding.
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var v any
		if dec.Decode(&v) != nil {
			continue
		}
		entries[k] = v
	}
	ext := map[string]any{"version": p.version, "unmapped": entries}
	if u.Truncated {
		ext["truncated"] = true
	}
	return ext
}

// Apply writes the values of the set rules of the record at ptr into
// target, a pointer to the record's CTIS type (*ctis.Finding for a finding
// record). A value a transform rejects, or that does not convert to the
// member's type, leaves the member as it was.
func (p *Passthrough) Apply(ptr string, target any) error {
	rd, ok := p.records[ptr]
	if !ok || len(rd.sets) == 0 {
		return nil
	}
	v := reflect.ValueOf(target)
	if v.Kind() != reflect.Pointer || v.IsNil() || v.Elem().Kind() != reflect.Struct {
		return ErrSetTarget
	}
	idx := make([]int, 0, len(rd.sets))
	for i := range rd.sets {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	for _, i := range idx {
		f := p.m.Fields[i]
		r := p.m.record(f.Record)
		if kindTypes[r.Kind] != v.Elem().Type() {
			return ErrSetTarget
		}
		s, ok := scalarText(rd.sets[i])
		if !ok {
			continue
		}
		if s, ok = p.m.apply(f, s); !ok {
			continue
		}
		setMember(v.Elem(), f.Set, s)
	}
	return nil
}

func (m *Mapping) record(name string) Record {
	for _, r := range m.Records {
		if r.Name == name {
			return r
		}
	}
	return Record{}
}

func lastToken(ptr string) string {
	i := strings.LastIndexByte(ptr, '/')
	return strings.ReplaceAll(strings.ReplaceAll(ptr[i+1:], "~1", "/"), "~0", "~")
}

// Store sets the extension value under the mapping's namespace; a nil value
// stores nothing.
func (m *Mapping) Store(ext *ctis.Extensions, value map[string]any) {
	if value == nil {
		return
	}
	for k, v := range value {
		ext.Set(m.Namespace, k, v)
	}
}

// PointerPath turns a pointer into the path the field patterns match:
// array indexes become "[]" on the previous segment.
func PointerPath(ptr string) (string, bool) {
	toks, ok := parsePointer(ptr)
	if !ok {
		return "", false
	}
	var b strings.Builder
	for i, t := range toks {
		if _, idx := isIndex(t); idx && i > 0 {
			b.WriteString("[]")
			continue
		}
		if _, idx := isIndex(t); idx && i == 0 {
			b.WriteString("/[]")
			continue
		}
		b.WriteString("/")
		b.WriteString(PathKey(t))
	}
	return b.String(), true
}

func tooDeepRaw(raw []byte, maxDepth int) bool {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	return tooDeep(v, 0, maxDepth)
}
