package importer

import (
	"fmt"
	"sort"
	"strings"
)

// Spec is the mapping spec of one format: every source field the importer
// knows, and what becomes of it.
type Spec struct {
	Format Format
	// Human name of the source format and the versions the spec was written
	// against.
	Title         string
	SourceVersion string
	// Notes on normalization rules that are not per field (severity tables,
	// status tables, asset identity, deduplication).
	Rules []string
	// The fields, in document order.
	Fields []Field
}

// Field is one row of a mapping spec.
//
// Path is the field's path in the source: XML as "/Root/Child/@attr"
// (elements keyed by an attribute as "tag[name]"), JSON as "/member/array[]/
// member". A "*" matches any run of characters inside one path segment; a
// trailing "/**" matches everything below.
//
// Exactly one of Target and Ignored is set: Target names the CTIS member or
// members the value goes to; Ignored says why the value is deliberately not
// kept. A container element whose children are listed has Target
// "(container)".
type Field struct {
	Path    string
	Target  string
	Ignored string
}

// Container is the Target of a field that only groups other fields.
const Container = "(container)"

// Mapped reports whether the field's value is kept.
func (f Field) Mapped() bool { return f.Target != "" && f.Target != Container }

// Match returns the first field whose path matches p.
func (s Spec) Match(p string) (Field, bool) {
	for _, f := range s.Fields {
		if pathMatch(f.Path, p) {
			return f, true
		}
	}
	return Field{}, false
}

// Unmapped returns the paths of observed that no field of s matches.
func (s Spec) Unmapped(observed []string) []string {
	var out []string
	for _, p := range observed {
		if _, ok := s.Match(p); !ok {
			out = append(out, p)
		}
	}
	return out
}

// Coverage is the share of a spec's fields that are kept.
type Coverage struct {
	Mapped  int
	Ignored int
}

// Percent is Mapped as a share of Mapped plus Ignored.
func (c Coverage) Percent() float64 {
	total := c.Mapped + c.Ignored
	if total == 0 {
		return 0
	}
	return 100 * float64(c.Mapped) / float64(total)
}

// Coverage counts the spec's mapped and ignored fields (containers are not
// counted).
func (s Spec) Coverage() Coverage {
	var c Coverage
	for _, f := range s.Fields {
		switch {
		case f.Target == Container:
		case f.Mapped():
			c.Mapped++
		default:
			c.Ignored++
		}
	}
	return c
}

// check returns the problems of the spec itself: a field with neither or
// both of Target and Ignored, a duplicate path, an empty path.
func (s Spec) check() []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range s.Fields {
		switch {
		case f.Path == "" || !strings.HasPrefix(f.Path, "/"):
			out = append(out, fmt.Sprintf("field %q: path must start with /", f.Path))
		case (f.Target == "") == (f.Ignored == ""):
			out = append(out, fmt.Sprintf("field %s: set exactly one of Target and Ignored", f.Path))
		case seen[f.Path]:
			out = append(out, fmt.Sprintf("field %s: listed twice", f.Path))
		}
		seen[f.Path] = true
	}
	return out
}

// Markdown renders the spec as a document.
func (s Spec) Markdown() string {
	var b strings.Builder
	c := s.Coverage()
	fmt.Fprintf(&b, "# %s mapping\n\n", s.Title)
	fmt.Fprintf(&b, "Generated from `importer/spec_%s.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.\n\n", s.Format)
	fmt.Fprintf(&b, "- Format: `%s`\n", s.Format)
	fmt.Fprintf(&b, "- Source versions: %s\n", s.SourceVersion)
	fmt.Fprintf(&b, "- Fields: %d mapped, %d ignored on purpose (%.0f%% mapped)\n\n", c.Mapped, c.Ignored, c.Percent())
	if len(s.Rules) > 0 {
		b.WriteString("## Rules\n\n")
		for _, r := range s.Rules {
			fmt.Fprintf(&b, "- %s\n", r)
		}
		b.WriteString("\n")
	}
	b.WriteString("## Fields\n\n| Source field | CTIS | Ignored because |\n|---|---|---|\n")
	for _, f := range s.Fields {
		target := ""
		if f.Target != "" {
			target = "`" + f.Target + "`"
			if f.Target == Container {
				target = "(container)"
			}
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", mdEscape(f.Path), mdEscape(target), mdEscape(f.Ignored))
	}
	return b.String()
}

func mdEscape(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

// Specs returns the mapping spec of every format Parse reads (plus the
// Qualys KnowledgeBase), sorted by format.
func Specs() []Spec {
	out := make([]Spec, 0, len(specs))
	for _, s := range specs {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Format < out[j].Format })
	return out
}

// SpecFor returns the mapping spec of a format.
func SpecFor(f Format) (Spec, bool) {
	s, ok := specs[f]
	return s, ok
}

// specs is filled by the spec_<format>.go files.
var specs = map[Format]Spec{}

func registerSpec(s Spec) Spec {
	specs[s.Format] = s
	return s
}

// pathMatch matches a path against a pattern of the Field.Path syntax.
func pathMatch(pattern, p string) bool {
	if pattern == p {
		return true
	}
	if rest, ok := strings.CutSuffix(pattern, "/**"); ok {
		if pathMatch(rest, p) {
			return true
		}
		ps := strings.Split(p, "/")
		rs := strings.Split(rest, "/")
		if len(ps) <= len(rs) {
			return false
		}
		return segmentsMatch(rs, ps[:len(rs)])
	}
	return segmentsMatch(strings.Split(pattern, "/"), strings.Split(p, "/"))
}

func segmentsMatch(pat, segs []string) bool {
	if len(pat) != len(segs) {
		return false
	}
	for i := range pat {
		if !wildcard(pat[i], segs[i]) {
			return false
		}
	}
	return true
}

// wildcard matches s against a pattern where "*" is any run of characters.
func wildcard(pattern, s string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for i := 1; i < len(parts)-1; i++ {
		j := strings.Index(s, parts[i])
		if j < 0 {
			return false
		}
		s = s[j+len(parts[i]):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}
