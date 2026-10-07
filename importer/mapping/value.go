package mapping

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxSplitItems = 1000
	maxValueBytes = 1 << 20
)

// value is a compiled ValueSpec.
type value struct {
	src      path
	isConst  bool
	constant any
	tmpl     []tmplPart
	vars     map[string]path
	def      any
	hasDef   bool
	first    bool
	trim     bool
	lower    bool
	upper    bool
	split    string
	table    map[string]string
	join     *string
	as       string
	maxBytes int
}

type tmplPart struct {
	lit string
	v   string // variable name; empty for a literal
}

var varNameRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,31}$`)

func compileValue(s ValueSpec) (value, error) {
	v := value{
		first: s.First, trim: s.Trim, lower: s.Lower, upper: s.Upper,
		split: s.Split, join: s.Join, as: s.As, maxBytes: s.MaxBytes,
	}
	sources := 0
	if s.Path != "" || s.bare {
		sources++
		p, err := parsePath(s.Path)
		if err != nil {
			return v, err
		}
		v.src = p
	}
	if s.Const != nil {
		sources++
		if !scalarOrStrings(s.Const) {
			return v, errors.New("const takes a string, number, boolean or list of strings")
		}
		v.isConst, v.constant = true, s.Const
	}
	if s.Template != "" {
		sources++
		parts, err := compileTemplate(s.Template, s.Vars)
		if err != nil {
			return v, err
		}
		v.tmpl = parts
		v.vars = map[string]path{}
		for name, raw := range s.Vars {
			p, err := parsePath(raw)
			if err != nil {
				return v, fmt.Errorf("vars.%s: %w", name, err)
			}
			v.vars[name] = p
		}
	} else if len(s.Vars) > 0 {
		return v, errors.New("vars without a template")
	}
	if sources != 1 {
		return v, errors.New("a value takes exactly one of path, const, template")
	}
	if s.Default != nil {
		if !scalarOrStrings(s.Default) {
			return v, errors.New("default takes a string, number, boolean or list of strings")
		}
		v.def, v.hasDef = s.Default, true
	}
	if s.Lower && s.Upper {
		return v, errors.New("lower and upper together")
	}
	switch s.As {
	case "", "integer", "boolean", "string":
	default:
		return v, fmt.Errorf("as %q, want integer, boolean or string", s.As)
	}
	if s.MaxBytes < 0 || s.MaxBytes > maxValueBytes {
		return v, fmt.Errorf("max_bytes outside 1..%d", maxValueBytes)
	}
	if len(s.Split) > 16 || (s.Join != nil && len(*s.Join) > 16) {
		return v, errors.New("split and join separators are at most 16 bytes")
	}
	if len(s.Map) > MaxMapEntries {
		return v, fmt.Errorf("map has more than %d entries", MaxMapEntries)
	}
	if len(s.Map) > 0 {
		v.table = s.Map
	}
	return v, nil
}

func scalarOrStrings(v any) bool {
	if _, ok := scalarString(v); ok {
		return true
	}
	list, ok := v.([]any)
	if !ok || len(list) > maxSplitItems {
		return false
	}
	for _, it := range list {
		if _, ok := it.(string); !ok {
			return false
		}
	}
	return true
}

// compileTemplate splits "{host}:{port}" into literals and named
// variables. Every variable is declared in vars and every declared variable
// is used; a brace that is not part of a variable is an error.
func compileTemplate(t string, vars map[string]string) ([]tmplPart, error) {
	if len(t) > MaxTemplateBytes {
		return nil, fmt.Errorf("template longer than %d bytes", MaxTemplateBytes)
	}
	var parts []tmplPart
	used := map[string]bool{}
	rest := t
	for rest != "" {
		open := strings.IndexByte(rest, '{')
		closeAt := strings.IndexByte(rest, '}')
		if open < 0 {
			if closeAt >= 0 {
				return nil, errors.New("template: } without {")
			}
			parts = append(parts, tmplPart{lit: rest})
			break
		}
		if closeAt >= 0 && closeAt < open {
			return nil, errors.New("template: } without {")
		}
		if open > 0 {
			parts = append(parts, tmplPart{lit: rest[:open]})
		}
		end := strings.IndexByte(rest[open:], '}')
		if end < 0 {
			return nil, errors.New("template: { without }")
		}
		name := rest[open+1 : open+end]
		if !varNameRE.MatchString(name) {
			return nil, fmt.Errorf("template: variable name %q", name)
		}
		if _, ok := vars[name]; !ok {
			return nil, fmt.Errorf("template: variable %q is not in vars", name)
		}
		used[name] = true
		parts = append(parts, tmplPart{v: name})
		rest = rest[open+end+1:]
	}
	for name := range vars {
		if !used[name] {
			return nil, fmt.Errorf("vars.%s is not used by the template", name)
		}
	}
	return parts, nil
}

// eval computes the value for one input record. ok is false when the value
// is missing (and has no default): the member is then not set.
func (v value) eval(rec any) (any, bool) {
	out, ok := v.raw(rec)
	if ok {
		out, ok = v.transform(out)
	}
	if !ok || empty(out) {
		if v.hasDef {
			return v.def, true
		}
		return nil, false
	}
	return out, true
}

func (v value) raw(rec any) (any, bool) {
	switch {
	case v.isConst:
		return v.constant, true
	case v.tmpl != nil:
		var b strings.Builder
		for _, p := range v.tmpl {
			if p.v == "" {
				b.WriteString(p.lit)
				continue
			}
			x, ok := v.vars[p.v].get(rec)
			if !ok {
				return nil, false
			}
			s, ok := scalarString(x)
			if !ok || s == "" {
				return nil, false
			}
			b.WriteString(s)
		}
		return b.String(), true
	}
	return v.src.get(rec)
}

func (v value) transform(x any) (any, bool) {
	if v.first {
		list, ok := x.([]any)
		if !ok {
			return x, true // a single value is its own first element
		}
		if len(list) == 0 {
			return nil, false
		}
		x = list[0]
	}
	x = mapStrings(x, func(s string) (string, bool) {
		if v.trim {
			s = strings.TrimSpace(s)
		}
		if v.lower {
			s = strings.ToLower(s)
		}
		if v.upper {
			s = strings.ToUpper(s)
		}
		return s, true
	})
	if v.split != "" {
		s, ok := x.(string)
		if ok {
			var items []any
			for _, it := range strings.Split(s, v.split) {
				if it = strings.TrimSpace(it); it != "" && len(items) < maxSplitItems {
					items = append(items, it)
				}
			}
			x = items
		}
	}
	if v.table != nil {
		x = mapStrings(x, func(s string) (string, bool) {
			m, ok := v.table[s]
			return m, ok
		})
		if x == nil {
			return nil, false
		}
	}
	if v.join != nil {
		if list, ok := x.([]any); ok {
			parts := make([]string, 0, len(list))
			for _, it := range list {
				if s, ok := scalarString(it); ok && s != "" {
					parts = append(parts, s)
				}
			}
			x = strings.Join(parts, *v.join)
		}
	}
	switch v.as {
	case "integer":
		n, ok := toInteger(x)
		if !ok {
			return nil, false
		}
		x = json.Number(strconv.FormatInt(n, 10))
	case "boolean":
		s, ok := scalarString(x)
		if !ok {
			return nil, false
		}
		b, err := strconv.ParseBool(strings.TrimSpace(s))
		if err != nil {
			return nil, false
		}
		x = b
	case "string":
		s, ok := scalarString(x)
		if !ok {
			return nil, false
		}
		x = s
	}
	if v.maxBytes > 0 {
		x = mapStrings(x, func(s string) (string, bool) { return truncate(s, v.maxBytes), true })
	}
	return x, true
}

// mapStrings applies f to a string or to every string of a list. An
// element f drops is removed from a list; a dropped single string is nil.
func mapStrings(x any, f func(string) (string, bool)) any {
	switch t := x.(type) {
	case string:
		s, ok := f(t)
		if !ok {
			return nil
		}
		return s
	case []any:
		out := make([]any, 0, len(t))
		for _, it := range t {
			if s, isStr := it.(string); isStr {
				if m, ok := f(s); ok {
					out = append(out, m)
				}
				continue
			}
			out = append(out, it)
		}
		return out
	}
	return x
}

// Integers a mapping may produce: the range a JSON number keeps exactly.
const maxSafeInteger = 1<<53 - 1

func toInteger(x any) (int64, bool) {
	s, ok := scalarString(x)
	if !ok {
		return 0, false
	}
	s = strings.TrimSpace(s)
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, n >= -maxSafeInteger && n <= maxSafeInteger
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) || math.Abs(f) > maxSafeInteger {
		return 0, false
	}
	return int64(f), true
}

func empty(x any) bool {
	switch t := x.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case []any:
		return len(t) == 0
	case map[string]any:
		return true // objects are never a value of a mapping
	}
	return false
}

// truncate cuts s to at most n bytes on a UTF-8 boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
