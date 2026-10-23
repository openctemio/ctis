package mapping

import (
	"sort"
	"strings"
)

// MaxObservedFields bounds the distinct input fields Options.Observe
// records.
const MaxObservedFields = 512

// observer records the distinct field paths of the input records: the
// columns of a CSV header, the leaf paths of JSON and XML records with list
// indexes left out ("/cve/0" is "/cve").
type observer struct {
	seen     map[string]bool
	order    []string
	overflow bool
}

func newObserver() *observer { return &observer{seen: map[string]bool{}} }

func (o *observer) add(p string) {
	if o.seen[p] {
		return
	}
	if len(o.order) >= MaxObservedFields {
		o.overflow = true
		return
	}
	o.seen[p] = true
	o.order = append(o.order, p)
}

// walk records the leaf paths of one decoded record.
func (o *observer) walk(prefix string, v any, depth int) {
	if depth > MaxInputDepth || o.overflow {
		return
	}
	switch x := v.(type) {
	case map[string]any:
		o.walkMap(prefix, x, depth)
	case xmlElem:
		o.walkMap(prefix, map[string]any(x), depth)
	case []any:
		o.walkList(prefix, x, depth)
	case xmlList:
		o.walkList(prefix, []any(x), depth)
	default:
		if prefix == "" {
			prefix = "/"
		}
		o.add(prefix)
	}
}

func (o *observer) walkMap(prefix string, m map[string]any, depth int) {
	for _, k := range sortedKeys(m) {
		o.walk(prefix+"/"+escapeKey(k), m[k], depth+1)
	}
}

func (o *observer) walkList(prefix string, l []any, depth int) {
	if len(l) == 0 {
		if prefix == "" {
			prefix = "/"
		}
		o.add(prefix)
	}
	for _, it := range l {
		o.walk(prefix, it, depth+1)
	}
}

// escapeKey writes a member name as a path step (JSON Pointer escapes).
func escapeKey(k string) string {
	return strings.ReplaceAll(strings.ReplaceAll(k, "~", "~0"), "/", "~1")
}

// normPath writes a parsed path with its list indexes left out.
func normPath(p path) string {
	var b strings.Builder
	for _, st := range p {
		if st.index >= 0 {
			continue
		}
		if _, err := parseIndex(st.key); err == nil {
			continue
		}
		b.WriteString("/")
		b.WriteString(escapeKey(st.key))
	}
	if b.Len() == 0 {
		return "/"
	}
	return b.String()
}

// referencedPaths lists the normalized source paths a mapping reads: in
// predicates, values and template variables. Load has parsed every path.
func referencedPaths(d document) []string {
	set := map[string]bool{}
	add := func(s string) {
		if p, err := parsePath(s); err == nil {
			set[normPath(p)] = true
		}
	}
	for _, r := range d.Records {
		for _, p := range r.When {
			add(p.Path)
		}
		for _, v := range r.Set {
			if v.Path != "" || v.bare {
				add(v.Path)
			}
			for _, vp := range v.Vars {
				add(vp)
			}
		}
	}
	return sortedKeys(set)
}

// unmapped are the observed fields no referenced path covers. A path covers
// itself and everything below it.
func unmapped(fields, refs []string) []string {
	var out []string
	for _, f := range fields {
		covered := false
		for _, r := range refs {
			if r == "/" || f == r || strings.HasPrefix(f, r+"/") {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, f)
		}
	}
	return out
}

// fields returns the observed fields: header order for CSV, sorted
// otherwise.
func (o *observer) fields(keepOrder bool) []string {
	out := append([]string(nil), o.order...)
	if !keepOrder {
		sort.Strings(out)
	}
	return out
}
