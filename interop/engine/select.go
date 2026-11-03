package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Set is the mappings of one format and direction, one per upstream
// version, side by side.
type Set struct {
	mappings []*Mapping
}

// NewSet groups mappings of one format and direction. The mappings must
// have distinct versions.
func NewSet(ms ...*Mapping) (*Set, error) {
	seen := map[string]bool{}
	for i, m := range ms {
		if m.Format != ms[0].Format || m.Direction != ms[0].Direction {
			return nil, mappingErr("set: mapping %d is %s %s, want %s %s", i, m.Format, m.Direction, ms[0].Format, ms[0].Direction)
		}
		if seen[m.Version] {
			return nil, mappingErr("set: version %s twice", m.Version)
		}
		seen[m.Version] = true
	}
	return &Set{mappings: ms}, nil
}

// MustSet is NewSet that panics, for the sets an adapter builds at init.
func MustSet(ms ...*Mapping) *Set {
	s, err := NewSet(ms...)
	if err != nil {
		panic(err)
	}
	return s
}

// Versions lists the upstream versions of the set, in the order given.
func (s *Set) Versions() []string {
	out := make([]string, len(s.mappings))
	for i, m := range s.mappings {
		out[i] = m.Version
	}
	return out
}

// Version returns the mapping of an upstream version.
func (s *Set) Version(v string) (*Mapping, bool) {
	for _, m := range s.mappings {
		if m.Version == v {
			return m, true
		}
	}
	return nil, false
}

// Latest is the last mapping of the set.
func (s *Set) Latest() *Mapping { return s.mappings[len(s.mappings)-1] }

// ErrVersion is returned by Select for a document no mapping of the set
// matches.
var ErrVersion = errors.New("engine: no mapping for the version the document declares")

// Select returns the import mapping whose detect predicates all hold for
// the document. The document is read as a stream, and only the members the
// predicates name are looked at.
func (s *Set) Select(data []byte) (*Mapping, error) {
	var want []string
	for _, m := range s.mappings {
		for _, p := range m.Detect {
			want = append(want, p.Pointer)
		}
	}
	vals, err := lookupScalars(data, want)
	if err != nil {
		return nil, err
	}
	for _, m := range s.mappings {
		if len(m.Detect) == 0 {
			continue
		}
		ok := true
		for _, p := range m.Detect {
			if !p.holds(vals) {
				ok = false
				break
			}
		}
		if ok {
			return m, nil
		}
	}
	return nil, fmt.Errorf("%w (supported: %s)", ErrVersion, strings.Join(s.Versions(), ", "))
}

func (p *Predicate) holds(vals map[string]*string) bool {
	v, present := vals[p.Pointer]
	if p.Absent {
		return !present
	}
	if !present {
		return p.OrAbsent
	}
	if v == nil {
		// Present, but an object, an array or null.
		return false
	}
	switch {
	case p.Equals != nil:
		return *v == *p.Equals
	case len(p.In) > 0:
		for _, x := range p.In {
			if *v == x {
				return true
			}
		}
		return false
	case p.Prefix != nil:
		return strings.HasPrefix(*v, *p.Prefix)
	case p.re != nil:
		s := *v
		if len(s) > 4096 {
			s = s[:4096]
		}
		return p.re.MatchString(s)
	}
	return false
}

// lookupScalars finds the scalar values at the pointers (members only, no
// array indexes) in one streaming pass. A pointer to an object, an array or
// null has no value.
func lookupScalars(data []byte, pointers []string) (map[string]*string, error) {
	want := map[string]bool{}
	for _, p := range pointers {
		want[p] = true
	}
	out := map[string]*string{}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	type frame struct {
		object, expectKey bool
		key, ptr          string
	}
	var stack []frame
	for len(out) < len(want) {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrVersion, err)
		}
		n := len(stack)
		if s, ok := tok.(string); ok && n > 0 && stack[n-1].object && stack[n-1].expectKey {
			stack[n-1].key, stack[n-1].expectKey = s, false
			continue
		}
		if dl, ok := tok.(json.Delim); ok && (dl == '}' || dl == ']') {
			stack = stack[:n-1]
			if m := len(stack); m > 0 && stack[m-1].object {
				stack[m-1].expectKey = true
			}
			continue
		}
		ptr := ""
		if n > 0 {
			if !stack[n-1].object {
				// Inside an array: no pointer of a predicate goes here.
				if dl, ok := tok.(json.Delim); ok {
					if err := skip(dec, dl == '{' || dl == '['); err != nil {
						return nil, err
					}
				}
				continue
			}
			ptr = stack[n-1].ptr + "/" + escapeToken(stack[n-1].key)
		}
		if dl, ok := tok.(json.Delim); ok {
			if want[ptr] {
				out[ptr] = nil
			}
			if n+1 > 64 {
				return nil, fmt.Errorf("%w: nested deeper than 64", ErrVersion)
			}
			stack = append(stack, frame{object: dl == '{', expectKey: dl == '{', ptr: ptr})
			continue
		}
		if want[ptr] {
			if s, ok := scalarString(tok); ok {
				out[ptr] = &s
			} else if tok != nil {
				out[ptr] = nil
			}
		}
		if n > 0 {
			stack[n-1].expectKey = true
		}
	}
	return out, nil
}

func scalarString(tok json.Token) (string, bool) {
	switch t := tok.(type) {
	case string:
		return t, true
	case json.Number:
		return t.String(), true
	case bool:
		if t {
			return "true", true
		}
		return "false", true
	}
	return "", false
}

// LoadFS loads the mappings of one direction from an adapter's embedded
// files: <version>/<direction>.json for every version directory at the root
// of fsys, sorted by version. A mapping's version must equal its directory.
// A new upstream version is one more directory.
func LoadFS(fsys fs.FS, dir Direction, opts LoadOptions) (*Set, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, mappingErr("%v", err)
	}
	var ms []*Mapping
	for _, e := range entries {
		if !e.IsDir() || !versionRE.MatchString(e.Name()) {
			continue
		}
		data, err := fs.ReadFile(fsys, path.Join(e.Name(), string(dir)+".json"))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, mappingErr("%v", err)
		}
		m, err := Load(data, opts)
		if err != nil {
			return nil, fmt.Errorf("%s/%s.json: %w", e.Name(), dir, err)
		}
		if m.Version != e.Name() || m.Direction != dir {
			return nil, mappingErr("%s/%s.json is %s %s", e.Name(), dir, m.Direction, m.Version)
		}
		ms = append(ms, m)
	}
	if len(ms) == 0 {
		return nil, mappingErr("no %s mapping", dir)
	}
	sort.Slice(ms, func(i, j int) bool { return versionLess(ms[i].Version, ms[j].Version) })
	return NewSet(ms...)
}

// MustLoadFS is LoadFS that panics, for the sets an adapter builds at init.
func MustLoadFS(fsys fs.FS, dir Direction, opts LoadOptions) *Set {
	s, err := LoadFS(fsys, dir, opts)
	if err != nil {
		panic(err)
	}
	return s
}

func versionLess(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			return x < y
		}
	}
	return false
}
