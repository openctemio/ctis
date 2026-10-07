package mapping

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// path is a parsed source path. Each step is a member name or a list index.
type path []step

type step struct {
	key   string
	index int // -1 for a member name
}

const maxPathSteps = 32

// parsePath parses "/a/b", "/a/0", "/a[0]" or "/" (and "") for the record
// itself. Member names use JSON Pointer escapes: "~1" is "/" and "~0" is
// "~". A step that is all digits addresses a list element, or an object
// member of that name when the value is an object.
func parsePath(s string) (path, error) {
	if s == "" || s == "/" {
		return path{}, nil
	}
	if !strings.HasPrefix(s, "/") {
		return nil, fmt.Errorf("%q: a path starts with /", s)
	}
	if len(s) > 512 {
		return nil, errors.New("path longer than 512 bytes")
	}
	var out path
	for _, raw := range strings.Split(s[1:], "/") {
		name := raw
		var idx []int
		// Trailing [n] suffixes: "cve-id[0]".
		for strings.HasSuffix(name, "]") {
			open := strings.LastIndexByte(name, '[')
			if open < 0 {
				return nil, fmt.Errorf("%q: unbalanced ]", s)
			}
			n, err := parseIndex(name[open+1 : len(name)-1])
			if err != nil {
				return nil, fmt.Errorf("%q: %w", s, err)
			}
			idx = append([]int{n}, idx...)
			name = name[:open]
		}
		if strings.ContainsAny(name, "[]") {
			return nil, fmt.Errorf("%q: [ inside a member name", s)
		}
		name = strings.ReplaceAll(strings.ReplaceAll(name, "~1", "/"), "~0", "~")
		if name == "" && len(idx) == 0 {
			return nil, fmt.Errorf("%q: empty step", s)
		}
		if name != "" {
			out = append(out, step{key: name, index: -1})
		}
		for _, n := range idx {
			out = append(out, step{index: n})
		}
	}
	if len(out) > maxPathSteps {
		return nil, fmt.Errorf("%q: more than %d steps", s, maxPathSteps)
	}
	return out, nil
}

func parseIndex(s string) (int, error) {
	if s == "" || len(s) > 6 || (len(s) > 1 && s[0] == '0') {
		return 0, fmt.Errorf("index %q", s)
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("index %q", s)
	}
	return n, nil
}

// get walks the decoded JSON value v. ok is false when a step is missing.
func (p path) get(v any) (any, bool) {
	cur := v
	for _, st := range p {
		switch x := cur.(type) {
		case map[string]any:
			key := st.key
			if st.index >= 0 {
				key = strconv.Itoa(st.index)
			}
			next, ok := x[key]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			n := st.index
			if n < 0 {
				var err error
				if n, err = parseIndex(st.key); err != nil {
					return nil, false
				}
			}
			if n >= len(x) {
				return nil, false
			}
			cur = x[n]
		default:
			return nil, false
		}
	}
	return cur, true
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// checkDepth refuses JSON nested deeper than max, without decoding it.
func checkDepth(data []byte, max int) error {
	depth := 0
	inString, escaped := false, false
	for _, c := range data {
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > max {
				return fmt.Errorf("nested deeper than %d", max)
			}
		case '}', ']':
			depth--
		}
	}
	return nil
}
