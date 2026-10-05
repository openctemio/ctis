package importer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"unicode/utf8"
)

// readAll reads the whole input within the size limit.
func readAll(r io.Reader, format Format, lim Limits) ([]byte, error) {
	data, err := io.ReadAll(newCapReader(r, lim.MaxInputBytes))
	if err != nil {
		if errors.Is(err, ErrTooLarge) {
			return nil, &ParseError{Format: format, Msg: err.Error(), Err: ErrTooLarge}
		}
		return nil, &ParseError{Format: format, Msg: "read input: " + err.Error(), Err: ErrMalformed}
	}
	return bytes.TrimPrefix(data, utf8BOM), nil
}

// lines maps byte offsets of one input to 1-based lines and columns.
type lines struct {
	data  []byte
	index []int // offset of every '\n', built on first use
}

func (l *lines) pos(off int64) (line, col int) {
	if off < 0 {
		return 0, 0
	}
	if off > int64(len(l.data)) {
		off = int64(len(l.data))
	}
	if l.index == nil {
		l.index = make([]int, 0, 1024)
		for i, b := range l.data {
			if b == '\n' {
				l.index = append(l.index, i)
			}
		}
	}
	o := int(off)
	n := sort.SearchInts(l.index, o) // newlines before o
	start := 0
	if n > 0 {
		start = l.index[n-1] + 1
	}
	return n + 1, utf8.RuneCount(l.data[start:o]) + 1
}

// jsonDoc is a JSON input that passed scanJSON.
type jsonDoc struct {
	format Format
	data   []byte
	lines  *lines
	// offsets of the elements of the arrays scanJSON was asked to index, by
	// path ("/findings[]").
	offsets map[string][]int64
}

// issueAt returns an Issue at element i of the array at path.
func (d *jsonDoc) issueAt(path string, i int, pointer, msg string) Issue {
	is := Issue{Path: pointer, Message: msg}
	if offs := d.offsets[path]; i >= 0 && i < len(offs) {
		is.Line, is.Column = d.lines.pos(offs[i])
	}
	return is
}

// scanJSON is the only way this package reads JSON. Before anything is
// decoded into a type it checks, in one streaming pass without building a
// tree, that the input is valid UTF-8 and valid JSON, that no value is
// nested deeper than MaxDepth and no string is longer than MaxTextBytes. It
// records the path of every member ("/a/b", arrays as "[]") and the start
// offset of every element of the arrays named in index.
func scanJSON(data []byte, format Format, lim Limits, obs *observer, index ...string) (*jsonDoc, error) {
	doc := &jsonDoc{format: format, data: data, lines: &lines{data: data}, offsets: map[string][]int64{}}
	fail := func(off int64, kind error, msg string) error {
		line, col := doc.lines.pos(off)
		return &ParseError{Format: format, Line: line, Column: col, Msg: msg, Err: kind}
	}
	if !utf8.Valid(data) {
		off := 0
		for off < len(data) {
			r, w := utf8.DecodeRune(data[off:])
			if r == utf8.RuneError && w <= 1 {
				break
			}
			off += w
		}
		return nil, fail(int64(off), ErrMalformed, "input is not valid UTF-8")
	}
	want := map[string]bool{}
	for _, p := range index {
		want[p] = true
	}

	type frame struct {
		object    bool
		expectKey bool
		path      string
		key       string
	}
	var stack []frame
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	seenValue := false
	for {
		prevEnd := dec.InputOffset()
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			var se *json.SyntaxError
			if errors.As(err, &se) {
				return nil, fail(se.Offset, ErrMalformed, se.Error())
			}
			return nil, fail(dec.InputOffset(), ErrMalformed, err.Error())
		}
		n := len(stack)
		// A key of the enclosing object.
		if s, ok := tok.(string); ok && n > 0 && stack[n-1].object && stack[n-1].expectKey {
			if len(s) > lim.MaxTextBytes {
				return nil, fail(prevEnd, ErrTooLarge, fmt.Sprintf("a member name is longer than %d bytes", lim.MaxTextBytes))
			}
			stack[n-1].key = s
			stack[n-1].expectKey = false
			continue
		}
		// The close of a container ends a value of its parent.
		if dl, ok := tok.(json.Delim); ok && (dl == '}' || dl == ']') {
			stack = stack[:n-1]
			if m := len(stack); m > 0 && stack[m-1].object {
				stack[m-1].expectKey = true
			}
			if len(stack) == 0 {
				seenValue = true
			}
			continue
		}
		if n == 0 && seenValue {
			return nil, fail(prevEnd, ErrMalformed, "more than one JSON value")
		}
		// A value: its path.
		var path string
		switch {
		case n == 0:
			path = ""
		case stack[n-1].object:
			path = stack[n-1].path + "/" + pathKey(stack[n-1].key)
		default:
			// The elements of a top-level array are "/[]".
			path = stack[n-1].path + "[]"
			if stack[n-1].path == "" {
				path = "/[]"
			}
			if want[path] {
				start := prevEnd
				for start < int64(len(data)) {
					c := data[start]
					if c != ' ' && c != '\t' && c != '\r' && c != '\n' && c != ',' {
						break
					}
					start++
				}
				doc.offsets[path] = append(doc.offsets[path], start)
			}
		}
		if path != "" {
			obs.add(path)
		}
		switch v := tok.(type) {
		case json.Delim: // '{' or '['
			if n+1 > lim.MaxDepth {
				return nil, fail(prevEnd, ErrTooLarge, fmt.Sprintf("values nested deeper than %d", lim.MaxDepth))
			}
			stack = append(stack, frame{object: v == '{', expectKey: v == '{', path: path})
			continue
		case string:
			if len(v) > lim.MaxTextBytes {
				return nil, fail(prevEnd, ErrTooLarge, fmt.Sprintf("a string is longer than %d bytes", lim.MaxTextBytes))
			}
		}
		if m := len(stack); m > 0 && stack[m-1].object {
			stack[m-1].expectKey = true
		}
		if len(stack) == 0 {
			seenValue = true
		}
	}
	if !seenValue {
		return nil, fail(0, ErrMalformed, "no JSON value")
	}
	return doc, nil
}

// decode decodes the scanned input into v, with a line number on error.
func (d *jsonDoc) decode(v any) error {
	if err := json.Unmarshal(d.data, v); err != nil {
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) {
			line, col := d.lines.pos(te.Offset)
			field := te.Field
			if field == "" {
				field = "value"
			}
			return &ParseError{Format: d.format, Line: line, Column: col, Msg: fmt.Sprintf("%s: want %s, got JSON %s", field, te.Type, te.Value), Err: ErrMalformed}
		}
		return &ParseError{Format: d.format, Msg: err.Error(), Err: ErrMalformed}
	}
	return nil
}
