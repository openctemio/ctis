package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/openctemio/ctis/v2"
)

// Entry is one kept member to write back: an absolute pointer into the
// output and its value.
type Entry struct {
	Pointer string
	Value   json.RawMessage
}

// Kept reads the passthrough an import stored under the mapping's namespace
// in ext: the upstream version it came from and its members (pointers as
// stored: absolute for the report, relative for a record). The members are
// checked again (pointer syntax, limits, scrub rules), because a CTIS
// document may come from anyone. ok is false when ext holds nothing for the
// namespace, or its version is neither the mapping's nor one the mapping
// re-emits from.
func (m *Mapping) Kept(ext ctis.Extensions) (version string, entries []Entry, ok bool) {
	ns, found := ext[m.Namespace]
	if !found {
		return "", nil, false
	}
	version, _ = ns["version"].(string)
	if !m.reemits(version) {
		return version, nil, false
	}
	raw, err := json.Marshal(ns["unmapped"])
	if err != nil {
		return version, nil, false
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(raw, &members) != nil {
		return version, nil, false
	}
	lim := m.limits()
	keys := make([]string, 0, len(members))
	for k := range members {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	size := 0
	for _, k := range keys {
		if len(entries) >= lim.MaxEntries {
			break
		}
		if _, ok := parsePointer(k); !ok || k == "" {
			continue
		}
		name := lastToken(k)
		if sensitiveName.MatchString(name) {
			continue
		}
		v, ok := scrubRaw(members[k], name, lim.MaxDepth, nil)
		if !ok || len(v) > lim.MaxBytes {
			continue
		}
		if size += len(k) + len(v); size > lim.MaxBytes {
			break
		}
		entries = append(entries, Entry{Pointer: k, Value: v})
	}
	return version, entries, true
}

// reemits reports whether the export mapping writes back the passthrough
// of an upstream version: its own, or one listed in ReemitFrom.
func (m *Mapping) reemits(version string) bool {
	if version == m.Version {
		return true
	}
	for _, v := range m.ReemitFrom {
		if v == version {
			return true
		}
	}
	return false
}

// ErrReemit is returned by Reemit for an output that is not a JSON object
// or array.
var ErrReemit = errors.New("engine: reemit")

// Reemit writes kept members back into an encoded output. A member is
// written only where the output has none yet and the export mapping does
// not own the place (Owns); missing objects on the way are created, missing
// array elements are not. It returns the new output (indented with indent
// when indent is not empty) and the number of members it could not place.
// Without entries the output is returned unchanged.
func (m *Mapping) Reemit(out []byte, entries []Entry, indent string) ([]byte, int, error) {
	if len(entries) == 0 {
		return out, 0, nil
	}
	root, err := parseNode(out)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrReemit, err)
	}
	dropped := 0
	for _, e := range entries {
		if m.Owns(e.Pointer) || !root.set(e.Pointer, e.Value) {
			dropped++
		}
	}
	var buf bytes.Buffer
	root.write(&buf)
	if indent == "" {
		return buf.Bytes(), dropped, nil
	}
	var ind bytes.Buffer
	if err := json.Indent(&ind, buf.Bytes(), "", indent); err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrReemit, err)
	}
	return ind.Bytes(), dropped, nil
}

// node is a JSON value that keeps the order of object members.
type node struct {
	keys []string
	vals []*node
	arr  []*node
	raw  json.RawMessage // a scalar
	kind byte            // '{', '[' or 0 for a scalar
}

func parseNode(data []byte) (*node, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	n, err := readNode(dec, 0)
	if err != nil {
		return nil, err
	}
	if n.kind == 0 {
		return nil, errors.New("output is not an object or an array")
	}
	return n, nil
}

func readNode(dec *json.Decoder, depth int) (*node, error) {
	if depth > 256 {
		return nil, errors.New("nested deeper than 256")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		n := &node{kind: byte(t)}
		for dec.More() {
			if t == '{' {
				k, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, _ := k.(string)
				v, err := readNode(dec, depth+1)
				if err != nil {
					return nil, err
				}
				n.keys = append(n.keys, key)
				n.vals = append(n.vals, v)
			} else {
				v, err := readNode(dec, depth+1)
				if err != nil {
					return nil, err
				}
				n.arr = append(n.arr, v)
			}
		}
		if _, err := dec.Token(); err != nil { // the closing delimiter
			return nil, err
		}
		return n, nil
	default:
		raw, err := json.Marshal(t)
		if err != nil {
			return nil, err
		}
		return &node{raw: raw}, nil
	}
}

func (n *node) member(k string) *node {
	for i, key := range n.keys {
		if key == k {
			return n.vals[i]
		}
	}
	return nil
}

// set places value at the pointer; false when the place exists already or
// cannot be reached.
func (n *node) set(ptr string, value json.RawMessage) bool {
	toks, ok := parsePointer(ptr)
	if !ok || len(toks) == 0 {
		return false
	}
	cur := n
	for i, t := range toks {
		last := i == len(toks)-1
		switch cur.kind {
		case '[':
			idx, ok := isIndex(t)
			if !ok || idx >= len(cur.arr) || last {
				return false
			}
			cur = cur.arr[idx]
		case '{':
			next := cur.member(t)
			if last {
				if next != nil {
					return false
				}
				v, err := parseValue(value)
				if err != nil {
					return false
				}
				cur.keys = append(cur.keys, t)
				cur.vals = append(cur.vals, v)
				return true
			}
			if next == nil {
				if _, isIdx := isIndex(toks[i+1]); isIdx {
					return false
				}
				next = &node{kind: '{'}
				cur.keys = append(cur.keys, t)
				cur.vals = append(cur.vals, next)
			}
			cur = next
		default:
			return false
		}
	}
	return false
}

func parseValue(raw json.RawMessage) (*node, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return readNode(dec, 0)
}

func (n *node) write(b *bytes.Buffer) {
	switch n.kind {
	case '{':
		b.WriteByte('{')
		for i, k := range n.keys {
			if i > 0 {
				b.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			b.Write(kb)
			b.WriteByte(':')
			n.vals[i].write(b)
		}
		b.WriteByte('}')
	case '[':
		b.WriteByte('[')
		for i, v := range n.arr {
			if i > 0 {
				b.WriteByte(',')
			}
			v.write(b)
		}
		b.WriteByte(']')
	default:
		b.Write(n.raw)
	}
}

// Unindexed returns the entries whose pointer crosses no array index: the
// members an exporter can place without knowing how it orders a list.
func Unindexed(entries []Entry) []Entry {
	var out []Entry
	for _, e := range entries {
		toks, ok := parsePointer(e.Pointer)
		if !ok {
			continue
		}
		indexed := false
		for _, t := range toks {
			if _, idx := isIndex(t); idx {
				indexed = true
				break
			}
		}
		if !indexed {
			out = append(out, e)
		}
	}
	return out
}
