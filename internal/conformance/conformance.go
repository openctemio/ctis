// Package conformance runs the CTIS conformance vectors (conformance/v2)
// against this implementation. The same vectors let any other implementation
// check itself: they are plain JSON, see conformance/README.md, and
// conformance/PROTOCOL.md describes the line protocol (Serve) through which
// scripts/conformance_harness.py drives any implementation.
package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Result is the outcome of one vector.
type Result struct {
	Suite string // for example "canonical/domain.json" or "documents"
	Name  string
	Err   string // empty when the vector passed
}

// Run executes every vector under dir (a conformance/v2 directory) and
// returns one Result per vector. It returns an error only when dir cannot be
// read at all.
func Run(dir string) ([]Result, error) {
	if _, err := os.Stat(dir); err != nil {
		return nil, err
	}
	cases, loadErrs := Cases(dir)
	out := make([]Result, 0, len(cases)+len(loadErrs))
	for _, le := range loadErrs {
		out = append(out, Result(le))
	}
	for _, c := range cases {
		got, e := Do(c.Op, c.Input)
		r := Result{Suite: c.Suite, Name: c.Name}
		if err := c.Check(got, e, true); err != nil {
			r.Err = err.Error()
		}
		out = append(out, r)
	}
	return out, nil
}

// Check compares an answer with the case's expectation. With messages set,
// an expected error message substring must occur in the answer's message
// (the Go reference words its messages as the vectors say; another
// implementation matches on the category only).
func (c *Case) Check(got any, e *OpError, messages bool) error {
	if c.WantErr != nil {
		if e == nil {
			return fmt.Errorf("%w, got %s", errNoError, compact(got))
		}
		if c.WantErr.Category != "" && e.Category != c.WantErr.Category {
			return fmt.Errorf("category %s, want %s (%s)", e.Category, c.WantErr.Category, e.Message)
		}
		if messages && c.WantErr.Message != "" && !strings.Contains(e.Message, c.WantErr.Message) {
			return fmt.Errorf("message %q does not contain %q", e.Message, c.WantErr.Message)
		}
		return nil
	}
	if e != nil {
		return e
	}
	g, w := compact(got), compact(c.Want)
	if g != w {
		return mismatch(g, w)
	}
	return nil
}

// compact is the canonical JSON text of a value (object members sorted),
// so two encodings of the same value compare equal.
func compact(v any) string {
	raw, ok := v.(json.RawMessage)
	if !ok {
		var err error
		if raw, err = json.Marshal(v); err != nil {
			return fmt.Sprintf("<%v>", err)
		}
	}
	var tree any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&tree); err != nil {
		return string(raw)
	}
	out, _ := json.Marshal(tree)
	return string(out)
}

func mismatch(got, want string) error {
	return fmt.Errorf("got %s, want %s", got, want)
}

// Failures returns the results that did not pass.
func Failures(rs []Result) []Result {
	var out []Result
	for _, r := range rs {
		if r.Err != "" {
			out = append(out, r)
		}
	}
	return out
}
