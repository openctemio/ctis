package interoptest

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/importer"
	"github.com/openctemio/ctis/v2/interop/engine"
)

// Vectors are the conformance vectors of one adapter and upstream version:
// conformance/interop/<format>/<version>/vectors.json and the files it
// names. Every implementation of an adapter runs the same files.
type Vectors struct {
	Format  string   `json:"format"`
	Version string   `json:"version"`
	Vectors []Vector `json:"vectors"`
}

// Vector is one upstream sample document (import) or one CTIS document
// (export) and what must hold for it.
type Vector struct {
	Name string `json:"name"`
	// Input is the upstream sample (import vectors) or a CTIS document
	// (export-only vectors).
	Input string `json:"input"`
	// Expect is the golden output: the CTIS report of an import (with the
	// VEX statements a VEX document gives), the upstream document of an
	// export-only vector.
	Expect string `json:"expect"`
	// RoundTrip: import, export, import again; the two reports are equal
	// but for Losses.
	RoundTrip bool `json:"roundtrip,omitempty"`
	// Losses are the accepted losses of the round trip, each with a reason.
	Losses []Loss `json:"losses,omitempty"`
	// Reemitted are pointers into the input that the export writes back
	// with the same value (the passthrough).
	Reemitted []string `json:"reemitted,omitempty"`
	// Kept are pointers (as stored under extensions) that the import keeps
	// as passthrough.
	Kept []string `json:"kept,omitempty"`
	// Never are strings that must not appear anywhere in the report nor in
	// the export (raw secrets, command lines, script URLs).
	Never []string `json:"never,omitempty"`
}

// Loss is one accepted loss.
type Loss struct {
	Member string `json:"member"`
	Reason string `json:"reason"`
}

// LoadVectors reads the vectors.json of dir and checks it names its own
// format and version.
func LoadVectors(t *testing.T, dir, format, version string) Vectors {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v Vectors
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("%s/vectors.json: %v", dir, err)
	}
	if v.Format != format || v.Version != version || len(v.Vectors) == 0 {
		t.Fatalf("%s/vectors.json is %s %s with %d vectors, want %s %s", dir, v.Format, v.Version, len(v.Vectors), format, version)
	}
	for _, x := range v.Vectors {
		for _, l := range x.Losses {
			if l.Reason == "" {
				t.Errorf("%s: loss %s has no reason", x.Name, l.Member)
			}
		}
	}
	return v
}

// ImportVectors runs the import vectors of dir through importer.Parse (the
// adapter is registered), and, when export is not nil, the round trips.
func ImportVectors(t *testing.T, dir string, format importer.Format, version string, ns string, export func(*ctis.Report) ([]byte, error)) {
	t.Helper()
	vs := LoadVectors(t, dir, string(format), version)
	for _, v := range vs.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			in, err := os.ReadFile(filepath.Join(dir, v.Input))
			if err != nil {
				t.Fatal(err)
			}
			first := parseBytes(t, in, format)
			if err := first.Report.Validate(); err != nil {
				t.Fatalf("not valid CTIS: %v", err)
			}
			if v.Expect != "" {
				// The report, and the VEX statements a VEX document gives.
				CompareJSON(t, filepath.Join(dir, v.Expect), struct {
					Report *ctis.Report             `json:"report"`
					VEX    []importer.VEXStatement `json:"vex,omitempty"`
				}{first.Report, first.VEX})
			}
			report, _ := json.Marshal(first.Report)
			never(t, "report", report, v.Never)
			kept := keptPointers(first.Report, ns)
			for _, p := range v.Kept {
				if !kept[p] {
					t.Errorf("passthrough: %s not kept (kept: %v)", p, keys(kept))
				}
			}
			if !v.RoundTrip {
				return
			}
			if export == nil {
				t.Fatal("round trip without an exporter")
			}
			out, err := export(first.Report)
			if err != nil {
				t.Fatal(err)
			}
			never(t, "export", out, v.Never)
			for _, p := range v.Reemitted {
				want, ok1 := valueAt(in, p)
				got, ok2 := valueAt(out, p)
				if !ok1 || !ok2 || !reflect.DeepEqual(want, got) {
					t.Errorf("reemit %s: input %v (%v), export %v (%v)", p, want, ok1, got, ok2)
				}
			}
			second := parseBytes(t, out, format)
			var losses []string
			for _, l := range v.Losses {
				losses = append(losses, l.Member)
			}
			for _, d := range DiffWithout(t, first.Report, second.Report, losses) {
				t.Error(d)
			}
		})
	}
}

// ExportVectors runs export-only vectors: a CTIS document to the golden
// upstream document.
func ExportVectors(t *testing.T, dir, format, version string, export func(*ctis.Report) ([]byte, error)) {
	t.Helper()
	vs := LoadVectors(t, dir, format, version)
	for _, v := range vs.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			in, err := os.ReadFile(filepath.Join(dir, v.Input))
			if err != nil {
				t.Fatal(err)
			}
			r, _, err := ctis.Decode(bytes.NewReader(in))
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Validate(); err != nil {
				t.Fatalf("input is not valid CTIS: %v", err)
			}
			out, err := export(&r)
			if err != nil {
				t.Fatal(err)
			}
			never(t, "export", out, v.Never)
			path := filepath.Join(dir, v.Expect)
			if len(out) == 0 || out[len(out)-1] != '\n' {
				out = append(out, '\n')
			}
			if *Update {
				if err := os.WriteFile(path, out, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run with -update to create it)", err)
			}
			if !bytes.Equal(want, out) {
				t.Errorf("%s differs from the export\n%s", path, firstDiff(want, out))
			}
		})
	}
}

// DiffWithout compares two values after dropping the members (the
// RoundTripDiff member syntax) on both sides.
func DiffWithout(t *testing.T, want, got any, members []string) []string {
	t.Helper()
	a, b := toTree(t, want), toTree(t, got)
	for _, m := range members {
		a = dropMember(a, splitMember(m))
		b = dropMember(b, splitMember(m))
	}
	var diffs []string
	diffTree("", a, b, &diffs)
	return diffs
}

func parseBytes(t *testing.T, in []byte, format importer.Format) *importer.Result {
	t.Helper()
	res, err := importer.Parse(context.Background(), bytes.NewReader(in), importer.Options{Format: format, Now: FixedNow, ReportID: ReportID})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	return res
}

func never(t *testing.T, what string, data []byte, values []string) {
	t.Helper()
	for _, s := range values {
		if strings.Contains(string(data), s) {
			t.Errorf("%s holds %q", what, s)
		}
	}
}

// keptPointers lists the passthrough pointers of a report: the report's own
// and, prefixed "findings[i]", each finding's.
func keptPointers(r *ctis.Report, ns string) map[string]bool {
	out := map[string]bool{}
	add := func(prefix string, ext ctis.Extensions) {
		un, _ := ext[ns]["unmapped"].(map[string]any)
		for k := range un {
			out[prefix+k] = true
		}
	}
	add("", r.Extensions)
	for i := range r.Findings {
		add("findings["+itoa(i)+"]", r.Findings[i].Extensions)
	}
	return out
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// valueAt returns the value at an RFC 6901 pointer of a JSON document.
func valueAt(doc []byte, ptr string) (any, bool) {
	var v any
	if json.Unmarshal(doc, &v) != nil {
		return nil, false
	}
	if _, ok := engine.PointerPath(ptr); !ok {
		return nil, false
	}
	for _, tok := range strings.Split(ptr, "/")[1:] {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		switch c := v.(type) {
		case map[string]any:
			x, ok := c[tok]
			if !ok {
				return nil, false
			}
			v = x
		case []any:
			var i int
			if err := json.Unmarshal([]byte(tok), &i); err != nil || i < 0 || i >= len(c) {
				return nil, false
			}
			v = c[i]
		default:
			return nil, false
		}
	}
	return v, true
}
