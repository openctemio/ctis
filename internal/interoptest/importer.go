package interoptest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2/importer"
	"github.com/openctemio/ctis/v2/interop/engine"
)

// FixedNow and ReportID make the importer output of the tests deterministic.
var FixedNow = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

// ReportID is the fixed UUIDv7 of the deterministic tests.
const ReportID = "0192f0a0-0000-7000-8000-000000000001"

func stem(p string) string { return strings.TrimSuffix(p, filepath.Ext(p)) }

func isCompanion(name string) bool {
	return strings.HasSuffix(name, ".golden.json") || strings.HasSuffix(name, ".result.json") ||
		strings.HasSuffix(name, ".options.json") || strings.HasSuffix(name, ".losses.json") ||
		strings.Contains(name, ".golden.")
}

// Fixtures lists the input fixtures of dir: every file that is not a golden
// file or a sidecar.
func Fixtures(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || isCompanion(e.Name()) {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	if len(out) == 0 {
		t.Fatalf("no fixtures in %s", dir)
	}
	return out
}

// ParseFixture parses a fixture through importer.Parse with the fixed clock
// and report id; <stem>.options.json sets the repository a code report is
// filed on. Observe is on, so Result.Fields lists the source paths.
func ParseFixture(t *testing.T, path string, format importer.Format) *importer.Result {
	t.Helper()
	in, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	opts := importer.Options{Now: FixedNow, ReportID: ReportID, Observe: true}
	if b, err := os.ReadFile(stem(path) + ".options.json"); err == nil {
		var o struct {
			Format     importer.Format `json:"format"`
			Repository string          `json:"repository"`
			Branch     string          `json:"branch"`
			CommitSHA  string          `json:"commit_sha"`
		}
		if err := json.Unmarshal(b, &o); err != nil {
			t.Fatal(err)
		}
		opts.Repository, opts.Branch, opts.CommitSHA = o.Repository, o.Branch, o.CommitSHA
		if o.Format != "" {
			opts.Format = o.Format
		}
	}
	res, err := importer.Parse(context.Background(), in, opts)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if res.Format != format {
		t.Fatalf("%s: detected %s, want %s", path, res.Format, format)
	}
	return res
}

// ImporterGolden pins the CTIS output of every fixture of dir (report in
// <stem>.golden.json, the rest in <stem>.result.json) and checks that it is
// a valid report whose findings all resolve to an asset.
func ImporterGolden(t *testing.T, dir string, format importer.Format) {
	t.Helper()
	for _, fx := range Fixtures(t, dir) {
		t.Run(filepath.Base(fx), func(t *testing.T) {
			res := ParseFixture(t, fx, format)
			if err := res.Report.Validate(); err != nil {
				t.Fatalf("report is not valid CTIS: %v", err)
			}
			for i, f := range res.Report.Findings {
				if f.AssetRef == "" {
					t.Errorf("finding %d (%s) has no asset_ref", i, f.Title)
				}
			}
			if len(res.Report.Findings) == 0 && len(res.VEX) == 0 && len(res.Report.Dependencies) == 0 {
				t.Fatal("fixture produced nothing: the case proves nothing")
			}
			CompareJSON(t, stem(fx)+".golden.json", res.Report)
			CompareJSON(t, stem(fx)+".result.json", struct {
				Format   importer.Format          `json:"format"`
				VEX      []importer.VEXStatement `json:"vex,omitempty"`
				Stats    importer.Stats          `json:"stats"`
				Issues   []importer.Issue        `json:"issues,omitempty"`
				Unmapped []string                `json:"unmapped,omitempty"`
			}{res.Format, res.VEX, res.Stats, res.Issues, res.Unmapped})
		})
	}
}

// CompareJSON compares v, encoded with two-space indentation and without
// HTML escaping, with the golden file at path; -update rewrites it.
func CompareJSON(t *testing.T, path string, v any) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	got := buf.Bytes()
	if *Update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from the output; rerun with -update and review the diff\n%s", path, firstDiff(want, got))
	}
}

func firstDiff(want, got []byte) string {
	wl := strings.Split(string(want), "\n")
	gl := strings.Split(string(got), "\n")
	for i := 0; i < len(wl) || i < len(gl); i++ {
		var w, g string
		if i < len(wl) {
			w = wl[i]
		}
		if i < len(gl) {
			g = gl[i]
		}
		if w != g {
			return fmt.Sprintf("line %d:\n- %s\n+ %s", i+1, w, g)
		}
	}
	return ""
}

// FieldCoverage is the mapping discipline gate of an import mapping: every
// source field of every fixture of dir is listed in the format's spec
// (mapped or ignored on purpose), and every mapped field of the spec occurs
// in a fixture, so the golden files prove each mapping the spec claims.
// extra are more source paths that prove fields (other test inputs).
func FieldCoverage(t *testing.T, dir string, format importer.Format, extra ...string) {
	t.Helper()
	spec, ok := importer.SpecFor(format)
	if !ok {
		t.Fatalf("format %s has no spec (is the adapter registered?)", format)
	}
	if problems := spec.Problems(); len(problems) > 0 {
		t.Errorf("spec %s: %s", format, strings.Join(problems, "; "))
	}
	seen := map[string]bool{}
	for _, p := range extra {
		seen[p] = true
	}
	for _, fx := range Fixtures(t, dir) {
		res := ParseFixture(t, fx, format)
		if len(res.Unmapped) > 0 {
			t.Errorf("%s holds fields its spec does not list (map them, or list them as ignored with a reason):\n  %s", fx, strings.Join(res.Unmapped, "\n  "))
		}
		for _, p := range res.Fields {
			seen[p] = true
		}
	}
	var missing []string
	for _, f := range spec.Fields {
		if !f.Mapped() {
			continue
		}
		hit := false
		for p := range seen {
			if engine.MatchPath(f.Path, p) {
				hit = true
				break
			}
		}
		if !hit {
			missing = append(missing, f.Path)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("spec %s maps fields no fixture holds, so no golden file proves the mapping (add them to a fixture):\n  %s", format, strings.Join(missing, "\n  "))
	}
}

// CompareText compares text with the file at path; -update rewrites it.
func CompareText(t *testing.T, path, want string) {
	t.Helper()
	if *Update {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != want {
		t.Errorf("%s is out of date; rerun the test with -update", path)
	}
}

// SpecOf turns an import mapping into the importer spec of its format: the
// fields with their targets, the notes as rules.
func SpecOf(m *engine.Mapping) importer.Spec {
	return importer.SpecFromMapping(m)
}

// StructPaths lists the JSON paths an encoded value of type t can hold, in
// the field path syntax: maps as "/*", slices as "[]", an any or raw value
// as "/**".
func StructPaths(t reflect.Type) []string {
	out := map[string]bool{}
	structPaths(t, "", out, 0)
	paths := make([]string, 0, len(out))
	for p := range out {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

var rawType = reflect.TypeOf(json.RawMessage{})

func structPaths(t reflect.Type, prefix string, out map[string]bool, depth int) {
	if depth > 24 {
		return
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == rawType || t.Kind() == reflect.Interface {
		out[prefix+"/**"] = true
		return
	}
	switch t.Kind() {
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			p := prefix + "/" + engine.PathKey(name)
			out[p] = true
			structPaths(f.Type, p, out, depth+1)
		}
	case reflect.Map:
		p := prefix + "/*"
		out[p] = true
		structPaths(t.Elem(), p, out, depth+1)
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			return
		}
		p := prefix + "[]"
		if prefix == "" {
			p = "/[]"
		}
		out[p] = true
		structPaths(t.Elem(), p, out, depth+1)
	}
}

// ExportCoverage checks that the export mapping lists every path the
// output type can hold: the mapping is the complete list of what the
// exporter writes, and Reemit never writes into those places.
func ExportCoverage(t *testing.T, m *engine.Mapping, out reflect.Type) {
	t.Helper()
	var missing []string
	for _, p := range StructPaths(out) {
		if _, ok := m.Match(p); !ok {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		t.Errorf("export mapping %s %s does not list what the exporter writes:\n  %s", m.Format, m.Version, strings.Join(missing, "\n  "))
	}
}
