package importer

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite the golden files and the mapping documents")

// fixtureRoot holds one directory per format. The golden reports live under
// the module's testdata so the schema check (scripts/validate_schemas.py)
// validates them against schemas/v1.
const fixtureRoot = "../testdata/importers"

var fixedNow = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

type fixture struct {
	format Format
	path   string // input file
	kb     string // Qualys KnowledgeBase companion, when present
}

// golden returns the path of the golden report of the fixture.
func (f fixture) golden() string { return stem(f.path) + ".golden.json" }

// result returns the path of the golden result (everything but the report).
func (f fixture) result() string { return stem(f.path) + ".result.json" }

func stem(p string) string { return strings.TrimSuffix(p, filepath.Ext(p)) }

func isCompanion(name string) bool {
	return strings.HasSuffix(name, ".golden.json") || strings.HasSuffix(name, ".result.json") || strings.HasSuffix(name, ".kb.xml") ||
		strings.HasSuffix(name, ".options.json") || strings.HasSuffix(name, ".legacy.json")
}

// fixtures lists every input fixture, by format directory.
func fixtures(t *testing.T) []fixture {
	t.Helper()
	dirs, err := os.ReadDir(fixtureRoot)
	if err != nil {
		t.Fatal(err)
	}
	var out []fixture
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		format := Format(d.Name())
		files, err := os.ReadDir(filepath.Join(fixtureRoot, d.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if f.IsDir() || isCompanion(f.Name()) {
				continue
			}
			fx := fixture{format: format, path: filepath.Join(fixtureRoot, d.Name(), f.Name())}
			if kb := stem(fx.path) + ".kb.xml"; fileExists(kb) {
				fx.kb = kb
			}
			out = append(out, fx)
		}
	}
	return out
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// runFixture parses a fixture with the test options.
func runFixture(t *testing.T, fx fixture) (*Result, []string) {
	t.Helper()
	in, err := os.Open(fx.path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	opts := Options{Now: fixedNow, ReportID: "import-test"}
	// <stem>.options.json sets the repository a code report is filed on.
	if b, err := os.ReadFile(stem(fx.path) + ".options.json"); err == nil {
		var o struct {
			Repository string `json:"repository"`
			Branch     string `json:"branch"`
			CommitSHA  string `json:"commit_sha"`
		}
		if err := json.Unmarshal(b, &o); err != nil {
			t.Fatal(err)
		}
		opts.Repository, opts.Branch, opts.CommitSHA = o.Repository, o.Branch, o.CommitSHA
	}
	if fx.kb != "" {
		kb, err := os.Open(fx.kb)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = kb.Close() }()
		opts.QualysKnowledgeBase = kb
	}
	res, paths, err := parse(context.Background(), in, opts)
	if err != nil {
		t.Fatalf("parse %s: %v", fx.path, err)
	}
	if res.Format != fx.format {
		t.Fatalf("%s: detected %s, the directory says %s", fx.path, res.Format, fx.format)
	}
	return res, paths
}

// TestImporters_Golden pins the CTIS output of every fixture, and checks
// that it is a valid CTIS report whose findings all resolve to an asset.
func TestImporters_Golden(t *testing.T) {
	fxs := fixtures(t)
	if len(fxs) == 0 {
		t.Fatal("no fixtures")
	}
	for _, fx := range fxs {
		t.Run(filepath.Base(fx.path), func(t *testing.T) {
			res, _ := runFixture(t, fx)
			if err := res.Report.Validate(); err != nil {
				t.Fatalf("report is not valid CTIS: %v", err)
			}
			// Every finding names its asset in the report (Validate checks
			// that a named asset exists).
			for i, f := range res.Report.Findings {
				if f.AssetRef == "" {
					t.Errorf("finding %d (%s) has no asset_ref", i, f.Title)
				}
			}
			if len(res.Report.Findings) == 0 && len(res.VEX) == 0 && len(res.Report.Dependencies) == 0 {
				t.Fatal("fixture produced nothing: the case proves nothing")
			}
			compareGolden(t, fx.golden(), res.Report)
			compareGolden(t, fx.result(), struct {
				Format   Format         `json:"format"`
				VEX      []VEXStatement `json:"vex,omitempty"`
				Stats    Stats          `json:"stats"`
				Issues   []Issue        `json:"issues,omitempty"`
				Unmapped []string       `json:"unmapped,omitempty"`
			}{res.Format, res.VEX, res.Stats, res.Issues, res.Unmapped})
		})
	}
}

func compareGolden(t *testing.T, path string, v any) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	got := buf.Bytes()
	if *update {
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
		t.Errorf("%s differs from the output; run go test ./importer -run TestImporters_Golden -update and review the diff\n%s", path, firstDiff(want, got))
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

// TestImporters_FieldCoverage is the mapping discipline gate: every field of
// every fixture must be listed in its format's spec (mapped or ignored on
// purpose), and every mapped field of a spec must occur in a fixture, so the
// golden files prove each mapping the spec claims.
func TestImporters_FieldCoverage(t *testing.T) {
	observed := map[Format]map[string]bool{}
	for _, fx := range fixtures(t) {
		res, paths := runFixture(t, fx)
		if len(res.Unmapped) > 0 {
			t.Errorf("%s holds fields its spec does not list (map them, or list them as ignored with a reason):\n  %s", fx.path, strings.Join(res.Unmapped, "\n  "))
		}
		if observed[fx.format] == nil {
			observed[fx.format] = map[string]bool{}
		}
		for _, p := range paths {
			observed[fx.format][p] = true
		}
	}
	for _, spec := range Specs() {
		if problems := spec.check(); len(problems) > 0 {
			t.Errorf("spec %s: %s", spec.Format, strings.Join(problems, "; "))
		}
		seen := observed[spec.Format]
		if spec.Format == FormatQualysKB {
			seen = observed[FormatQualys]
		}
		if seen == nil {
			t.Errorf("spec %s has no fixture", spec.Format)
			continue
		}
		var missing []string
		for _, f := range spec.Fields {
			if !f.Mapped() {
				continue
			}
			hit := false
			for p := range seen {
				if pathMatch(f.Path, p) {
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
			t.Errorf("spec %s maps fields no fixture holds, so no golden file proves the mapping (add them to a fixture):\n  %s", spec.Format, strings.Join(missing, "\n  "))
		}
	}
	for _, f := range AllFormats() {
		if _, ok := SpecFor(f); !ok {
			t.Errorf("format %s has no mapping spec", f)
		}
	}
}

// TestMappingDocs keeps docs/importers/ in step with the specs.
func TestMappingDocs(t *testing.T) {
	const dir = "../docs/importers"
	docs := map[string]string{"README.md": coverageReport(t)}
	for _, s := range Specs() {
		docs[string(s.Format)+".md"] = s.Markdown()
	}
	if *update {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, want := range docs {
		path := filepath.Join(dir, name)
		if *update {
			if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Errorf("%s is out of date; run go test ./importer -run TestMappingDocs -update", path)
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if _, ok := docs[e.Name()]; !ok && !*update {
			t.Errorf("%s/%s belongs to no spec; remove it", dir, e.Name())
		}
	}
}

// coverageReport renders the per-importer coverage table.
func coverageReport(t *testing.T) string {
	t.Helper()
	observed := map[Format]map[string]bool{}
	for _, fx := range fixtures(t) {
		_, paths := runFixture(t, fx)
		if observed[fx.format] == nil {
			observed[fx.format] = map[string]bool{}
		}
		for _, p := range paths {
			observed[fx.format][p] = true
		}
	}
	var b strings.Builder
	b.WriteString("# Importer mapping specs\n\n")
	b.WriteString("Generated by `go test ./importer -run TestMappingDocs -update`; do not edit.\n\n")
	b.WriteString("Each importer converts one exported format to CTIS. Its spec lists every source field it knows and the CTIS member that keeps it, or why it is ignored on purpose. The tests fail when a fixture holds a field its spec does not list, or when a spec maps a field no fixture holds.\n\n")
	b.WriteString("- **Spec coverage**: mapped fields as a share of all fields the spec lists.\n")
	b.WriteString("- **Fixture coverage**: distinct source field paths of the fixtures whose spec row maps them, as a share of all distinct paths the fixtures hold.\n\n")
	b.WriteString("| Format | Spec | Mapped | Ignored | Spec coverage | Fixture paths | Fixture coverage |\n|---|---|---|---|---|---|---|\n")
	for _, s := range Specs() {
		c := s.Coverage()
		seen := observed[s.Format]
		if s.Format == FormatQualysKB {
			seen = map[string]bool{}
			for p := range observed[FormatQualys] {
				if strings.HasPrefix(p, "/KNOWLEDGE_BASE_VULN_LIST_OUTPUT") {
					seen[p] = true
				}
			}
		}
		mapped, total := 0, 0
		for p := range seen {
			f, ok := s.Match(p)
			if !ok {
				continue
			}
			if f.Target == Container {
				continue
			}
			total++
			if f.Mapped() {
				mapped++
			}
		}
		pct := 0.0
		if total > 0 {
			pct = 100 * float64(mapped) / float64(total)
		}
		fmt.Fprintf(&b, "| `%s` | [%s](%s.md) | %d | %d | %.0f%% | %d | %.0f%% |\n", s.Format, s.Title, s.Format, c.Mapped, c.Ignored, c.Percent(), total, pct)
	}
	return b.String()
}
