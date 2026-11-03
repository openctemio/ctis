package engine

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"
)

// testImport is a small import mapping: one record per result, three set
// rules, one ignored subtree, a fold rule.
const testImport = `{
  "apiVersion": "openctem.io/interop/v1",
  "format": "demo",
  "version": "1.1",
  "direction": "import",
  "namespace": "org.ctis.interop.demo",
  "title": "Demo",
  "version_pointer": "/version",
  "detect": [{"pointer": "/version", "equals": "1.1", "or_absent": true}],
  "fold": [{"from": "/items[]/items[]", "to": "/items[]"}],
  "records": [{"name": "result", "path": "/results[]", "kind": "finding"}],
  "tables": {
    "kind": {"match": "token", "map": {"notapplicable": "not_applicable", "pass": "pass"}},
    "level": {"match": "fold", "map": {"error": "high"}, "default": "medium"}
  },
  "hooks": ["demo.results"],
  "fields": [
    {"path": "/version", "target": "format check"},
    {"path": "/results", "target": "(container)"},
    {"path": "/results[]", "target": "findings[]", "hook": "demo.results"},
    {"path": "/results[]/title", "target": "title", "hook": "demo.results"},
    {"path": "/results[]/guid", "target": "correlation_id", "set": "correlation_id", "record": "result"},
    {"path": "/results[]/kind", "target": "kind", "set": "kind", "record": "result", "transform": ["table:kind"]},
    {"path": "/results[]/confidence", "target": "confidence", "set": "confidence", "record": "result"},
    {"path": "/results[]/loc/line", "target": "location.start_line", "set": "location.start_line", "record": "result"},
    {"path": "/results[]/help", "target": "references", "set": "rule_name", "record": "result", "transform": ["http_url"]},
    {"path": "/invocations", "ignored": "how the tool ran"},
    {"path": "/invocations/**", "ignored": "how the tool ran"},
    {"path": "/items", "target": "(container)"},
    {"path": "/items[]", "target": "(container)"},
    {"path": "/items[]/items", "target": "(container)"},
    {"path": "/items[]/name", "target": "dependencies[].name"}
  ]
}`

const testExport = `{
  "apiVersion": "openctem.io/interop/v1",
  "format": "demo",
  "version": "1.1",
  "direction": "export",
  "namespace": "org.ctis.interop.demo",
  "title": "Demo",
  "reemit_from": ["1.0"],
  "hooks": ["demo.out"],
  "fields": [
    {"path": "/version", "target": "version", "hook": "demo.out"},
    {"path": "/results", "target": "(container)"},
    {"path": "/results[]", "target": "findings", "hook": "demo.out"},
    {"path": "/results[]/title", "target": "title", "hook": "demo.out"}
  ]
}`

func loadImport(t *testing.T) *Mapping {
	t.Helper()
	m, err := Load([]byte(testImport), LoadOptions{Hooks: []string{"demo.results"}, Tables: []string{"level"}})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func loadExport(t *testing.T) *Mapping {
	t.Helper()
	m, err := Load([]byte(testExport), LoadOptions{Hooks: []string{"demo.out"}})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestLoad(t *testing.T) {
	m := loadImport(t)
	if !strings.HasPrefix(m.Digest(), "sha256:") {
		t.Fatalf("digest %q", m.Digest())
	}
	if f, ok := m.Match("/results[]/guid"); !ok || f.Set != "correlation_id" || !f.Mapped() {
		t.Fatalf("match: %+v %v", f, ok)
	}
	if f, ok := m.Match("/invocations/a/b"); !ok || f.Mapped() {
		t.Fatalf("ignored: %+v %v", f, ok)
	}
	if v, ok := m.Lookup("level", " ERROR "); !ok || v != "high" {
		t.Fatalf("lookup fold: %q %v", v, ok)
	}
	if v, ok := m.Lookup("level", "other"); !ok || v != "medium" {
		t.Fatalf("lookup default: %q %v", v, ok)
	}
	if _, ok := m.Lookup("kind", "x"); ok {
		t.Fatal("lookup without default must miss")
	}
	if got := m.Reverse("kind", "pass"); len(got) != 1 || got[0] != "pass" {
		t.Fatalf("reverse %v", got)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("Lookup of a missing table must panic")
		}
	}()
	m.Lookup("missing", "x")
}

func TestLoadRefuses(t *testing.T) {
	base := map[string]any{}
	if err := json.Unmarshal([]byte(testImport), &base); err != nil {
		t.Fatal(err)
	}
	mutate := func(f func(m map[string]any)) []byte {
		b, _ := json.Marshal(base)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		f(m)
		out, _ := json.Marshal(m)
		return out
	}
	field := func(m map[string]any, i int) map[string]any {
		return m["fields"].([]any)[i].(map[string]any)
	}
	cases := map[string][]byte{
		"not json":          []byte(`{`),
		"two values":        []byte(testImport + `{}`),
		"too large":         []byte(strings.Repeat(" ", MaxMappingBytes+1)),
		"unknown member":    mutate(func(m map[string]any) { m["extra"] = 1 }),
		"api version":       mutate(func(m map[string]any) { m["apiVersion"] = "v0" }),
		"format":            mutate(func(m map[string]any) { m["format"] = "De mo" }),
		"version":           mutate(func(m map[string]any) { m["version"] = "latest" }),
		"direction":         mutate(func(m map[string]any) { m["direction"] = "both" }),
		"namespace":         mutate(func(m map[string]any) { m["namespace"] = "demo" }),
		"title":             mutate(func(m map[string]any) { m["title"] = "" }),
		"unknown hook":      mutate(func(m map[string]any) { m["hooks"] = []string{"demo.results", "evil"} }),
		"unused hook":       mutate(func(m map[string]any) { field(m, 2)["hook"] = nil; field(m, 3)["hook"] = nil }),
		"field hook unlist": mutate(func(m map[string]any) { m["hooks"] = []string{} }),
		"missing table":     mutate(func(m map[string]any) { delete(m["tables"].(map[string]any), "level") }),
		"table key form": mutate(func(m map[string]any) {
			m["tables"].(map[string]any)["kind"].(map[string]any)["map"] = map[string]string{"Not_Applicable": "x"}
		}),
		"table match":        mutate(func(m map[string]any) { m["tables"].(map[string]any)["kind"].(map[string]any)["match"] = "regex" }),
		"duplicate field":    mutate(func(m map[string]any) { m["fields"] = append(m["fields"].([]any), field(m, 0)) }),
		"both target ign":    mutate(func(m map[string]any) { field(m, 0)["ignored"] = "x" }),
		"neither":            mutate(func(m map[string]any) { delete(field(m, 0), "target") }),
		"set outside record": mutate(func(m map[string]any) { field(m, 4)["path"] = "/guid" }),
		"set array below":    mutate(func(m map[string]any) { field(m, 4)["path"] = "/results[]/a[]/guid" }),
		"set reserved":       mutate(func(m map[string]any) { field(m, 4)["set"] = "asset_ref" }),
		"set unknown member": mutate(func(m map[string]any) { field(m, 4)["set"] = "no_such_member" }),
		"set object":         mutate(func(m map[string]any) { field(m, 4)["set"] = "location" }),
		"set list":           mutate(func(m map[string]any) { field(m, 4)["set"] = "tags" }),
		"set no record":      mutate(func(m map[string]any) { field(m, 4)["record"] = "nope" }),
		"bad transform":      mutate(func(m map[string]any) { field(m, 4)["transform"] = []string{"exec"} }),
		"bad table ref":      mutate(func(m map[string]any) { field(m, 4)["transform"] = []string{"table:nope"} }),
		"bad max bytes":      mutate(func(m map[string]any) { field(m, 4)["transform"] = []string{"max_bytes:0"} }),
		"transform w/o set":  mutate(func(m map[string]any) { field(m, 0)["transform"] = []string{"trim"} }),
		"detect two tests":   mutate(func(m map[string]any) { m["detect"].([]any)[0].(map[string]any)["prefix"] = "1" }),
		"detect bad re":      mutate(func(m map[string]any) { m["detect"] = []any{map[string]any{"pointer": "/v", "matches": "("}} }),
		"detect pointer":     mutate(func(m map[string]any) { m["detect"] = []any{map[string]any{"pointer": "v", "equals": "1"}} }),
		"fold widening":      mutate(func(m map[string]any) { m["fold"] = []any{map[string]any{"from": "/a", "to": "/a/b/c"}} }),
		"record kind":        mutate(func(m map[string]any) { m["records"].([]any)[0].(map[string]any)["kind"] = "report" }),
		"passthrough limit":  mutate(func(m map[string]any) { m["passthrough"] = map[string]any{"max_bytes": 1 << 30} }),
		"reemit on import":   mutate(func(m map[string]any) { m["reemit_from"] = []string{"1.0"} }),
		"version pointer":    mutate(func(m map[string]any) { m["version_pointer"] = "version" }),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(data, LoadOptions{Hooks: []string{"demo.results"}, Tables: []string{"level"}})
			if !errors.Is(err, ErrMapping) {
				t.Fatalf("want ErrMapping, got %v", err)
			}
		})
	}
	if _, err := Load([]byte(testExport), LoadOptions{}); err == nil {
		t.Fatal("export with an unregistered hook loaded")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("MustLoad must panic on a bad mapping")
		}
	}()
	MustLoad([]byte(`{}`), LoadOptions{})
}

func TestMatchPath(t *testing.T) {
	cases := []struct {
		pattern, path string
		match, below  bool
	}{
		{"/a/b", "/a/b", true, false},
		{"/a/*", "/a/xyz", true, false},
		{"/a/x*z", "/a/xyz", true, false},
		{"/a/**", "/a/b/c", true, true},
		{"/a/**/d", "/a/b/c/d", true, true},
		{"/a/b/c", "/a", false, true},
		{"/a/b[]/c", "/a/b", false, true},
		{"/a/b[]/c", "/a/b[]", false, true},
		{"/a/**", "/a", true, true},
		{"/x/y", "/a", false, false},
		{"/a", "/a/b", false, false},
	}
	for _, c := range cases {
		if got := MatchPath(c.pattern, c.path); got != c.match {
			t.Errorf("MatchPath(%s, %s) = %v", c.pattern, c.path, got)
		}
		if got := matchBelow(c.pattern, c.path); got != c.below {
			t.Errorf("matchBelow(%s, %s) = %v", c.pattern, c.path, got)
		}
	}
	if got := PathKey("a/b[0]\x01" + strings.Repeat("é", 100)); strings.ContainsAny(got, "/[]\x01") || len(got) > 128 {
		t.Errorf("PathKey = %q", got)
	}
	for in, want := range map[string]string{"/runs/0/results/3/x": "/runs[]/results[]/x", "/0/a": "/[]/a", "/a~1b/c": "/a_b/c", "": ""} {
		if got, ok := PointerPath(in); !ok || got != want {
			t.Errorf("PointerPath(%q) = %q %v, want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"a", "/a~2", "/" + strings.Repeat("a/", MaxPathSegments+1), "/\xff"} {
		if _, ok := PointerPath(bad); ok {
			t.Errorf("PointerPath(%q) accepted", bad)
		}
	}
}

func TestSelect(t *testing.T) {
	v10 := strings.Replace(testImport, `"version": "1.1",`, `"version": "1.0",`, 1)
	v10 = strings.Replace(v10, `{"pointer": "/version", "equals": "1.1", "or_absent": true}`, `{"pointer": "/version", "in": ["1.0", "0.9"]}, {"pointer": "/kind", "absent": true}`, 1)
	m10, err := Load([]byte(v10), LoadOptions{Hooks: []string{"demo.results"}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSet(m10, loadImport(t))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Versions(); len(got) != 2 || got[0] != "1.0" || s.Latest().Version != "1.1" {
		t.Fatalf("versions %v", got)
	}
	if _, ok := s.Version("1.0"); !ok {
		t.Fatal("Version(1.0)")
	}
	for doc, want := range map[string]string{
		`{"version": "1.1"}`:                               "1.1",
		`{"results": []}`:                                  "1.1",
		`{"version": "0.9", "x": [{"a": 1}]}`:              "1.0",
		`{"nested": {"version": "1.0"}, "version": "1.0"}`: "1.0",
	} {
		m, err := s.Select([]byte(doc))
		if err != nil || m.Version != want {
			t.Errorf("Select(%s) = %v, %v; want %s", doc, m, err, want)
		}
	}
	for _, doc := range []string{`{"version": "2.0"}`, `{"version": "1.0", "kind": "x"}`, `{"version": {"a": 1}}`, `{"version": {"a": null}, "kind": 1}`} {
		if _, err := s.Select([]byte(doc)); !errors.Is(err, ErrVersion) {
			t.Errorf("Select(%s): want ErrVersion, got %v", doc, err)
		}
	}
	if _, err := s.Select([]byte(strings.Repeat(`{"a":`, 100) + "1" + strings.Repeat("}", 100))); !errors.Is(err, ErrVersion) {
		t.Errorf("deep document: %v", err)
	}
	if _, err := NewSet(loadImport(t), loadImport(t)); err == nil {
		t.Fatal("set with a version twice")
	}
	if _, err := NewSet(loadImport(t), loadExport(t)); err == nil {
		t.Fatal("set with mixed directions")
	}
}

const testDoc = `{
  "version": "1.1",
  "tool": {"name": "x", "fullName": "Demo Scanner", "token": "s3cr3t-token-value"},
  "invocations": [{"commandLine": "scan --password hunter2"}],
  "items": [{"name": "a", "items": [{"name": "b", "license": "MIT"}]}],
  "results": [
    {"title": "one", "guid": "G-1", "kind": "Not_Applicable", "confidence": 70, "loc": {"line": 12}, "help": "https://example.com/r",
     "rank": 3.5, "hostedViewerUri": "javascript:alert(1)", "fixes": [{"description": {"text": "upgrade"}, "env": {"PATH": "/x"}}],
     "snippet": "password = \"hunter2hunter2\""},
    {"title": "two", "kind": "weird", "confidence": "high", "help": "file:///etc/passwd"}
  ]
}`

func TestCollectAndApply(t *testing.T) {
	m := loadImport(t)
	pt, err := m.Collect([]byte(testDoc))
	if err != nil {
		t.Fatal(err)
	}
	if pt.Version() != "1.1" || pt.Empty() {
		t.Fatalf("version %q empty %v", pt.Version(), pt.Empty())
	}
	doc := pt.DocExtension()
	un := doc["unmapped"].(map[string]any)
	if _, ok := un["/tool"]; !ok {
		t.Fatalf("doc unmapped: %v", un)
	}
	tool := un["/tool"].(map[string]any)
	if _, ok := tool["token"]; ok {
		t.Fatal("a credential member was kept")
	}
	if _, ok := un["/invocations"]; ok {
		t.Fatal("an ignored member was kept")
	}
	if _, ok := un["/items/0/items/0/license"]; !ok {
		t.Fatalf("fold: nested item member not kept: %v", un)
	}
	if _, ok := un["/items/0/items/0/name"]; ok {
		t.Fatal("fold: a listed nested member was kept")
	}

	var f ctis.Finding
	if err := pt.Apply("/results/0", &f); err != nil {
		t.Fatal(err)
	}
	if f.CorrelationID != "G-1" || f.Kind != "not_applicable" || f.Confidence != 70 || f.Location == nil || f.Location.StartLine != 12 || f.RuleName != "https://example.com/r" {
		t.Fatalf("set rules: %+v loc %+v", f, f.Location)
	}
	var g ctis.Finding
	_ = pt.Apply("/results/1", &g)
	if g.Kind != "" || g.Confidence != 0 || g.RuleName != "" {
		t.Fatalf("rejected values must leave members unset: %+v", g)
	}
	if err := pt.Apply("/results/0", &ctis.Asset{}); !errors.Is(err, ErrSetTarget) {
		t.Fatalf("wrong target type: %v", err)
	}
	if err := pt.Apply("/results/0", f); !errors.Is(err, ErrSetTarget) {
		t.Fatalf("non-pointer target: %v", err)
	}

	rec := pt.RecordExtension("/results/0", func(s string) string { return strings.ReplaceAll(s, "upgrade", "UP") })
	ru := rec["unmapped"].(map[string]any)
	if ru["/rank"] == nil {
		t.Fatalf("record unmapped: %v", ru)
	}
	if _, ok := ru["/hostedViewerUri"]; ok {
		t.Fatal("a javascript: URL was kept")
	}
	fixes, _ := json.Marshal(ru["/fixes"])
	if strings.Contains(string(fixes), "env") || !strings.Contains(string(fixes), `"UP"`) {
		t.Fatalf("fixes not scrubbed: %s", fixes)
	}
	snip, _ := ru["/snippet"].(string)
	if strings.Contains(snip, "hunter2hunter2") {
		t.Fatalf("credential in a kept string: %q", snip)
	}
	if pt.RecordExtension("/results/9", nil) != nil {
		t.Fatal("extension of an unknown record")
	}

	var ext ctis.Extensions
	m.Store(&ext, doc)
	m.Store(&ext, nil)
	if ext["org.ctis.interop.demo"]["version"] != "1.1" {
		t.Fatalf("store: %v", ext)
	}
	r := ctis.NewReport()
	r.Extensions = ext
	if raw, _ := json.Marshal(r.Extensions); len(raw) > ctis.MaxExtensionsBytes {
		t.Fatalf("extension too large: %d", len(raw))
	}
}

func TestCollectLimits(t *testing.T) {
	m := loadImport(t)
	var b strings.Builder
	b.WriteString(`{"version": "1.1"`)
	for i := 0; i < 500; i++ {
		b.WriteString(`, "m` + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + `_` + strings.Repeat("y", i) + `": "` + strings.Repeat("v", 200) + `"`)
	}
	b.WriteString(`, "deep": ` + strings.Repeat(`{"a":`, 40) + `1` + strings.Repeat(`}`, 40))
	b.WriteString(`, "big": "` + strings.Repeat("z", 64<<10) + `"}`)
	pt, err := m.Collect([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if pt.Dropped == 0 || !pt.Doc.Truncated {
		t.Fatalf("limits did not apply: dropped %d", pt.Dropped)
	}
	ext := pt.DocExtension()
	raw, _ := json.Marshal(ext)
	if len(raw) > DefaultLimits.MaxBytes+4096 || len(ext["unmapped"].(map[string]any)) > DefaultLimits.MaxEntries {
		t.Fatalf("doc passthrough unbounded: %d bytes", len(raw))
	}
	if ext["truncated"] != true {
		t.Fatal("truncated flag missing")
	}
	if _, ok := ext["unmapped"].(map[string]any)["/deep"]; ok {
		t.Fatal("a value deeper than MaxDepth was kept")
	}
	// Many records: at most MaxRecords keep members.
	var r strings.Builder
	r.WriteString(`{"results": [`)
	for i := 0; i < DefaultLimits.MaxRecords+5; i++ {
		if i > 0 {
			r.WriteString(",")
		}
		r.WriteString(`{"x": 1}`)
	}
	r.WriteString(`]}`)
	pt, err = m.Collect([]byte(r.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(pt.records) > DefaultLimits.MaxRecords || pt.Dropped == 0 {
		t.Fatalf("records %d dropped %d", len(pt.records), pt.Dropped)
	}
	// A deep value outside the listed members is dropped, not walked.
	if deep, err := m.Collect([]byte(strings.Repeat("[", 300) + strings.Repeat("]", 300))); err != nil || deep.Dropped == 0 || !deep.Empty() && deep.DocExtension()["unmapped"].(map[string]any)["/0"] != nil {
		t.Errorf("deep value: %v", err)
	}
	// A deep value inside a folded container is bounded too: either the
	// walk stops at its depth limit or the value is dropped.
	if pt, err := m.Collect([]byte(`{"items": [{"items": ` + strings.Repeat(`[{"items":`, 300) + "1" + strings.Repeat("}]", 300) + `}]}`)); err == nil {
		if raw, _ := json.Marshal(pt.DocExtension()); len(raw) > DefaultLimits.MaxBytes+1024 {
			t.Errorf("deep listed container kept %d bytes", len(raw))
		}
	} else if !errors.Is(err, ErrPassthrough) {
		t.Errorf("deep listed container: %v", err)
	}
	for _, bad := range []string{`{`, `{"a": ]}`} {
		if _, err := m.Collect([]byte(bad)); !errors.Is(err, ErrPassthrough) {
			t.Errorf("Collect(%.20s): %v", bad, err)
		}
	}
	empty, err := m.Collect([]byte(`{"version": "1.1", "results": [{"title": "t"}]}`))
	if err != nil || !empty.Empty() || empty.DocExtension() != nil {
		t.Fatalf("listed-only document kept something: %v", err)
	}
}

func TestKeptAndReemit(t *testing.T) {
	m := loadExport(t)
	ext := ctis.Extensions{"org.ctis.interop.demo": {"version": "1.0", "unmapped": map[string]any{
		"/extra":             map[string]any{"a": 1, "password": "p"},
		"/results/0/rank":    3,
		"/results/0/title":   "overwrite?",
		"/results/9/x":       1,
		"/version":           "9.9",
		"/meta/new/deep":     "created",
		"/items/0/x":         "no array to create",
		"not a pointer":      1,
		"/link/href":         "javascript:x",
		"/apiKey":            "k",
		"/results/0/props/u": "<b>&</b>",
	}}}
	version, entries, ok := m.Kept(ext)
	if !ok || version != "1.0" {
		t.Fatalf("kept: %v %v", version, ok)
	}
	for _, e := range entries {
		if e.Pointer == "not a pointer" || e.Pointer == "/apiKey" || e.Pointer == "/link/href" {
			t.Fatalf("Kept passed %q", e.Pointer)
		}
	}
	out := []byte("{\n  \"version\": \"1.1\",\n  \"results\": [\n    {\n      \"title\": \"t\"\n    }\n  ]\n}")
	got, dropped, err := m.Reemit(out, entries, "  ")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(got, &v); err != nil {
		t.Fatalf("%v: %s", err, got)
	}
	res := v["results"].([]any)[0].(map[string]any)
	if res["title"] != "t" || v["version"] != "1.1" {
		t.Fatalf("a mapped member was overwritten: %s", got)
	}
	if res["rank"] != float64(3) || v["meta"].(map[string]any)["new"].(map[string]any)["deep"] != "created" {
		t.Fatalf("kept members not written back: %s", got)
	}
	if _, ok := v["extra"].(map[string]any)["password"]; ok {
		t.Fatal("credential written back")
	}
	if _, ok := v["items"]; ok {
		t.Fatal("an array was created")
	}
	if dropped < 3 {
		t.Fatalf("dropped %d", dropped)
	}
	if !strings.Contains(string(got), "\"\\u003cb\\u003e\\u0026\\u003c/b\\u003e\"") || !strings.HasPrefix(string(got), "{\n  \"version\"") {
		t.Fatalf("encoding differs from encoding/json: %s", got)
	}
	same, n, err := m.Reemit(out, nil, "  ")
	if err != nil || n != 0 || string(same) != string(out) {
		t.Fatal("no entries must return the output unchanged")
	}
	if _, _, err := m.Reemit([]byte(`"scalar"`), entries, ""); !errors.Is(err, ErrReemit) {
		t.Fatalf("scalar output: %v", err)
	}
	if _, _, ok := m.Kept(ctis.Extensions{"org.ctis.interop.demo": {"version": "0.1"}}); ok {
		t.Fatal("a version the mapping does not re-emit from")
	}
	if _, _, ok := m.Kept(nil); ok {
		t.Fatal("nothing kept")
	}
	if got := Unindexed(entries); len(got) == 0 {
		t.Fatal("Unindexed dropped everything")
	} else {
		for _, e := range got {
			if strings.Contains(e.Pointer, "/0/") || strings.Contains(e.Pointer, "/9/") {
				t.Fatalf("indexed pointer %q", e.Pointer)
			}
		}
	}
	if !m.Owns("/results/0/title") || m.Owns("/results/0/rank") || !m.Owns("not a pointer") {
		t.Fatal("Owns")
	}
}

func TestFoldPath(t *testing.T) {
	m := loadImport(t)
	if got := m.FoldPath("/items[]/items[]/items[]/name"); got != "/items[]/name" {
		t.Fatalf("FoldPath = %q", got)
	}
	if got := m.FoldPath("/items[]/itemsX"); got != "/items[]/itemsX" {
		t.Fatalf("FoldPath = %q", got)
	}
}

func FuzzCollect(f *testing.F) {
	f.Add([]byte(testDoc))
	f.Add([]byte(`{"results":[{"guid":1,"kind":null,"loc":{"line":"x"}}]}`))
	m := MustLoad([]byte(testImport), LoadOptions{Hooks: []string{"demo.results"}})
	e := MustLoad([]byte(testExport), LoadOptions{Hooks: []string{"demo.out"}})
	f.Fuzz(func(t *testing.T, data []byte) {
		pt, err := m.Collect(data)
		if err != nil {
			return
		}
		var ext ctis.Extensions
		m.Store(&ext, pt.DocExtension())
		var fd ctis.Finding
		_ = pt.Apply("/results/0", &fd)
		if raw, err := json.Marshal(ext); err != nil || len(raw) > ctis.MaxExtensionsBytes {
			t.Fatalf("extension %d bytes, %v", len(raw), err)
		}
		_, entries, _ := e.Kept(ctis.Extensions{e.Namespace: {"version": "1.1", "unmapped": ext[m.Namespace]["unmapped"]}})
		if _, _, err := e.Reemit([]byte(`{"results":[{}]}`), entries, "  "); err != nil {
			t.Fatal(err)
		}
	})
}
