package mapping

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"
)

// doc builds a mapping with one rule.
func doc(source, each, rule string) string {
	e := ""
	if each != "" {
		e = fmt.Sprintf(`"each": %q,`, each)
	}
	return fmt.Sprintf(`{"apiVersion": "openctem.io/mapping/v2", "source": %q, %s "records": [%s]}`, source, e, rule)
}

const assetRule = `{"kind": "asset", "set": {"type": {"const": "ip_address"}, "value": "/ip"}}`

func mustLoad(t *testing.T, s string) *Mapping {
	t.Helper()
	m, err := Load([]byte(s))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return m
}

func apply(t *testing.T, m *Mapping, in string, opts Options) (*ctis.Report, Stats) {
	t.Helper()
	if opts.Now == nil {
		opts.Now = fixedNow
	}
	r, st, err := m.Apply(context.Background(), strings.NewReader(in), opts)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return r, st
}

func TestLoadRefusals(t *testing.T) {
	big := strings.Repeat(" ", MaxMappingBytes+1)
	rules := make([]string, MaxRules+1)
	for i := range rules {
		rules[i] = assetRule
	}
	var sets []string
	for i := 0; i <= MaxSetsPerRule; i++ {
		sets = append(sets, fmt.Sprintf(`"properties.k%d": "/x"`, i))
	}
	var preds []string
	for i := 0; i <= MaxPredicates; i++ {
		preds = append(preds, `{"path": "/x", "exists": true}`)
	}
	var in []string
	for i := 0; i <= MaxInValues; i++ {
		in = append(in, fmt.Sprintf("%q", fmt.Sprint(i)))
	}
	mapEntries := make([]string, MaxMapEntries+1)
	for i := range mapEntries {
		mapEntries[i] = fmt.Sprintf(`"k%d": "v"`, i)
	}
	setRule := func(set string) string {
		return doc("jsonl", "", `{"kind": "asset", "set": {"type": {"const": "ip_address"}, "value": "/ip", `+set+`}}`)
	}
	whenRule := func(when string) string {
		return doc("jsonl", "", `{"when": `+when+`, "kind": "asset", "set": {"type": {"const": "ip_address"}, "value": "/ip"}}`)
	}
	cases := map[string]struct{ in, want string }{
		"too big":              {big, "bytes, more than"},
		"too deep":             {strings.Repeat("[", 40), "nested deeper"},
		"not json":             {"{", "mapping:"},
		"unknown member":       {`{"apiVersion": "openctem.io/mapping/v2", "source": "jsonl", "records": [], "x": 1}`, "unknown field"},
		"trailing":             {doc("jsonl", "", assetRule) + " {}", "trailing data"},
		"api version":          {`{"apiVersion": "v2", "source": "jsonl", "records": [` + assetRule + `]}`, "apiVersion"},
		"source":               {doc("yaml", "", assetRule), "source \"yaml\""},
		"xml without each":     {doc("xml", "", assetRule), "source xml needs each"},
		"xml each relative":    {doc("xml", "a/b", assetRule), "starts with / or //"},
		"xml each bad name":    {doc("xml", "/a/1b", assetRule), "element name"},
		"xml each deep any":    {doc("xml", "//a/b", assetRule), "one element name"},
		"each on csv":          {doc("csv", "/a", assetRule), "each is for source json or xml"},
		"each on jsonl":        {doc("jsonl", "/a", assetRule), "each is for source json or xml"},
		"each malformed":       {doc("json", "a", assetRule), "starts with /"},
		"no records":           {`{"apiVersion": "openctem.io/mapping/v2", "source": "jsonl", "records": []}`, "records is empty"},
		"too many rules":       {doc("jsonl", "", strings.Join(rules, ",")), "records rules"},
		"kind":                 {doc("jsonl", "", `{"kind": "event", "set": {"x": "/x"}}`), "kind \"event\""},
		"empty set":            {doc("jsonl", "", `{"kind": "asset", "set": {}}`), "set is empty"},
		"too many sets":        {setRule(strings.Join(sets, ",")), "members, at most"},
		"too many preds":       {whenRule("[" + strings.Join(preds, ",") + "]"), "predicates, at most"},
		"missing type":         {doc("jsonl", "", `{"kind": "asset", "set": {"value": "/ip"}}`), "must set \"type\""},
		"finding severity":     {doc("jsonl", "", `{"kind": "finding", "set": {"title": "/t"}}`), "must set \"severity\""},
		"dependency name":      {doc("jsonl", "", `{"kind": "dependency", "set": {"version": "/v"}}`), "must set \"name\""},
		"bad asset type":       {doc("jsonl", "", `{"kind": "asset", "set": {"type": {"const": "email"}, "value": "/v"}}`), "not a CTIS asset type"},
		"unknown target":       {setRule(`"technical.domain.registrar_name": "/x"`), "no member"},
		"target segment":       {setRule(`"Properties.x": "/x"`), "segment"},
		"forbidden id":         {setRule(`"id": "/x"`), "set by the report builder"},
		"forbidden link":       {doc("jsonl", "", `{"kind": "finding", "set": {"title": "/t", "severity": "/s", "asset_ref": "/a"}}`), "set by the report builder"},
		"metadata":             {setRule(`"metadata.source_type": "/x"`), "no member"},
		"object target":        {setRule(`"technical.domain": "/x"`), "members of an object"},
		"list of objects":      {setRule(`"owners": "/x"`), "lists of strings"},
		"below list":           {setRule(`"owners.ref": "/x"`), "below a slice"},
		"map two levels":       {setRule(`"properties.a.b": "/x"`), "one key below"},
		"map no key":           {setRule(`"properties": "/x"`), "one key below"},
		"overlap":              {doc("jsonl", "", `{"kind": "finding", "set": {"title": "/t", "severity": "/s", "network": "/n", "network.host": "/h"}}`), "members of an object"},
		"overlap prefix":       {setRule(`"technical.domain.registrar": "/x", "technical.domain.registrar.x": "/y"`), "below a string"},
		"pred two ops":         {whenRule(`{"path": "/x", "exists": true, "equals": "a"}`), "exactly one of"},
		"pred no op":           {whenRule(`{"path": "/x"}`), "exactly one of"},
		"pred path":            {whenRule(`{"path": "x", "exists": true}`), "starts with /"},
		"pred equals obj":      {whenRule(`{"path": "/x", "equals": {"a": 1}}`), "equals takes"},
		"pred in empty":        {whenRule(`{"path": "/x", "in": []}`), "in takes 1 to"},
		"pred in too many":     {whenRule(`{"path": "/x", "in": [` + strings.Join(in, ",") + `]}`), "in takes 1 to"},
		"pred in obj":          {whenRule(`{"path": "/x", "in": [{}]}`), "in takes strings"},
		"pred regex long":      {whenRule(`{"path": "/x", "matches": "` + strings.Repeat("a", MaxRegexLen+1) + `"}`), "longer than"},
		"pred regex bad":       {whenRule(`{"path": "/x", "matches": "(("}`), "matches:"},
		"pred unknown":         {whenRule(`{"path": "/x", "like": "a"}`), "unknown field"},
		"value two sources":    {setRule(`"name": {"path": "/a", "const": "b"}`), "exactly one of path"},
		"value no source":      {setRule(`"name": {"lower": true}`), "exactly one of path"},
		"value unknown":        {setRule(`"name": {"path": "/a", "eval": "x"}`), "unknown field"},
		"const object":         {setRule(`"name": {"const": {"a": 1}}`), "const takes"},
		"const list mixed":     {setRule(`"tags": {"const": ["a", 1]}`), "const takes"},
		"default object":       {setRule(`"name": {"path": "/a", "default": {}}`), "default takes"},
		"lower upper":          {setRule(`"name": {"path": "/a", "lower": true, "upper": true}`), "lower and upper"},
		"as":                   {setRule(`"name": {"path": "/a", "as": "float"}`), "as \"float\""},
		"max bytes":            {setRule(`"name": {"path": "/a", "max_bytes": 2000000}`), "max_bytes"},
		"separator":            {setRule(`"name": {"path": "/a", "split": "` + strings.Repeat(",", 17) + `"}`), "separators"},
		"map entries":          {setRule(`"name": {"path": "/a", "map": {` + strings.Join(mapEntries, ",") + `}}`), "map has more"},
		"vars no template":     {setRule(`"name": {"path": "/a", "vars": {"a": "/a"}}`), "vars without a template"},
		"template undeclared":  {setRule(`"name": {"template": "{a}", "vars": {}}`), "not in vars"},
		"template unused":      {setRule(`"name": {"template": "{a}", "vars": {"a": "/a", "b": "/b"}}`), "not used"},
		"template open":        {setRule(`"name": {"template": "{a", "vars": {"a": "/a"}}`), "{ without }"},
		"template close":       {setRule(`"name": {"template": "a}", "vars": {}}`), "} without {"},
		"template close first": {setRule(`"name": {"template": "}{a}", "vars": {"a": "/a"}}`), "} without {"},
		"template name":        {setRule(`"name": {"template": "{A-b}", "vars": {"A-b": "/a"}}`), "variable name"},
		"template long":        {setRule(`"name": {"template": "` + strings.Repeat("a", MaxTemplateBytes+1) + `"}`), "template longer"},
		"template var path":    {setRule(`"name": {"template": "{a}", "vars": {"a": "a"}}`), "vars.a"},
		"value path":           {setRule(`"name": "a/b"`), "starts with /"},
		"path index":           {setRule(`"name": "/a[01]"`), "index"},
		"path bracket":         {setRule(`"name": "/a]"`), "unbalanced"},
		"path inner bracket":   {setRule(`"name": "/a[0]b"`), "inside a member name"},
		"path empty step":      {setRule(`"name": "/a//b"`), "empty step"},
		"path long":            {setRule(`"name": "/` + strings.Repeat("a", 520) + `"`), "longer than 512"},
		"path steps":           {setRule(`"name": "` + strings.Repeat("/a", 33) + `"`), "more than 32 steps"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load([]byte(tc.in))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestDigestIsCanonical(t *testing.T) {
	a := mustLoad(t, `{"apiVersion": "openctem.io/mapping/v2", "source": "jsonl", "records": [{"kind": "asset", "set": {"value": "/ip", "type": {"const": "ip_address"}}}]}`)
	b := mustLoad(t, "{\n  \"records\": [{\"set\": {\"type\": {\"const\": \"ip_address\"},\n \"value\": \"/ip\"}, \"kind\": \"asset\"}],\n  \"source\": \"jsonl\", \"apiVersion\": \"openctem.io/mapping/v2\"}")
	if a.Digest() != b.Digest() || !strings.HasPrefix(a.Digest(), "sha256:") || len(a.Digest()) != 71 {
		t.Fatalf("%s vs %s", a.Digest(), b.Digest())
	}
	c := mustLoad(t, doc("jsonl", "", `{"kind": "asset", "set": {"value": "/addr", "type": {"const": "ip_address"}}}`))
	if c.Digest() == a.Digest() {
		t.Fatal("a change of content keeps the digest")
	}
	if a.Source() != "jsonl" {
		t.Fatal(a.Source())
	}
}

func TestTransforms(t *testing.T) {
	m := mustLoad(t, doc("jsonl", "", `{"kind": "asset", "set": {
		"type": {"const": "ip_address"},
		"value": {"path": "/ip", "trim": true},
		"name": {"path": "/names", "first": true, "upper": true},
		"tags": {"path": "/csv", "split": ";", "lower": true, "map": {"a": "alpha", "b": "beta"}},
		"description": {"path": "/list", "join": " | ", "max_bytes": 9},
		"confidence": {"path": "/conf", "as": "integer"},
		"is_internet_accessible": {"path": "/public", "as": "boolean"},
		"criticality": {"path": "/crit", "default": "low"},
		"properties.single": {"path": "/scalar", "first": true},
		"properties.as_string": {"path": "/num", "as": "string"},
		"properties.idx": "/arr/1",
		"properties.idx2": "/arr[0]",
		"properties.objkey": "/obj/0",
		"properties.esc": "/a~1b",
		"properties.empty_list": {"path": "/none", "first": true, "default": "d"}
	}}`))
	in := `{"ip": "  192.0.2.1 ", "names": ["host-a", "host-b"], "csv": "A; b; c;", "list": ["one", 2, true, {"x":1}, ""],` +
		` "conf": "75", "public": "true", "scalar": "s", "num": 12, "arr": ["x", "y"], "obj": {"0": "zero"}, "a/b": "slash", "none": []}`
	r, st := apply(t, m, in, Options{})
	if st.Assets != 1 {
		t.Fatalf("stats %+v", st)
	}
	a := r.Assets[0]
	p := a.Properties
	checks := map[string]bool{
		"value":       a.Value == "192.0.2.1",
		"name":        a.Name == "HOST-A",
		"tags":        strings.Join(a.Tags, ",") == "alpha,beta",
		"description": a.Description == "one | 2 |",
		"confidence":  a.Confidence == 75,
		"public":      a.IsInternetAccessible != nil && *a.IsInternetAccessible,
		"criticality": a.Criticality == "low",
		"single":      p["single"] == "s",
		"as_string":   p["as_string"] == "12",
		"idx":         p["idx"] == "y",
		"idx2":        p["idx2"] == "x",
		"objkey":      p["objkey"] == "zero",
		"esc":         p["esc"] == "slash",
		"empty_list":  p["empty_list"] == "d",
	}
	for k, ok := range checks {
		if !ok {
			t.Errorf("%s: %+v", k, a)
		}
	}
}

func TestIntegerAndBooleanConversion(t *testing.T) {
	for in, want := range map[string]any{
		`"42"`: int64(42), `42.0`: int64(42), `-3`: int64(-3), `"x"`: nil, `42.5`: nil,
		`9007199254740993`: nil, `1e300`: nil, `true`: nil, `[1]`: nil,
	} {
		v, err := compileValue(ValueSpec{Path: "/v", As: "integer"})
		if err != nil {
			t.Fatal(err)
		}
		rec, _ := decodeValue([]byte(`{"v": ` + in + `}`))
		got, ok := v.eval(rec)
		if want == nil {
			if ok {
				t.Errorf("%s: got %v", in, got)
			}
			continue
		}
		if !ok || fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s: got %v", in, got)
		}
	}
	v, _ := compileValue(ValueSpec{Path: "/v", As: "boolean"})
	for in, ok := range map[string]bool{`"yes"`: false, `"1"`: true, `false`: true, `{}`: false} {
		rec, _ := decodeValue([]byte(`{"v": ` + in + `}`))
		if _, got := v.eval(rec); got != ok {
			t.Errorf("boolean %s: %v", in, got)
		}
	}
	s, _ := compileValue(ValueSpec{Path: "/v", As: "string"})
	rec, _ := decodeValue([]byte(`{"v": [1]}`))
	if _, ok := s.eval(rec); ok {
		t.Error("a list is not a string")
	}
	m, _ := compileValue(ValueSpec{Path: "/v", Map: map[string]string{"a": "b"}})
	rec, _ = decodeValue([]byte(`{"v": "z"}`))
	if _, ok := m.eval(rec); ok {
		t.Error("an unmapped value without default is missing")
	}
}

func TestPredicates(t *testing.T) {
	m := mustLoad(t, doc("jsonl", "", `
		{"when": {"path": "/kind", "equals": "host"}, "kind": "asset", "set": {"type": {"const": "host"}, "value": "/v"}},
		{"when": [{"path": "/n", "in": [1, 2]}, {"path": "/up", "equals": true}], "kind": "asset", "set": {"type": {"const": "ip_address"}, "value": "/v"}},
		{"when": {"path": "/v", "matches": "^[a-z]+\\.example\\.com$"}, "kind": "asset", "set": {"type": {"const": "domain_name"}, "value": "/v"}},
		{"when": {"path": "/gone", "exists": false}, "kind": "asset", "set": {"type": {"const": "domain_name"}, "value": "/v"}},
		{"when": {"path": "/obj", "equals": "x"}, "kind": "asset", "set": {"type": {"const": "ip_range"}, "value": "/v"}}`))
	in := strings.Join([]string{
		`{"kind": "host", "v": "h1", "gone": 1}`,
		`{"n": 2, "up": true, "v": "192.0.2.1", "gone": null}`,
		`{"n": 3, "up": true, "v": "x", "gone": 1}`,
		`{"v": "a.example.com"}`,
		`{"obj": {"a": 1}, "v": "y", "gone": 1}`,
		`["not", "an", "object"]`,
	}, "\n")
	r, st := apply(t, m, in, Options{})
	var got []string
	for _, a := range r.Assets {
		got = append(got, string(a.Type)+"="+a.Value)
	}
	// The same name from two rules is one asset; an address is no domain name.
	want := "host=h1,ip_address=192.0.2.1,domain_name=a.example.com"
	if strings.Join(got, ",") != want {
		t.Fatalf("got %v (stats %+v)", got, st)
	}
}

func TestSecretFindingsAreRedacted(t *testing.T) {
	m := mustLoad(t, doc("jsonl", "", `{"kind": "finding", "set": {
		"type": {"const": "secret"}, "title": {"template": "Secret {s} in code", "vars": {"s": "/secret"}},
		"severity": {"const": "high"}, "rule_id": "/rule", "location.path": "/file", "location.snippet": "/line",
		"secret.masked_value": "/secret"}}`))
	raw := "AKIAIOSFODNN7EXAMPLE"
	r, _ := apply(t, m, `{"rule": "aws", "file": "a.env", "line": "key=`+raw+`", "secret": "`+raw+`"}`, Options{})
	if len(r.Findings) != 1 {
		t.Fatal("finding")
	}
	f := r.Findings[0]
	for _, s := range []string{f.Title, f.Location.Snippet, f.Secret.MaskedValue} {
		if strings.Contains(s, raw) {
			t.Fatalf("raw secret kept: %q", s)
		}
	}
}

func TestHostileInput(t *testing.T) {
	m := mustLoad(t, doc("jsonl", "", `{"kind": "finding", "set": {"title": "/t", "severity": {"const": "low"}, "evidence": "/e", "rule_id": "/r"}}`))
	in := `{"t": "a\u0000b\u001b[2Jc\nd e", "e": "x\ty\nz\u0007", "r": "` + strings.Repeat("r", 5000) + `"}`
	r, _ := apply(t, m, in, Options{})
	f := r.Findings[0]
	if f.Title != "ab[2Jc de" || evidenceText(f) != "x\ty\nz" || len(f.RuleID) != shortTextBytes {
		t.Fatalf("%q %q %d", f.Title, evidenceText(f), len(f.RuleID))
	}
	long := mustLoad(t, doc("jsonl", "", `{"kind": "finding", "set": {"title": {"const": "t"}, "severity": {"const": "low"}, "evidence": "/e"}}`))
	r, _ = apply(t, long, `{"e": "`+strings.Repeat("é", 40000)+`"}`, Options{})
	if e := evidenceText(r.Findings[0]); len(e) > longTextBytes || !strings.HasPrefix(e, "éé") || strings.ContainsRune(e, '�') {
		t.Fatalf("evidence %d bytes", len(e))
	}
	// A deep line is skipped, the next one is read.
	asset := mustLoad(t, doc("jsonl", "", assetRule))
	_, st := apply(t, asset, strings.Repeat("[", 100)+"\n"+`{"ip": "192.0.2.1"}`, Options{})
	if st.Assets != 1 || st.Skipped != 1 || !strings.Contains(st.Issues[0].Message, "nested deeper") {
		t.Fatalf("%+v", st)
	}
	// Issue messages are one clean bounded line even when they quote input.
	when := mustLoad(t, doc("jsonl", "", `{"kind": "asset", "set": {"type": {"const": "ip_address"}, "value": "/v", "first_seen_at": "/d"}}`))
	_, st = apply(t, when, `{"v": "192.0.2.1", "d": "\u001b[31m`+strings.Repeat("\\n", 400)+`"}`, Options{})
	if msg := st.Issues[0].Message; len(msg) > 300 || strings.ContainsAny(msg, "\n\x1b") {
		t.Fatalf("issue %q", msg)
	}
}

func TestLimits(t *testing.T) {
	m := mustLoad(t, doc("jsonl", "", assetRule))
	lines := strings.Repeat(`{"ip": "192.0.2.1"}`+"\n", 10)

	if _, _, err := m.Apply(context.Background(), strings.NewReader(lines), Options{MaxInputBytes: 50}); !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("input cap: %v", err)
	}
	_, st := apply(t, m, lines, Options{MaxRecords: 3})
	if st.Records != 3 || !st.Truncated || st.Assets != 3 {
		t.Fatalf("record cap: %+v", st)
	}
	_, st = apply(t, m, lines, Options{MaxOutputs: 2})
	if st.Assets != 2 || !st.Truncated {
		t.Fatalf("output cap: %+v", st)
	}
	long := `{"ip": "` + strings.Repeat("1", 200) + `"}` + "\n" + `{"ip": "192.0.2.9"}`
	_, st = apply(t, m, long, Options{MaxRecordBytes: 100})
	if st.Assets != 1 || st.Skipped != 1 || !strings.Contains(st.Issues[0].Message, "longer than 100") {
		t.Fatalf("line cap: %+v", st)
	}
	bad := strings.Repeat("x\n", 50)
	_, st = apply(t, m, bad, Options{MaxIssues: 4})
	if len(st.Issues) != 4 || st.Skipped != 50 {
		t.Fatalf("issue cap: %+v", st)
	}
	_, st = apply(t, m, strings.Repeat("y", 300), Options{MaxRecordBytes: 100, MaxRecords: 1})
	if !st.Truncated {
		t.Fatalf("a too long line counts as a record: %+v", st)
	}
	// Canceled before reading.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := m.Apply(ctx, strings.NewReader(lines), Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}

func TestJSONSource(t *testing.T) {
	m := mustLoad(t, doc("json", "/data/items", assetRule))
	r, st := apply(t, m, `{"data": {"items": [{"ip": "192.0.2.1"}, {"ip": ""}, 5]}}`, Options{})
	if len(r.Assets) != 1 || st.Records != 3 || st.Skipped != 2 {
		t.Fatalf("%+v", st)
	}
	if _, st := apply(t, m, `{"data": {}}`, Options{}); len(st.Issues) != 1 || !strings.Contains(st.Issues[0].Message, "each path") {
		t.Fatalf("missing each: %+v", st)
	}
	if _, _, err := m.Apply(context.Background(), strings.NewReader(`{"data": {"items": {"ip": "x"}}}`), Options{}); !errors.Is(err, ErrNotAList) {
		t.Fatalf("not a list: %v", err)
	}
	for _, in := range []string{`{"data": `, `{} {}`, strings.Repeat("[", 70) + strings.Repeat("]", 70)} {
		if _, _, err := m.Apply(context.Background(), strings.NewReader(in), Options{}); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	if _, _, err := m.Apply(context.Background(), strings.NewReader(`{"data": {"items": []}}`), Options{MaxInputBytes: 5}); !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("json input cap: %v", err)
	}
	// Without each, an object is one record and an array is a list.
	whole := mustLoad(t, doc("json", "", assetRule))
	if r, _ := apply(t, whole, `{"ip": "192.0.2.1"}`, Options{}); len(r.Assets) != 1 {
		t.Fatal("object")
	}
	if r, _ := apply(t, whole, `[{"ip": "192.0.2.1"}, {"ip": "192.0.2.2"}]`, Options{}); len(r.Assets) != 2 {
		t.Fatal("array")
	}
}

func TestToolIsFromOptionsOnly(t *testing.T) {
	m := mustLoad(t, doc("jsonl", "", assetRule))
	tool := &ctis.Tool{Name: "acme", Techniques: []ctis.Technique{ctis.TechniqueEASM}}
	r, _ := apply(t, m, `{"ip": "192.0.2.1", "tool": "other"}`, Options{Tool: tool})
	tool.Techniques[0] = ctis.TechniqueDAST
	if r.Tool == nil || r.Tool.Name != "acme" || r.Tool.Techniques[0] != ctis.TechniqueEASM {
		t.Fatalf("%+v", r.Tool)
	}
	if r2, _ := apply(t, m, `{"ip": "192.0.2.1"}`, Options{}); r2.Tool != nil {
		t.Fatal("no tool unless given")
	}
}

func TestDependenciesAndDecodeFailures(t *testing.T) {
	m := mustLoad(t, doc("jsonl", "", `{"kind": "dependency", "set": {"name": "/n", "version": "/v", "licenses": "/l"}},
		{"kind": "finding", "set": {"title": {"const": "t"}, "severity": "/sev", "confidence": "/c"}},
		{"kind": "asset", "set": {"type": {"const": "unclassified"}, "value": "/n", "confidence": "/c"}}`))
	r, st := apply(t, m, `{"n": "lodash", "v": "4.17.0", "l": ["MIT"], "sev": "high", "c": 50}
{"n": " ", "sev": "nope", "c": "x"}
{"n": "a", "l": "MIT", "sev": "low", "c": 500}`, Options{})
	// One license as a string is a one-item list: the third dependency is
	// kept.
	if len(r.Dependencies) != 2 || len(r.Findings) != 1 || len(r.Assets) != 2 || st.Skipped != 5 {
		t.Fatalf("%+v %+v", r, st)
	}
	if s := st.Issues[0].String(); !strings.Contains(s, "record 2, rule 0") {
		t.Fatal(s)
	}
	if s := (Issue{Record: 1, Rule: -1, Message: "m"}).String(); s != "record 1: m" {
		t.Fatal(s)
	}
}

func TestCheckDepthIgnoresStrings(t *testing.T) {
	if err := checkDepth([]byte(`{"a": "[[[[[[[[[[\"[[["}`), 2); err != nil {
		t.Fatal(err)
	}
	if err := checkDepth([]byte(`[[[`), 2); err == nil {
		t.Fatal("depth")
	}
}

func TestPathGet(t *testing.T) {
	rec, _ := decodeValue([]byte(`{"a": [{"b": 1}], "s": "x"}`))
	for p, ok := range map[string]bool{"/a/0/b": true, "/a[0]/b": true, "/a/1": false, "/a/x": false, "/s/x": false, "/": true, "/nope": false} {
		pp, err := parsePath(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, got := pp.get(rec); got != ok {
			t.Errorf("%s: %v", p, got)
		}
	}
}

// evidenceText is the text of the raw_text evidence items of a finding.
func evidenceText(f ctis.Finding) string {
	var parts []string
	for _, it := range f.EvidenceItems {
		if it.Kind == ctis.EvidenceKindRawText {
			parts = append(parts, it.Text)
		}
	}
	return strings.Join(parts, "\n")
}

func TestV1MappingIsRefused(t *testing.T) {
	_, err := Load([]byte(`{"apiVersion": "openctem.io/mapping/v1", "source": "jsonl", "records": [` + assetRule + `]}`))
	if err == nil || !strings.Contains(err.Error(), "rewrite the mapping for CTIS 2.0") {
		t.Fatalf("v1 mapping: %v", err)
	}
}

func TestFindingAssetAndIDs(t *testing.T) {
	m := mustLoad(t, doc("jsonl", "", `{"kind": "finding", "set": {"title": "/t", "severity": {"const": "low"}, "asset_value": "/a", "asset_type": {"path": "/k", "default": ""}, "vulnerability.ids": "/ids"}}`))
	in := `{"t": "x", "a": "Host.Example.com.", "k": "", "ids": ["cve-2024-0001", "GHSA-cfgh-jmpq-rvwx", "RHSA-2024:1"]}` + "\n" +
		`{"t": "y", "a": "Host.Example.com", "k": "ip_address"}` + "\n" +
		`{"t": "z", "a": "bad value with spaces", "k": "domain_name"}` + "\n" +
		`{"t": "w"}` + "\n"
	r, st := apply(t, m, in, Options{ReportID: "0192f0a0-0000-7000-8000-000000000001"})
	if len(r.Findings) != 2 || st.Skipped != 2 {
		t.Fatalf("findings %d, stats %+v", len(r.Findings), st)
	}
	f := r.Findings[0]
	if len(r.Assets) != 2 || r.Assets[0].Type != ctis.AssetTypeDomainName || r.Assets[0].Value != "host.example.com" || f.AssetRef != r.Assets[0].ID {
		t.Fatalf("assets %+v, finding asset_ref %q", r.Assets, f.AssetRef)
	}
	if f.Vulnerability == nil || len(f.Vulnerability.IDs) != 3 || ctis.CVEs(f.Vulnerability)[0] != "CVE-2024-0001" {
		t.Fatalf("ids %+v", f.Vulnerability)
	}
	if r.Metadata.ID != "0192f0a0-0000-7000-8000-000000000001" {
		t.Fatalf("metadata.id %q", r.Metadata.ID)
	}
	// Findings that name no asset go to the default asset.
	d, _ := apply(t, mustLoad(t, doc("jsonl", "", `{"kind": "finding", "set": {"title": "/t", "severity": {"const": "low"}}}`)), `{"t": "x"}`, Options{DefaultAsset: &ctis.Asset{Type: ctis.AssetTypeRepository, Value: "github.com/example/app"}})
	if len(d.Assets) != 1 || d.Assets[0].Value != "github.com/example/app" || d.Findings[0].AssetRef != d.Assets[0].ID {
		t.Fatalf("default asset: %+v", d.Assets)
	}
	if _, _, err := m.Apply(context.Background(), strings.NewReader(in), Options{Now: fixedNow, ReportID: "not-a-uuid"}); err == nil {
		t.Error("an invalid ReportID was accepted")
	}
}
