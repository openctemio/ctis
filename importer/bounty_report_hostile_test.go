package importer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openctemio/ctis"
)

// Hostile bounty reports. The importer keeps every text as data: it never
// renders, resolves or follows anything, so a record that carries markup, a
// URL to an internal address or a bidi override must come out as inert text
// (or be dropped with an issue), and the parse must open no connection.

func jstr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func brOne(fields string) string {
	return `{"bounty_reports":[{"report_ref":"R-1","title":"t",` + fields + `}]}`
}

const bidi = "\u202e"

func hasBidiOrControl(s string) bool {
	for _, r := range s {
		if isBidi(r) || (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f {
			return true
		}
	}
	return false
}

// allStrings walks a decoded value and calls fn on every string in it.
func allStrings(v any, fn func(string)) {
	switch x := v.(type) {
	case string:
		fn(x)
	case map[string]any:
		for _, e := range x {
			allStrings(e, fn)
		}
	case ctis.Properties:
		for _, e := range x {
			allStrings(e, fn)
		}
	case []string:
		for _, e := range x {
			fn(e)
		}
	}
}

func TestBountyReport_MarkupStaysData(t *testing.T) {
	payloads := []string{
		`<script>alert(1)</script>`,
		`<img src=x onerror=alert(document.cookie)>`,
		`<svg onload=alert(1)></svg>`,
		`[x](javascript:alert(1))`,
		`![](http://169.254.169.254/latest/meta-data/)`,
	}
	for _, p := range payloads {
		in := brOne(`"title":` + jstr("T "+p) + `,"description":` + jstr("D "+p) + `,"steps":` + jstr("S "+p) + `,"impact":` + jstr("I "+p))
		res := brParse(t, strings.Replace(in, `"title":"t",`, "", 1), Options{})
		f := res.Report.Findings[0]
		// Kept byte for byte (it is data), and never turned into a link.
		for _, got := range []string{f.Title, f.Description} {
			if !strings.Contains(got, p) {
				t.Errorf("%q: markup was altered: %q", p, got)
			}
		}
		if len(f.References) != 0 || f.Web != nil || len(f.EvidenceItems) != 0 {
			t.Errorf("%q: a link-like member was set: %+v", p, f)
		}
	}
}

func TestBountyReport_URLs(t *testing.T) {
	bad := []string{
		"http://169.254.169.254/", "file:///etc/passwd", "gopher://127.0.0.1:6379/_", "javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>", "https://user:pass@example.com/r/1", "ftp://example.com/",
		"/relative/path", "//example.com/x", "https:///nohost", "https://exa mple.com/", "https://example.com/\u202e",
		"https:example.com", "https://example.com/" + strings.Repeat("a", 2049),
	}
	for _, u := range bad {
		res := brParse(t, brOne(`"url":`+jstr(u)), Options{})
		if _, ok := brProps(t, res.Report.Findings[0])["url"]; ok {
			t.Errorf("url %.40q was kept", u)
		}
		if !hasIssue(res, "url is not an https URL") {
			t.Errorf("url %.40q: no issue", u)
		}
	}
	res := brParse(t, brOne(`"url":"https://example.com/r/1?x=1#y","asset":"https://example.com/r/1"`), Options{})
	f := res.Report.Findings[0]
	if brProps(t, f)["url"] != "https://example.com/r/1?x=1#y" || len(f.References) != 0 {
		t.Errorf("props = %v references = %v", f.Properties, f.References)
	}
}

func TestBountyReport_AssetCredentialsAndSchemes(t *testing.T) {
	res := brParse(t, brOne(`"asset":"http://user:pass@internal.example.com/a?b=c#frag"`), Options{})
	f := res.Report.Findings[0]
	a := res.Report.Assets[0]
	if a.Value != "internal.example.com" || brProps(t, f)["endpoint_path"] != "/a" || !hasIssue(res, "credentials") {
		t.Errorf("asset = %+v props = %v issues = %v", a, f.Properties, res.Issues)
	}
	whole, _ := json.Marshal(res.Report)
	for _, s := range []string{"user:", "pass", "secret", "b=c", "frag"} {
		if strings.Contains(string(whole), s) {
			t.Errorf("%q survived in %s", s, whole)
		}
	}
	for _, in := range []string{"file:///etc/passwd", "gopher://127.0.0.1:6379/_", "javascript:alert(1)", "data:text/html,x", "http://", "https://:80/"} {
		res := brParse(t, brOne(`"asset":`+jstr(in)), Options{})
		if got := res.Report.Assets[0]; got.Type != ctis.AssetTypeUnclassified {
			t.Errorf("asset %q became %+v", in, got)
		}
		if len(res.Issues) == 0 {
			t.Errorf("asset %q: no issue", in)
		}
	}
	// An application id is kept on one line, at most 255 characters.
	res = brParse(t, brOne(`"asset":`+jstr("app\n"+strings.Repeat("x", 400))), Options{})
	if a := res.Report.Assets[0]; a.Type != ctis.AssetTypeWebApplication || len([]rune(a.Value)) > 255 || strings.ContainsAny(a.Value, "\n") {
		t.Errorf("asset = %+v", a)
	}
}

func TestBountyReport_BidiAndControl(t *testing.T) {
	// A title and a parameter are cleaned.
	res := brParse(t, `{"bounty_reports":[{"report_ref":"R-1","title":`+jstr("ev"+bidi+"il\x00 \x01title\u200f\u2066")+`,"parameter":`+jstr("p"+bidi+"q\x07")+`,"description":`+jstr("a\x00b\r\nc\td\x1b[31m"+bidi)+`}]}`, Options{})
	f := res.Report.Findings[0]
	if f.Title != "evil title" || brProps(t, f)["parameter"] != "pq" || f.Description != "ab\nc\td[31m" {
		t.Errorf("title %q parameter %v description %q", f.Title, brProps(t, f)["parameter"], f.Description)
	}
	// An identity with such a character is invalid, not cleaned.
	res = brParse(t, `{"bounty_reports":[{"report_ref":`+jstr("R"+bidi+"1")+`,"title":"t"},{"report_ref":"R-2","intake":`+jstr("a"+bidi+"b")+`,"title":"t"},{"report_ref":"R-3","title":"t","researcher":`+jstr("al"+bidi+"ice")+`},{"report_ref":"R-4\u0000","title":"t"}]}`, Options{})
	if len(res.Report.Findings) != 1 || res.Report.Findings[0].Native.InstanceID != "R-3" {
		t.Fatalf("findings = %d, issues %v", len(res.Report.Findings), res.Issues)
	}
	if _, ok := brProps(t, res.Report.Findings[0])["researcher"]; ok || !hasIssue(res, "researcher is not valid") {
		t.Error("a researcher with a bidi override was kept")
	}
	// Nothing of any report carries a bidi or control character.
	for _, in := range []string{brOne(`"description":` + jstr("x\x00\u202a\u2069\u200e")), brOne(`"state":"new\u0000"`)} {
		res := brParse(t, in, Options{})
		raw, _ := json.Marshal(res.Report)
		var v any
		_ = json.Unmarshal(raw, &v)
		allStrings(v, func(s string) {
			if hasBidiOrControl(s) {
				t.Errorf("control or bidi character in %q", s)
			}
		})
	}
}

func TestBountyReport_Sizes(t *testing.T) {
	// A 10 MiB description: the library refuses a string over MaxTextBytes
	// (8 MiB by default); with a bigger text limit it is cut at 64 KiB.
	huge := brOne(`"description":"` + strings.Repeat("A", 10<<20) + `"`)
	_, err := Parse(context.Background(), strings.NewReader(huge), Options{Format: FormatBountyReport})
	wantKind(t, err, ErrTooLarge)
	res, err := Parse(context.Background(), strings.NewReader(huge), Options{Format: FormatBountyReport, Limits: Limits{MaxTextBytes: 16 << 20}})
	if err != nil {
		t.Fatal(err)
	}
	if n := len([]rune(res.Report.Findings[0].Description)); n > 64<<10 || !hasIssue(res, "description is longer than 64 KiB") {
		t.Errorf("description has %d characters; issues %v", n, res.Issues)
	}
	if err := res.Report.Validate(); err != nil {
		t.Error(err)
	}
	// The whole file over MaxInputBytes.
	_, err = Parse(context.Background(), strings.NewReader(huge), Options{Format: FormatBountyReport, Limits: Limits{MaxTextBytes: 16 << 20, MaxInputBytes: 1 << 20}})
	wantKind(t, err, ErrTooLarge)
	_, err = Parse(context.Background(), strings.NewReader("report_ref,title\n"+strings.Repeat("a,b\n", 1<<18)), Options{Format: FormatBountyReport, Limits: Limits{MaxInputBytes: 1 << 20}})
	wantKind(t, err, ErrTooLarge)
	// Too many records.
	_, err = Parse(context.Background(), strings.NewReader("report_ref,title\na,b\nc,d\ne,f\n"), Options{Format: FormatBountyReport, Limits: Limits{MaxFindings: 2}})
	wantKind(t, err, ErrTooLarge)
	// A 1000-character report_ref, and a 1000-character title.
	res = brParse(t, `{"bounty_reports":[{"report_ref":"`+strings.Repeat("r", 1000)+`","title":"t"},{"report_ref":"ok","title":"`+strings.Repeat("t", 1000)+`"}]}`, Options{})
	if len(res.Report.Findings) != 1 || len([]rune(res.Report.Findings[0].Title)) != capTitle || !hasIssue(res, "report_ref is not valid") {
		t.Errorf("findings %d issues %v", len(res.Report.Findings), res.Issues)
	}
}

func TestBountyReport_CSVCellsAreData(t *testing.T) {
	in := "report_ref,title,researcher,description,parameter\n" +
		"1,=cmd|' /C calc'!A0,+evil,-2+3,@SUM(1+1)\n" +
		"2,\"=1+1\",-x,\"+line1\n-line2\",=p\n"
	res := brParse(t, in, Options{})
	if len(res.Report.Findings) != 2 {
		t.Fatalf("findings = %d, issues %v", len(res.Report.Findings), res.Issues)
	}
	f := res.Report.Findings[0]
	if f.Title != "=cmd|' /C calc'!A0" || f.Description != "-2+3" || brProps(t, f)["parameter"] != "@SUM(1+1)" || brProps(t, f)["researcher"] != "+evil" {
		t.Errorf("finding = %+v props %v", f, f.Properties)
	}
	if res.Report.Findings[1].Description != "+line1\n-line2" {
		t.Errorf("description = %q", res.Report.Findings[1].Description)
	}
}

func TestBountyReport_DuplicatesAndMissing(t *testing.T) {
	res := brParse(t, `{"bounty_reports":[
		{"report_ref":"A","title":"first"},{"report_ref":"A","title":"second"},{"report_ref":"A","intake":"other","title":"other intake"},
		{"title":"no ref"},{"report_ref":"B"},{"report_ref":"C","title":"   "},{"report_ref":"D","title":"ok","reward":"lots"},"text",null,[]]}`, Options{})
	var titles []string
	for _, f := range res.Report.Findings {
		titles = append(titles, f.Title)
	}
	if strings.Join(titles, "|") != "first|other intake" {
		t.Errorf("titles = %v; issues %v", titles, res.Issues)
	}
	for _, w := range []string{"repeated", "without a report_ref", "without a title", "wrong type"} {
		if !hasIssue(res, w) {
			t.Errorf("no issue %q in %v", w, res.Issues)
		}
	}
	if res.Stats.Records != 10 || res.Stats.Findings != 2 || res.Stats.Skipped != 8 {
		t.Errorf("stats = %+v", res.Stats)
	}
}

// --- nothing leaves the process ------------------------------------------

type countingTransport struct{ n *atomic.Int64 }

func (c countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.n.Add(1)
	return nil, errors.New("outbound request refused by the test")
}

// TestBountyReport_NoOutboundRequests parses every fixture and every hostile
// input with the default HTTP transport and the default resolver replaced by
// ones that count their use and fail; both counters must stay at zero.
func TestBountyReport_NoOutboundRequests(t *testing.T) {
	var httpCalls, dnsCalls atomic.Int64
	oldT, oldR := http.DefaultTransport, net.DefaultResolver
	http.DefaultTransport = countingTransport{&httpCalls}
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		dnsCalls.Add(1)
		return nil, errors.New("lookup refused by the test")
	}}
	defer func() { http.DefaultTransport, net.DefaultResolver = oldT, oldR }()

	inputs := map[string]string{}
	for _, fx := range fixtures(t) {
		if fx.format == FormatBountyReport {
			b, err := os.ReadFile(fx.path)
			if err != nil {
				t.Fatal(err)
			}
			inputs[fx.path] = string(b)
		}
	}
	urls := []string{"http://169.254.169.254/", "file:///etc/passwd", "gopher://127.0.0.1:6379/_", "javascript:alert(1)", "data:text/html,x", "https://user:pass@example.com/r/1", "https://metadata.internal/latest", "http://[::1]:8080/"}
	for i, u := range urls {
		inputs[fmt.Sprintf("url-%d", i)] = brOne(`"url":` + jstr(u) + `,"asset":` + jstr(u) + `,"description":` + jstr("![]("+u+") [x]("+u+") <img src="+u+">"))
	}
	inputs["bare-hosts"] = brOne(`"asset":"does-not-exist.invalid"`)
	inputs["bare-ip"] = brOne(`"asset":"10.0.0.1"`)
	inputs["csv"] = "report_ref,title,url,asset\nA,t,https://example.com/,https://localhost/x\n"

	for name, in := range inputs {
		res, err := Parse(context.Background(), strings.NewReader(in), Options{Format: FormatBountyReport, Now: fixedNow})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// No reference or property value is a followable URL.
		raw, _ := json.Marshal(res.Report)
		var v any
		_ = json.Unmarshal(raw, &v)
		for _, f := range res.Report.Findings {
			var vals []string
			vals = append(vals, f.References...)
			allStrings(f.Properties, func(s string) { vals = append(vals, s) })
			for _, s := range vals {
				ls := strings.ToLower(s)
				for _, p := range []string{"http://", "file:", "gopher:", "javascript:", "data:"} {
					if strings.HasPrefix(ls, p) {
						t.Errorf("%s: %q is kept as a reference or property", name, s)
					}
				}
			}
			if len(f.References) != 0 {
				t.Errorf("%s: references = %v", name, f.References)
			}
		}
	}
	if httpCalls.Load() != 0 || dnsCalls.Load() != 0 {
		t.Fatalf("outbound activity: %d HTTP requests, %d resolver dials", httpCalls.Load(), dnsCalls.Load())
	}
	if len(inputs) < 10 {
		t.Fatal("the inputs were not read")
	}
}
