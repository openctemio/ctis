package importer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/openctemio/ctis"
)

func brParse(t *testing.T, in string, opts Options) *Result {
	t.Helper()
	if opts.Format == "" {
		opts.Format = FormatBountyReport
	}
	res, err := Parse(context.Background(), strings.NewReader(in), opts)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := res.Report.Validate(); err != nil {
		t.Fatalf("report is not valid CTIS: %v", err)
	}
	return res
}

func brProps(t *testing.T, f ctis.Finding) map[string]any {
	t.Helper()
	m, ok := f.Properties["bounty_report"].(map[string]any)
	if !ok {
		t.Fatalf("no bounty_report properties on %q", f.Title)
	}
	return m
}

func hasIssue(res *Result, sub string) bool {
	for _, is := range res.Issues {
		if strings.Contains(is.Message, sub) {
			return true
		}
	}
	return false
}

// Detect names the JSON shape, and only by the top-level member.
func TestDetect_BountyReport(t *testing.T) {
	for in, want := range map[string]bool{
		`{"bounty_reports": []}`:                               true,
		"\xEF\xBB\xBF {\"bounty_reports\": [{\"title\": \"x\"": true,
		`{"x": {"bounty_reports": []}}`:                        false,
		`{"findings": [{"bounty_reports": 1}]}`:                false,
		`[{"bounty_reports": []}]`:                             false,
		`report_ref,title` + "\n" + `a,b`:                      false,
		`{"bounty_report": []}`:                                false,
	} {
		got, ok := Detect([]byte(in))
		if (ok && got == FormatBountyReport) != want {
			t.Errorf("Detect(%.50q) = %q, %v; want bounty_report=%v", in, got, ok, want)
		}
	}
	// No other format's fixture is taken for this one, and ours is.
	for _, fx := range fixtures(t) {
		head, err := os.ReadFile(fx.path)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := Detect(head)
		switch {
		case fx.format == FormatBountyReport && strings.HasSuffix(fx.path, ".json"):
			if !ok || got != FormatBountyReport {
				t.Errorf("%s: detected %q, %v", fx.path, got, ok)
			}
		case fx.format == FormatBountyReport:
			if ok {
				t.Errorf("%s: CSV was detected as %q", fx.path, got)
			}
		case ok && got == FormatBountyReport:
			t.Errorf("%s was detected as bounty_report", fx.path)
		}
	}
}

// The members of findings[].properties.bounty_report are the contract with
// the platform: no other key is ever written, and the fixtures together
// exercise every one.
func TestBountyReport_PropertiesContract(t *testing.T) {
	allowed := map[string]bool{"intake": true, "ref": true, "researcher": true, "submitted_at": true, "reported_severity": true, "state": true, "weakness": true, "endpoint_path": true, "parameter": true, "url": true, "reward": true, "disclosure": true}
	sub := map[string]map[string]bool{"reward": {"amount": true, "currency": true, "status": true}, "disclosure": {"state": true, "agreed_date": true}}
	seen := map[string]bool{}
	for _, fx := range fixtures(t) {
		if fx.format != FormatBountyReport {
			continue
		}
		res, _ := runFixture(t, fx)
		for _, f := range res.Report.Findings {
			if len(f.Properties) != 1 {
				t.Errorf("%s: properties has keys beyond bounty_report: %v", f.Title, f.Properties)
			}
			if f.Tags != nil || f.References != nil {
				t.Errorf("%s: tags or references set", f.Title)
			}
			for k, v := range brProps(t, f) {
				if !allowed[k] {
					t.Errorf("unexpected property %q", k)
				}
				seen[k] = true
				if s, ok := sub[k]; ok {
					for k2 := range v.(map[string]any) {
						if !s[k2] {
							t.Errorf("unexpected property %s.%s", k, k2)
						}
						seen[k+"."+k2] = true
					}
				}
			}
		}
	}
	for k := range allowed {
		if !seen[k] {
			t.Errorf("no fixture exercises property %q", k)
		}
	}
	for k, s := range sub {
		for k2 := range s {
			if !seen[k+"."+k2] {
				t.Errorf("no fixture exercises property %s.%s", k, k2)
			}
		}
	}
}

func TestBountyReport_Mapping(t *testing.T) {
	in := `{"bounty_reports":[
	 {"report_ref":"R-1","intake":"Prog.One","title":"  A\n title ","submitted_at":"2026-01-02T03:04:05+02:00","reported_severity":"NONE","state":"Not-Applicable","asset":"https://Example.COM./a/b?q=1#f"},
	 {"report_ref":"R-2","title":"t2","reported_severity":"Moderate","asset":"2001:db8::1"},
	 {"report_ref":"R-3","title":"t3","asset":"ftp://example.com/x"},
	 {"report_ref":"R-4","title":"t4","asset":"javascript:alert(1)"},
	 {"report_ref":"R-5","title":"t5","asset":"my app (prod)"}
	]}`
	res := brParse(t, in, Options{BountyIntake: "Default-Intake"})
	fs := res.Report.Findings
	if len(fs) != 5 {
		t.Fatalf("findings = %d, issues %v", len(fs), res.Issues)
	}
	p := brProps(t, fs[0])
	if p["intake"] != "prog.one" || p["state"] != "not_applicable" || p["reported_severity"] != "none" || p["endpoint_path"] != "/a/b" || p["submitted_at"] != "2026-01-02T01:04:05Z" {
		t.Errorf("props = %v", p)
	}
	if fs[0].Title != "A title" || fs[0].Severity != ctis.SeverityInfo || fs[0].Native.Severity != "NONE" || fs[0].Native.Status != "Not-Applicable" {
		t.Errorf("finding = %+v native %+v", fs[0], fs[0].Native)
	}
	if res.Report.Assets[0].Value != "example.com" || res.Report.Assets[0].Type != ctis.AssetTypeDomain {
		t.Errorf("asset = %+v", res.Report.Assets[0])
	}
	// The default intake and a severity the source does not know.
	if brProps(t, fs[1])["intake"] != "default-intake" || fs[1].Severity != ctis.SeverityMedium {
		t.Errorf("finding 2 = %v", fs[1])
	}
	if _, ok := brProps(t, fs[1])["reported_severity"]; ok {
		t.Error("an unknown severity was kept")
	}
	var ip, app bool
	for _, a := range res.Report.Assets {
		ip = ip || (a.Type == ctis.AssetTypeIPAddress && a.Value == "2001:db8::1")
		app = app || (a.Type == ctis.AssetTypeWebApplication && a.Value == "my app (prod)")
	}
	if !ip || !app {
		t.Errorf("assets = %+v", res.Report.Assets)
	}
	// ftp and javascript assets are refused: the default asset takes them.
	for _, f := range fs[2:4] {
		var a ctis.Asset
		for _, x := range res.Report.Assets {
			if x.ID == f.AssetRef {
				a = x
			}
		}
		if a.Type != ctis.AssetTypeUnclassified {
			t.Errorf("%s: asset = %+v", f.Title, a)
		}
	}
}

func TestBountyReport_FingerprintAndIntake(t *testing.T) {
	a := brParse(t, `{"bounty_reports":[{"report_ref":"X","title":"t"}]}`, Options{})
	b := brParse(t, `{"bounty_reports":[{"report_ref":"X","title":"t","intake":"IMPORT"}]}`, Options{})
	c := brParse(t, `{"bounty_reports":[{"report_ref":"X","title":"t"}]}`, Options{BountyIntake: "other"})
	fa, fb, fc := a.Report.Findings[0].Fingerprint, b.Report.Findings[0].Fingerprint, c.Report.Findings[0].Fingerprint
	if fa != fb || fa == fc {
		t.Errorf("fingerprints %s %s %s", fa, fb, fc)
	}
	sum := sha256.Sum256([]byte("import\x00X"))
	if fa != "bounty_report:v1:"+hex.EncodeToString(sum[:]) {
		t.Errorf("fingerprint %s", fa)
	}
	if _, err := Parse(context.Background(), strings.NewReader(`{"bounty_reports":[]}`), Options{Format: FormatBountyReport, BountyIntake: "Bad Intake!"}); err == nil {
		t.Error("an invalid Options.BountyIntake was accepted")
	}
}

func TestBountyReport_FieldRules(t *testing.T) {
	cases := []struct {
		name, rec string
		skipped   bool
		issue     string
		absent    string // property that must be missing
	}{
		{"ref with space", `{"report_ref":"a b","title":"t"}`, true, "report_ref is not valid", ""},
		{"ref 129 chars", `{"report_ref":"` + strings.Repeat("a", 129) + `","title":"t"}`, true, "report_ref is not valid", ""},
		{"ref non ascii", `{"report_ref":"réf","title":"t"}`, true, "report_ref is not valid", ""},
		{"intake bad", `{"report_ref":"a","intake":"-x","title":"t"}`, true, "intake is not valid", ""},
		{"intake long", `{"report_ref":"a","intake":"` + strings.Repeat("a", 65) + `","title":"t"}`, true, "intake is not valid", ""},
		{"researcher long", `{"report_ref":"a","title":"t","researcher":"` + strings.Repeat("r", 65) + `"}`, false, "researcher is not valid", "researcher"},
		{"researcher newline", `{"report_ref":"a","title":"t","researcher":"a\nb"}`, false, "researcher is not valid", "researcher"},
		{"cwe lower", `{"report_ref":"a","title":"t","weakness":"cwe-79"}`, false, "weakness is not", "weakness"},
		{"cwe 7 digits", `{"report_ref":"a","title":"t","weakness":"CWE-1234567"}`, false, "weakness is not", "weakness"},
		{"state unknown", `{"report_ref":"a","title":"t","state":"banana"}`, false, "unknown state", "state"},
		{"time bad", `{"report_ref":"a","title":"t","submitted_at":"2026-01-02"}`, false, "submitted_at", "submitted_at"},
		{"amount 13 digits", `{"report_ref":"a","title":"t","reward":{"amount":"1234567890123"}}`, false, "reward amount", "reward"},
		{"amount 3 decimals", `{"report_ref":"a","title":"t","reward":{"amount":"1.234"}}`, false, "reward amount", "reward"},
		{"amount exponent", `{"report_ref":"a","title":"t","reward":{"amount":1e3}}`, false, "reward amount", "reward"},
		{"currency lower", `{"report_ref":"a","title":"t","reward":{"currency":"usd"}}`, false, "reward currency", "reward"},
		{"currency 4", `{"report_ref":"a","title":"t","reward":{"currency":"USDT"}}`, false, "reward currency", "reward"},
		{"reward status", `{"report_ref":"a","title":"t","reward":{"status":"owed"}}`, false, "reward status", "reward"},
		{"disclosure state", `{"report_ref":"a","title":"t","disclosure":{"state":"public"}}`, false, "disclosure state", "disclosure"},
		{"disclosure date", `{"report_ref":"a","title":"t","disclosure":{"agreed_date":"2026-13-40"}}`, false, "agreed_date", "disclosure"},
		{"cvss 2", `{"report_ref":"a","title":"t","cvss_vector":"AV:N/AC:L/Au:N/C:P/I:P/A:P"}`, false, "cvss_vector", ""},
		{"url relative", `{"report_ref":"a","title":"t","url":"/x"}`, false, "url is not", "url"},
		{"url 2049", `{"report_ref":"a","title":"t","url":"https://e.com/` + strings.Repeat("a", 2040) + `"}`, false, "url is not", "url"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := brParse(t, `{"bounty_reports":[`+c.rec+`]}`, Options{})
			if c.skipped != (len(res.Report.Findings) == 0) {
				t.Fatalf("findings = %d, issues %v", len(res.Report.Findings), res.Issues)
			}
			if !hasIssue(res, c.issue) {
				t.Errorf("no issue %q in %v", c.issue, res.Issues)
			}
			if c.skipped {
				if res.Stats.Skipped != 1 {
					t.Errorf("skipped = %d", res.Stats.Skipped)
				}
				return
			}
			if c.absent != "" {
				if _, ok := brProps(t, res.Report.Findings[0])[c.absent]; ok {
					t.Errorf("property %q was kept", c.absent)
				}
			}
			if f := res.Report.Findings[0]; c.name == "cvss 2" && len(f.Scores) != 0 {
				t.Errorf("scores = %v", f.Scores)
			}
		})
	}
}

func TestBountyReport_Description(t *testing.T) {
	res := brParse(t, `{"bounty_reports":[{"report_ref":"a","title":"t","description":"d","steps":"s","impact":"i"},{"report_ref":"b","title":"t","description":"d"}]}`, Options{})
	if got := res.Report.Findings[0].Description; got != "d\n\n## Steps to reproduce\n\ns\n\n## Impact\n\ni" {
		t.Errorf("description = %q", got)
	}
	if got := res.Report.Findings[1].Description; got != "d" {
		t.Errorf("description = %q", got)
	}
	big := strings.Repeat("x", 70<<10)
	res = brParse(t, `{"bounty_reports":[{"report_ref":"a","title":"t","description":"`+big+`","steps":"`+big+`","impact":"`+big+`"}]}`, Options{})
	d := res.Report.Findings[0].Description
	if n := len([]rune(d)); n > 64<<10+64<<10+16<<10+100 {
		t.Errorf("description has %d characters", n)
	}
	for _, w := range []string{"description is longer", "steps is longer", "impact is longer"} {
		if !hasIssue(res, w) {
			t.Errorf("no issue %q", w)
		}
	}
}

func TestBountyReport_CSV(t *testing.T) {
	res := brParse(t, "\xEF\xBB\xBFreport_ref,Title,reward_amount\nA,\"x, \"\"y\"\"\",12.5\nB,t2,\n", Options{})
	if len(res.Report.Findings) != 2 || res.Report.Findings[0].Title != `x, "y"` {
		t.Fatalf("findings = %+v issues %v", res.Report.Findings, res.Issues)
	}
	if rw := brProps(t, res.Report.Findings[0])["reward"].(map[string]any); rw["amount"] != "12.5" {
		t.Errorf("reward = %v", rw)
	}
	if _, ok := brProps(t, res.Report.Findings[1])["reward"]; ok {
		t.Error("an empty reward was kept")
	}
	// Columns the format does not know are listed as unmapped, never read.
	res = brParse(t, "report_ref,title,secret_note,reward_amount\nA,t,hello,1\n", Options{})
	if len(res.Unmapped) != 1 || res.Unmapped[0] != "/bounty_reports[]/secret_note" || strings.Contains(fmt.Sprint(res.Report.Findings), "hello") {
		t.Errorf("unmapped = %v", res.Unmapped)
	}
	for name, in := range map[string]string{
		"empty":           "",
		"no title column": "report_ref\nA\n",
		"duplicate col":   "report_ref,title,title\nA,b,c\n",
		"short row":       "report_ref,title\nA\n",
		"long row":        "report_ref,title\nA,b,c\n",
		"bare quote":      "report_ref,title\nA,b\"c\n",
		"open quote":      "report_ref,title\nA,\"b\n",
		"json array":      `[{"report_ref":"a"}]`,
		"bad utf8":        "report_ref,title\nA,\xff\n",
	} {
		_, err := Parse(context.Background(), strings.NewReader(in), Options{Format: FormatBountyReport})
		wantKind(t, err, ErrMalformed)
		_ = name
	}
	// A JSON file without the array is malformed too.
	_, err := Parse(context.Background(), strings.NewReader(`{"x":1}`), Options{Format: FormatBountyReport})
	wantKind(t, err, ErrMalformed)
}

func TestBountyReport_FormatListed(t *testing.T) {
	var names []string
	for _, f := range AllFormats() {
		names = append(names, string(f))
	}
	if !sort.StringsAreSorted(names) || !FormatBountyReport.IsValid() || !strings.Contains(strings.Join(names, ","), "bounty_report") {
		t.Errorf("formats = %v", names)
	}
	if _, err := os.Stat(filepath.Join("..", "docs", "importers", "bounty_report.md")); err != nil {
		t.Error(err)
	}
}
