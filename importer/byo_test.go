package importer

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"
)

// The formats of tools a person runs and imports (nmap, testssl.sh, line
// lists, CTIS files): detection, scope verdicts and hostile input.

func TestDetect_PersonRunFormats(t *testing.T) {
	cases := map[string]struct {
		in   string
		want Format
	}{
		"nmap":           {`<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun scanner="nmap"></nmaprun>`, FormatNmap},
		"testssl flat":   {`[{"id":"TLS1","ip":"a.example.com/192.0.2.1","port":"443","severity":"LOW","finding":"offered"}]`, FormatTestssl},
		"testssl pretty": {`{"Invocation":"testssl.sh x","at":"h","version":"3.2","scanResult":[]}`, FormatTestssl},
		"ctis":           {`{"version":"2.0","$schema":"https://schemas.openctem.io/ctis/2.0/report.json","metadata":{},"findings":[]}`, FormatCTIS},
		"ctis no schema": {`{"version":"2.1","metadata":{"id":"x"},"assets":[]}`, FormatCTIS},
		// A DefectDojo file has findings and no CTIS version.
		"defectdojo": {`{"findings":[{"title":"x","severity":"High"}]}`, FormatDefectDojo},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok := Detect([]byte(c.in))
			if !ok || got != c.want {
				t.Fatalf("Detect = %q, %v; want %q", got, ok, c.want)
			}
		})
	}
	// A line list is never detected: any text would match.
	if f, ok := Detect([]byte("www.example.com\n192.0.2.1\n")); ok {
		t.Fatalf("a line list was detected as %q", f)
	}
}

func TestNmap_RefusesEntitiesAndOtherRoots(t *testing.T) {
	for name, in := range map[string]string{
		"xxe":        `<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///etc/passwd">]><nmaprun><host><address addr="&x;" addrtype="ipv4"/></host></nmaprun>`,
		"other root": `<?xml version="1.0"?><report><host/></report>`,
		"no root":    `<?xml version="1.0"?>`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseString(t, in, Options{Format: FormatNmap}); err == nil {
				t.Fatal("parsed")
			}
		})
	}
}

func TestNmap_ScriptOutputAndArgsNeverKept(t *testing.T) {
	in := `<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap --script-args http.useragent=x,creds.global=admin:Secr3t 192.0.2.5" version="7.95">
<host><status state="up"/><address addr="192.0.2.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/><script id="http-title" output="Secr3t admin panel"/></port></ports></host></nmaprun>`
	res, err := parseString(t, in, Options{Format: FormatNmap, ScopeDomains: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	raw := mustJSON(t, res.Report)
	if strings.Contains(raw, "Secr3t") {
		t.Fatalf("the report holds the script arguments or output: %s", raw)
	}
	if len(res.Report.Findings) != 0 {
		t.Fatalf("nmap made findings: %+v", res.Report.Findings)
	}
	if got := scopeOf(res.Report, ctis.AssetTypeIPAddress, "192.0.2.5"); got != scopeUnknown {
		t.Fatalf("an address is %q, want unknown (the receiver judges addresses)", got)
	}
}

func TestTestssl_SeverityAndMinimum(t *testing.T) {
	in := `[
{"id":"TLS1","ip":"a.example.com/192.0.2.1","port":"443","severity":"LOW","finding":"offered"},
{"id":"heartbleed","ip":"a.example.com/192.0.2.1","port":"443","severity":"CRITICAL","cve":"CVE-2014-0160","finding":"VULNERABLE"},
{"id":"TLS1_3","ip":"a.example.com/192.0.2.1","port":"443","severity":"OK","finding":"offered"},
{"id":"overall_grade","ip":"a.example.com/192.0.2.1","port":"443","severity":"CRITICAL","finding":"F"},
{"id":"bogus","ip":"a.example.com/192.0.2.1","port":"443","severity":"SEVERE","finding":"x"},
{"id":"noport","ip":"a.example.com/192.0.2.1","port":"0","severity":"HIGH","finding":"x"}
]`
	res, err := parseString(t, in, Options{Format: FormatTestssl, MinSeverity: ctis.SeverityMedium, ScopeDomains: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Findings) != 1 || res.Report.Findings[0].RuleID != "heartbleed" {
		t.Fatalf("findings = %+v, want heartbleed only (LOW below the minimum, OK and the grade are not findings)", res.Report.Findings)
	}
	f := res.Report.Findings[0]
	if f.Type != ctis.FindingTypeVulnerability || f.Severity != ctis.SeverityCritical || f.Native.Severity != "CRITICAL" {
		t.Fatalf("finding = %+v", f)
	}
	if res.Stats.Skipped != 3 {
		t.Fatalf("skipped = %d, want 3 (below the minimum, unknown severity, no endpoint)", res.Stats.Skipped)
	}
	if got := scopeOf(res.Report, ctis.AssetTypeDomainName, "a.example.com"); got != scopeInTarget {
		t.Fatalf("a.example.com is %q, want in_target", got)
	}
}

func TestLines_Kinds(t *testing.T) {
	in := "www.example.com\n192.0.2.1\nhttps://u:p@app.example.com/a?token=abc\n198.51.100.0/24\nother.example.org.\n"
	cases := map[string]struct {
		as   string
		want map[ctis.AssetType]int
	}{
		"auto":   {LinesAsAuto, map[ctis.AssetType]int{ctis.AssetTypeDomainName: 2, ctis.AssetTypeIPAddress: 1, ctis.AssetTypeIPRange: 1, ctis.AssetTypeWebOrigin: 1}},
		"host":   {LinesAsHost, map[ctis.AssetType]int{ctis.AssetTypeDomainName: 2, ctis.AssetTypeIPAddress: 1}},
		"domain": {LinesAsDomain, map[ctis.AssetType]int{ctis.AssetTypeDomainName: 2}},
		"ip":     {LinesAsIP, map[ctis.AssetType]int{ctis.AssetTypeIPAddress: 1, ctis.AssetTypeIPRange: 1}},
		"url":    {LinesAsURL, map[ctis.AssetType]int{ctis.AssetTypeWebOrigin: 1}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			res, err := parseString(t, in, Options{Format: FormatLines, LinesAs: c.as, ScopeDomains: []string{"example.com"}})
			if err != nil {
				t.Fatal(err)
			}
			got := map[ctis.AssetType]int{}
			for _, a := range res.Report.Assets {
				got[a.Type]++
			}
			if mustJSON(t, got) != mustJSON(t, c.want) {
				t.Fatalf("assets = %v, want %v", got, c.want)
			}
			raw := mustJSON(t, res.Report)
			if strings.Contains(raw, "u:p@") || strings.Contains(raw, "abc") {
				t.Fatalf("credentials or a query value reached the report: %s", raw)
			}
		})
	}
	if _, err := parseString(t, in, Options{Format: FormatLines, LinesAs: "everything"}); err == nil {
		t.Fatal("an unknown LinesAs was accepted")
	}
	res, err := parseString(t, in, Options{Format: FormatLines, ScopeDomains: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := scopeOf(res.Report, ctis.AssetTypeDomainName, "other.example.org"); got != scopeOutsideTarget {
		t.Fatalf("other.example.org is %q, want outside_target", got)
	}
}

func TestLines_HostileLines(t *testing.T) {
	in := "ok.example.com\nbad\x00.example.com\n\x1b[31mred.example.com\n" + strings.Repeat("a", 70<<10) + ".example.com\n\xff\xfe.example.com\njavascript:alert(1)\n"
	res, err := parseString(t, in, Options{Format: FormatLines})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Assets) != 1 || res.Report.Assets[0].Value != "ok.example.com" {
		t.Fatalf("assets = %+v, want ok.example.com only", res.Report.Assets)
	}
	if res.Stats.Skipped != 5 {
		t.Fatalf("skipped = %d, want 5", res.Stats.Skipped)
	}
	if _, err := parseString(t, strings.Repeat("a.example.com\n", 100), Options{Format: FormatLines, Limits: Limits{MaxInputBytes: 64}}); err == nil {
		t.Fatal("an input over MaxInputBytes was read")
	} else {
		wantKind(t, err, ErrTooLarge)
	}
}

func TestCTIS_ProducerCannotClaimScopeOrVerification(t *testing.T) {
	in := `{"version":"2.0","metadata":{"id":"019a2b3c-4d5e-7ede-9f59-abaa8f9477a8","generated_at":"2026-10-02T12:00:00Z","channel":"scanner"},
"tool":{"name":"acme-scan","version":"1.0"},
"extensions":{"io.openctem":{"coverage":"x"}},
"assets":[{"id":"a1","type":"domain_name","value":"evil.example.net","extensions":{"io.openctem":{"import_scope":"in_target","candidate_exposure":"none"}}}],
"findings":[{"id":"f1","type":"vulnerability","title":"t","severity":"critical","asset_ref":"a1",
 "validation":{"status":"exploited"},"extensions":{"io.openctem":{"candidate_unverified":false}}}]}`
	res, err := parseString(t, in, Options{Format: FormatCTIS, ScopeDomains: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := scopeOf(res.Report, ctis.AssetTypeDomainName, "evil.example.net"); got != scopeOutsideTarget {
		t.Fatalf("the producer's in_target survived: %q", got)
	}
	a := res.Report.Assets[0]
	if _, ok := a.Extensions.Get(ctis.OpenCTEMNamespace, "candidate_exposure"); ok {
		t.Fatal("the producer's candidate_exposure survived")
	}
	if len(res.Report.Findings) != 1 {
		t.Fatalf("findings = %d", len(res.Report.Findings))
	}
	f := res.Report.Findings[0]
	if f.Validation != nil || f.Extensions[ctis.OpenCTEMNamespace] != nil {
		t.Fatalf("the finding kept a verification claim or the receiver profile: %+v", f)
	}
	if res.Report.Metadata.Channel != ctis.ChannelManual || res.Report.Metadata.ID == "019a2b3c-4d5e-7ede-9f59-abaa8f9477a8" {
		t.Fatalf("the document's own id or channel was kept: %+v", res.Report.Metadata)
	}
	if res.Report.Tool == nil || res.Report.Tool.Name != "acme-scan" {
		t.Fatalf("tool = %+v", res.Report.Tool)
	}
}

func TestCTIS_StrictDecode(t *testing.T) {
	for name, in := range map[string]string{
		"unknown member": `{"version":"2.0","metadata":{"id":"x","generated_at":"2026-10-02T12:00:00Z"},"surprise":1}`,
		"other major":    `{"version":"1.6","metadata":{}}`,
		"trailing data":  `{"version":"2.0","metadata":{"id":"x","generated_at":"2026-10-02T12:00:00Z"}} {}`,
		"deep nesting":   `{"version":"2.0","metadata":{},"properties":` + strings.Repeat(`{"a":`, 200) + `1` + strings.Repeat(`}`, 200) + `}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseString(t, in, Options{Format: FormatCTIS}); err == nil {
				t.Fatal("parsed")
			}
		})
	}
}

func scopeOf(r *ctis.Report, t ctis.AssetType, v string) any {
	for _, a := range r.Assets {
		if a.Type == t && a.Value == v {
			got, _ := a.Extensions.Get(ctis.OpenCTEMNamespace, extImportScope)
			return got
		}
	}
	return "<missing>"
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
