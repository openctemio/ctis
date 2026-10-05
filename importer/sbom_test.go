package importer

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/openctemio/ctis"
)

// Hostile and edge-case input for the CycloneDX, SPDX and OSV importers.

const cdxHead = `{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:x","version":1,`

func TestCycloneDX_DeepNesting(t *testing.T) {
	in := cdxHead + `"components":` + strings.Repeat(`[{"name":"a","components":`, 200) + `[]` + strings.Repeat(`}]`, 200) + `}`
	_, err := parseString(t, in, Options{})
	wantKind(t, err, ErrTooLarge)
}

func TestCycloneDX_Limits(t *testing.T) {
	var comps []string
	for i := 0; i < 20; i++ {
		comps = append(comps, `{"bom-ref":"c`+strings.Repeat("x", i)+`","name":"c"}`)
	}
	in := cdxHead + `"metadata":{"component":{"name":"app","type":"application"}},"components":[` + strings.Join(comps, ",") + `]}`
	_, err := parseString(t, in, Options{Limits: Limits{MaxComponents: 5}})
	wantKind(t, err, ErrTooLarge)

	var vulns []string
	for i := 0; i < 20; i++ {
		vulns = append(vulns, `{"id":"CVE-2024-000`+string(rune('0'+i%10))+`","analysis":{"state":"not_affected","detail":"x"},"affects":[{"ref":"pkg:npm/a@1"}]}`)
	}
	in = cdxHead + `"vulnerabilities":[` + strings.Join(vulns, ",") + `]}`
	_, err = parseString(t, in, Options{Limits: Limits{MaxStatements: 5}})
	wantKind(t, err, ErrTooLarge)
}

func TestCycloneDX_WrongTypeHasLine(t *testing.T) {
	in := "{\n\"bomFormat\": \"CycloneDX\",\n\"version\": \"one\"\n}"
	_, err := parseString(t, in, Options{})
	p := wantKind(t, err, ErrMalformed)
	if p.Line != 3 {
		t.Errorf("line = %d, want 3", p.Line)
	}
}

func TestCycloneDX_InvalidUTF8HasLine(t *testing.T) {
	in := "{\n\"bomFormat\": \"CycloneDX\",\n\"components\": [{\"name\": \"\xff\"}]\n}"
	_, err := parseString(t, in, Options{Format: FormatCycloneDX})
	p := wantKind(t, err, ErrMalformed)
	if p.Line != 3 {
		t.Errorf("line = %d, want 3", p.Line)
	}
}

func TestCycloneDX_NotCycloneDX(t *testing.T) {
	_, err := parseString(t, `{"bomFormat":"SPDX"}`, Options{Format: FormatCycloneDX})
	wantKind(t, err, ErrMalformed)
}

// Cycles and self references in the graph are kept as plain references; a
// component never depends on itself, and a ref collision keeps the first.
func TestCycloneDX_CyclesAndCollisions(t *testing.T) {
	in := cdxHead + `"metadata":{"component":{"bom-ref":"app","name":"app"}},
	"components":[{"bom-ref":"a","name":"a"},{"bom-ref":"b","name":"b"},{"bom-ref":"a","name":"evil"}],
	"dependencies":[{"ref":"a","dependsOn":["b","a"]},{"ref":"b","dependsOn":["a"]},{"ref":"app","dependsOn":["a"]}]}`
	res, err := parseString(t, in, Options{})
	if err != nil {
		t.Fatal(err)
	}
	deps := res.Report.Dependencies
	if len(deps) != 2 || deps[0].Name != "a" {
		t.Fatalf("dependencies = %+v", deps)
	}
	if strings.Join(deps[0].DependsOn, ",") != "b" || strings.Join(deps[1].DependsOn, ",") != "a" {
		t.Fatalf("depends_on = %v / %v", deps[0].DependsOn, deps[1].DependsOn)
	}
	if deps[0].Relationship != "direct" || deps[1].Relationship != "indirect" {
		t.Fatalf("relationships = %s / %s", deps[0].Relationship, deps[1].Relationship)
	}
	if len(res.Issues) != 1 || !strings.Contains(res.Issues[0].Message, "used twice") {
		t.Fatalf("issues = %+v", res.Issues)
	}
	if err := res.Report.Validate(); err != nil {
		t.Fatal(err)
	}
}

// A purl with control characters or whitespace never reaches a match key.
func TestPURL_ControlCharacters(t *testing.T) {
	for _, bad := range []string{"pkg:npm/a@1\n", "pkg:npm/a b@1", "pkg:npm/a\x00@1", "npm/a@1", "pkg:/a", "pkg:n*m/a@1"} {
		if got := cleanPURL(bad); got != "" && bad != "pkg:npm/a@1\n" {
			t.Errorf("cleanPURL(%q) = %q", bad, got)
		}
	}
	in := cdxHead + `"metadata":{"component":{"name":"app"}},"components":[{"bom-ref":"x","name":"x","purl":"pkg:npm/x@1\u0007"}],
	"vulnerabilities":[{"id":"CVE-2024-0001","analysis":{"state":"not_affected","detail":"d"},"affects":[{"ref":"pkg:npm/y@1\u001b[31m"}]}]}`
	res, err := parseString(t, in, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Report.Dependencies[0].PURL != "" {
		t.Errorf("kept purl %q", res.Report.Dependencies[0].PURL)
	}
	if len(res.VEX) != 0 {
		t.Errorf("a statement on a hostile purl was kept: %+v", res.VEX)
	}
	if purlName("pkg:maven/org.example/a%2Fb@1?x=y") != "org.example/a/b" || purlName("nope") != "" || purlName("pkg:npm") != "" {
		t.Error("purlName")
	}
}

// A bare not_affected claim neither makes a statement nor hides the finding.
func TestCycloneDX_BareNotAffectedKeepsFinding(t *testing.T) {
	in := cdxHead + `"metadata":{"component":{"name":"app"}},"components":[{"bom-ref":"x","name":"x","version":"1"}],
	"vulnerabilities":[{"id":"CVE-2024-0001","analysis":{"state":"not_affected"},"affects":[{"ref":"x"}]},
	{"id":"CVE-2024-0002","analysis":{"state":"false_positive"},"affects":[{"ref":"x"}]}]}`
	res, err := parseString(t, in, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.VEX) != 0 || len(res.Report.Findings) != 1 || res.Report.Findings[0].RuleID != "CVE-2024-0001" {
		t.Fatalf("vex=%d findings=%+v", len(res.VEX), res.Report.Findings)
	}
	if res.Report.Findings[0].Severity != ctis.SeverityMedium {
		t.Errorf("severity = %s", res.Report.Findings[0].Severity)
	}
}

func TestCycloneDX_NoSubject(t *testing.T) {
	res, err := parseString(t, cdxHead+`"components":[{"name":"a"}]}`, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Assets) != 1 || res.Report.Assets[0].Type != ctis.AssetTypeUnclassified || res.Report.Assets[0].Value != "urn:uuid:x" {
		t.Fatalf("assets = %+v", res.Report.Assets)
	}
}

func TestSPDX_Edges(t *testing.T) {
	_, err := parseString(t, `{"spdxVersion":"SPDX-3.0"}`, Options{Format: FormatSPDX})
	wantKind(t, err, ErrMalformed)

	in := `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"doc",
	"packages":[{"SPDXID":"a","name":"a","supplier":"Person: Jane (jane@example.com)","originator":"Organization: Org (org@example.com)"}],
	"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"missing"},{"spdxElementId":"a","relationshipType":"DEPENDS_ON","relatedSpdxElement":"a"}]}`
	res, err := parseString(t, in, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Assets) != 1 || res.Report.Assets[0].Value != "doc" {
		t.Fatalf("assets = %+v", res.Report.Assets)
	}
	out, _ := json.Marshal(res)
	if bytes.Contains(out, []byte("@example.com")) || bytes.Contains(out, []byte("Jane")) {
		t.Errorf("a person or e-mail address reached the result: %s", out)
	}
	if len(res.Report.Dependencies[0].DependsOn) != 0 {
		t.Error("self dependency kept")
	}

	// DESCRIBED_BY names the subject too.
	in = `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[{"SPDXID":"s","name":"s"},{"SPDXID":"a","name":"a"}],
	"relationships":[{"spdxElementId":"s","relationshipType":"DESCRIBED_BY","relatedSpdxElement":"SPDXRef-DOCUMENT"}]}`
	res, err = parseString(t, in, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Report.Assets[0].Value != "s" || len(res.Report.Dependencies) != 1 {
		t.Fatalf("assets=%+v deps=%+v", res.Report.Assets, res.Report.Dependencies)
	}
}

func TestOSV_Edges(t *testing.T) {
	in := "{\"results\": [\n{\"source\": {\"path\": 7}}]}"
	_, err := parseString(t, in, Options{})
	p := wantKind(t, err, ErrMalformed)
	if p.Line != 2 {
		t.Errorf("line = %d, want 2", p.Line)
	}
	// A source path is only a label: control characters are removed and
	// nothing is opened.
	in = `{"results":[{"source":{"path":"../../etc/passwd\u001b[2J"},"packages":[{"package":{"name":"a","version":"1","ecosystem":"npm"},
	"vulnerabilities":[{"id":"GHSA-xxxx-xxxx-xxxx","summary":"s","database_specific":{"severity":"CRITICAL"}}]}]}]}`
	res, err := parseString(t, in, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if v := res.Report.Assets[0].Value; strings.ContainsRune(v, 0x1b) {
		t.Errorf("asset value kept an escape: %q", v)
	}
	if res.Report.Findings[0].Severity != ctis.SeverityCritical {
		t.Errorf("severity = %s", res.Report.Findings[0].Severity)
	}
	if err := res.Report.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSBOM_NoPeopleInGoldens(t *testing.T) {
	for _, dir := range []string{"cyclonedx", "spdx", "osv"} {
		files, _ := os.ReadDir(fixtureRoot + "/" + dir)
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".golden.json") && !strings.HasSuffix(f.Name(), ".result.json") {
				continue
			}
			b, err := os.ReadFile(fixtureRoot + "/" + dir + "/" + f.Name())
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range []string{"jane@example.com", "maint@example.com", "researcher@example.com", "Jane Example", "/home/runner", "send [[[["} {
				if bytes.Contains(b, []byte(s)) {
					t.Errorf("%s/%s holds %q", dir, f.Name(), s)
				}
			}
		}
	}
}

func TestSBOMHelpers(t *testing.T) {
	if severityFromCVSS(9.1) != ctis.SeverityCritical || severityFromCVSS(0) != ctis.SeverityInfo || severityFromCVSS(3.9) != ctis.SeverityLow {
		t.Error("severityFromCVSS")
	}
	for w, want := range map[string]ctis.Severity{"important": ctis.SeverityHigh, "negligible": ctis.SeverityInfo, "moderate": ctis.SeverityMedium} {
		if got, ok := severityWord(w); !ok || got != want {
			t.Errorf("severityWord(%s) = %s", w, got)
		}
	}
	if _, ok := severityWord("x"); ok {
		t.Error("severityWord(x)")
	}
	if assetTypeOfPurpose("OPERATING_SYSTEM") != ctis.AssetTypeHost || assetTypeOfPurpose("library") != ctis.AssetTypeRepository {
		t.Error("assetTypeOfPurpose")
	}
	if floatString(7.5) != "7.5" {
		t.Error("floatString")
	}
	d := ctis.Dependency{}
	for i := 0; i < 40; i++ {
		addDepProperty(&d, "k"+strings.Repeat("x", i), "v")
	}
	if len(d.Properties) != maxDepProperties {
		t.Errorf("properties = %d", len(d.Properties))
	}
	sys, ver := cdxRatingSystem("other", "CVSS:3.1/AV:N")
	if sys != ctis.ScoreSystemCVSS || ver != "3.1" {
		t.Errorf("rating system = %s %s", sys, ver)
	}
	if _, v := cdxRatingSystem("CVSSv3", "CVSS:3.1/AV:N"); v != "3.1" {
		t.Error("CVSSv3 with a 3.1 vector")
	}
}
