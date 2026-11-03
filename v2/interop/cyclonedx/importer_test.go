package cyclonedx

import (
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/importer"
	"github.com/openctemio/ctis/v2/internal/goldencheck"
	"github.com/openctemio/ctis/v2/internal/interoptest"
)

type Options = importer.Options
type Limits = importer.Limits

func parseString(t *testing.T, in string, opts Options) (*importer.Result, error) {
	t.Helper()
	return interoptest.ParseString(t, in, opts)
}

func wantKind(t *testing.T, err, kind error) (p struct{ Line, Column int }) {
	t.Helper()
	p.Line, p.Column = interoptest.WantKind(t, err, kind)
	return p
}

// Hostile and edge-case input for the CycloneDX importer.

const cdxHead = `{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:x","version":1,`

func TestCycloneDX_DeepNesting(t *testing.T) {
	in := cdxHead + `"components":` + strings.Repeat(`[{"name":"a","components":`, 200) + `[]` + strings.Repeat(`}]`, 200) + `}`
	_, err := parseString(t, in, Options{})
	wantKind(t, err, importer.ErrTooLarge)
}

func TestCycloneDX_Limits(t *testing.T) {
	var comps []string
	for i := 0; i < 20; i++ {
		comps = append(comps, `{"bom-ref":"c`+strings.Repeat("x", i)+`","name":"c"}`)
	}
	in := cdxHead + `"metadata":{"component":{"name":"app","type":"application"}},"components":[` + strings.Join(comps, ",") + `]}`
	_, err := parseString(t, in, Options{Limits: Limits{MaxComponents: 5}})
	wantKind(t, err, importer.ErrTooLarge)

	var vulns []string
	for i := 0; i < 20; i++ {
		vulns = append(vulns, `{"id":"CVE-2024-000`+string(rune('0'+i%10))+`","analysis":{"state":"not_affected","detail":"x"},"affects":[{"ref":"pkg:npm/a@1"}]}`)
	}
	in = cdxHead + `"vulnerabilities":[` + strings.Join(vulns, ",") + `]}`
	_, err = parseString(t, in, Options{Limits: Limits{MaxStatements: 5}})
	wantKind(t, err, importer.ErrTooLarge)
}

func TestCycloneDX_WrongTypeHasLine(t *testing.T) {
	in := "{\n\"bomFormat\": \"CycloneDX\",\n\"version\": \"one\"\n}"
	_, err := parseString(t, in, Options{})
	p := wantKind(t, err, importer.ErrMalformed)
	if p.Line != 3 {
		t.Errorf("line = %d, want 3", p.Line)
	}
}

func TestCycloneDX_InvalidUTF8HasLine(t *testing.T) {
	in := "{\n\"bomFormat\": \"CycloneDX\",\n\"components\": [{\"name\": \"\xff\"}]\n}"
	_, err := parseString(t, in, Options{Format: importer.FormatCycloneDX})
	p := wantKind(t, err, importer.ErrMalformed)
	if p.Line != 3 {
		t.Errorf("line = %d, want 3", p.Line)
	}
}

func TestCycloneDX_NotCycloneDX(t *testing.T) {
	_, err := parseString(t, `{"bomFormat":"SPDX"}`, Options{Format: importer.FormatCycloneDX})
	wantKind(t, err, importer.ErrMalformed)
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
	if deps[0].Relationship != ctis.DependencyDirect || deps[1].Relationship != ctis.DependencyTransitive {
		t.Fatalf("relationships = %s / %s", deps[0].Relationship, deps[1].Relationship)
	}
	if len(res.Issues) != 1 || !strings.Contains(res.Issues[0].Message, "used twice") {
		t.Fatalf("issues = %+v", res.Issues)
	}
	if err := res.Report.Validate(); err != nil {
		t.Fatal(err)
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

// A purl with control characters or whitespace never reaches a match key.
func TestPURL_ControlCharacters(t *testing.T) {
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
}

func TestCdxRatingSystem(t *testing.T) {
	sys, ver := cdxRatingSystem("other", "CVSS:3.1/AV:N")
	if sys != ctis.ScoreSystemCVSS || ver != "3.1" {
		t.Errorf("rating system = %s %s", sys, ver)
	}
	if _, v := cdxRatingSystem("CVSSv3", "CVSS:3.1/AV:N"); v != "3.1" {
		t.Error("CVSSv3 with a 3.1 vector")
	}
}

func TestSBOM_NoPeopleInGoldens(t *testing.T) {
	goldencheck.NoPeopleInGoldens(t, importerFixtures)
}
