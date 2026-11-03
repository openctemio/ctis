package cyclonedx

import (
	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/internal/interoptest"

	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestExportCycloneDXMappingTables(t *testing.T) {
	for _, j := range ctis.AllVEXJustifications() {
		got := cdxJustificationOf(&ctis.VEX{Status: ctis.VEXStatusNotAffected, Justification: j})
		if _, ok := exp.Lookup("justification", got); !ok {
			t.Errorf("%s -> %q is not a CycloneDX justification", j, got)
		}
		back, ok := ctis.NormalizeVEXJustification(got)
		if !ok || (back != j && j != ctis.VEXJustificationComponentNotPresent) {
			t.Errorf("%s -> %s -> %s", j, got, back)
		}
	}
	if got := cdxJustificationOf(&ctis.VEX{NativeJustification: "protected_at_runtime", Justification: ctis.VEXJustificationInlineMitigationsAlreadyExist}); got != "protected_at_runtime" {
		t.Errorf("native justification not kept: %s", got)
	}
	if cdxJustificationOf(&ctis.VEX{}) != "" {
		t.Error("empty justification")
	}
	for _, s := range ctis.AllVEXStatuses() {
		st := cdxStateOf(s)
		if back, ok := ctis.NormalizeVEXStatus(st); !ok || back != s {
			t.Errorf("%s -> %s -> %s", s, st, back)
		}
	}
	if cdxStateOf("bogus") != "" {
		t.Error("bogus status")
	}
	cases := []struct {
		s    ctis.Score
		want string
		ok   bool
	}{
		{ctis.Score{System: ctis.ScoreSystemCVSS, Version: "2.0"}, "CVSSv2", true},
		{ctis.Score{System: ctis.ScoreSystemCVSS, Version: "3.0"}, "CVSSv3", true},
		{ctis.Score{System: ctis.ScoreSystemCVSS, Version: "3.1"}, "CVSSv31", true},
		{ctis.Score{System: ctis.ScoreSystemCVSS, Version: "4.0"}, "CVSSv4", true},
		{ctis.Score{System: ctis.ScoreSystemCVSS}, "other", true},
		{ctis.Score{System: ctis.ScoreSystemSSVC}, "SSVC", true},
		{ctis.Score{System: ctis.ScoreSystemVendor}, "other", true},
		{ctis.Score{System: ctis.ScoreSystemEPSS}, "", false},
	}
	for _, c := range cases {
		if got, ok := cdxMethodOf(&c.s); got != c.want || ok != c.ok {
			t.Errorf("%+v -> %s %v", c.s, got, ok)
		}
	}
	if cdxSeverityOf(ctis.SeverityInfo) != "info" || cdxSeverityOf("bogus") != "" {
		t.Error("cdxSeverityOf")
	}
	if got := cdxExtraKey(strings.Repeat("a", 70)); len(got) != 64 {
		t.Errorf("cdxExtraKey: %d", len(got))
	}
}

func TestExportCycloneDXNativeReport(t *testing.T) {
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	epss := 0.4
	r := &ctis.Report{
		Version:  ctis.SchemaVersion,
		Metadata: ctis.ReportMetadata{ID: interoptest.ReportID, GeneratedAt: ts, Properties: ctis.Properties{"bom_version": float64(7)}},
		Assets:   []ctis.Asset{{ID: "img", Type: ctis.AssetTypeContainer, Value: "registry.example/app:1"}, {Type: ctis.AssetTypeHost, Value: "h"}},
		Dependencies: []ctis.Dependency{
			{ID: "a", Name: "a", Version: "1", Relationship: "direct", DependsOn: []string{"b", "a", "missing"},
				Properties: ctis.Properties{"hash_sha-256": "00ff", "hash_bogus": "x", "custom": "v", "number": 3}},
			{Name: "b", Version: "2", PURL: "pkg:npm/b@2"},
			{Name: "b", Version: "2", PURL: "pkg:npm/b@2"},
			{Name: ""},
		},
		Findings: []ctis.Finding{
			{Type: ctis.FindingTypeVulnerability, Title: "x", Severity: ctis.SeverityHigh, RuleID: "rule-1",
				Vulnerability: &ctis.VulnerabilityDetails{IDs: []ctis.VulnerabilityID{{Type: ctis.VulnerabilityIDCVE, ID: "CVE-2024-0001"}, {Type: ctis.VulnerabilityIDCVE, ID: "CVE-2024-0002"}}, PackageName: "c", InstalledVersion: "3", CWEIDs: []string{"CWE-20"}, AffectedVersionRange: "<4"},
				Scores:        []ctis.Score{{System: ctis.ScoreSystemEPSS, Value: &epss}, {System: ctis.ScoreSystemSSVC, Label: "Act", Vector: "SSVCv2/E:A"}},
				Status:        ctis.FindingStatusFalsePositive, References: []string{"https://example.com/r"}},
			{Type: ctis.FindingTypeVulnerability, Title: "y", Severity: ctis.SeverityLow, RuleID: "CVE-2024-0003",
				Vulnerability: &ctis.VulnerabilityDetails{PURL: "pkg:npm/b@2", PackageName: "b", InstalledVersion: "2"},
				VEX:           &ctis.VEX{Status: ctis.VEXStatusFixed, AsOf: &ts}},
			{Type: ctis.FindingTypeVulnerability, Title: "z", Severity: ctis.SeverityMedium,
				Vulnerability: &ctis.VulnerabilityDetails{IDs: []ctis.VulnerabilityID{{Type: ctis.VulnerabilityIDGHSA, ID: "GHSA-aaaa-bbbb-cccc"}}, PackageName: "a", InstalledVersion: "1"}},
			{Type: ctis.FindingTypeVulnerability, Title: "no id", Severity: ctis.SeverityMedium},
			{Type: ctis.FindingTypeSecret, Title: "s", Severity: ctis.SeverityHigh, Vulnerability: &ctis.VulnerabilityDetails{IDs: []ctis.VulnerabilityID{{Type: ctis.VulnerabilityIDCVE, ID: "CVE-2024-9"}}}},
		},
	}
	out, err := Export(r, &ExportOptions{SubjectAssetID: "img"})
	if err != nil {
		t.Fatal(err)
	}
	var bom map[string]any
	if err := json.Unmarshal(out, &bom); err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{`"version": 7`, `"type": "container"`, `"alg": "SHA-256"`, `"name": "ctis:custom"`, `"state": "false_positive"`,
		`"state": "resolved"`, `"ref": "pkg-c@3"`, `"id": "GHSA-aaaa-bbbb-cccc"`, `"name": "ctis:score:epss"`, `"method": "SSVC"`,
		`"range": "\u003c4"`, `"serialNumber": "urn:uuid:`, `"timestamp": "2026-01-02T03:04:05Z"`, `"name": "ctis:references"`, `"id": "CVE-2024-0002"`} {
		if !strings.Contains(s, want) {
			t.Errorf("BOM lacks %s:\n%s", want, s)
		}
	}
	if strings.Contains(s, "CVE-2024-9") {
		t.Error("a secret finding was written as a vulnerability")
	}
	vulns := bom["vulnerabilities"].([]any)
	if len(vulns) != 3 {
		t.Errorf("%d vulnerabilities", len(vulns))
	}
	again, _ := Export(r, &ExportOptions{SubjectAssetID: "img"})
	if string(again) != s {
		t.Error("not deterministic")
	}
	if serial := cdxSerial(r); len(serial) != len("urn:uuid:")+36 || !strings.HasPrefix(serial, "urn:uuid:") || serial[23] != '8' {
		t.Error("serial")
	}
	// No assets, no graph, no options.
	out, err = Export(&ctis.Report{Findings: []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Severity: ctis.SeverityInfo, RuleID: "OSV-1", Vulnerability: &ctis.VulnerabilityDetails{PackageName: "p"}}}}, nil)
	if err != nil || !strings.Contains(string(out), `"severity": "info"`) {
		t.Errorf("minimal: %v\n%s", err, out)
	}
	if _, err := Export(nil, nil); err == nil {
		t.Error("nil report")
	}
	for _, a := range []ctis.Asset{{Type: ctis.AssetTypeHost, Value: "pkg:generic/x@1"}, {Type: ctis.AssetTypeRepository, Value: "r", Name: "n"}} {
		c := cdxSubjectOf(&a)
		if c.Type == "" || c.BOMRef == "" || c.Name == "" {
			t.Errorf("subject %+v", c)
		}
	}
}
