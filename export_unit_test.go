package ctis

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestExportCycloneDXMappingTables(t *testing.T) {
	for _, j := range AllVEXJustifications() {
		got := cdxJustificationOf(&VEX{Status: VEXStatusNotAffected, Justification: j})
		if !cdxJustifications[got] {
			t.Errorf("%s -> %q is not a CycloneDX justification", j, got)
		}
		back, ok := NormalizeVEXJustification(got)
		if !ok || (back != j && j != VEXJustificationComponentNotPresent) {
			t.Errorf("%s -> %s -> %s", j, got, back)
		}
	}
	if got := cdxJustificationOf(&VEX{NativeJustification: "protected_at_runtime", Justification: VEXJustificationInlineMitigationsAlreadyExist}); got != "protected_at_runtime" {
		t.Errorf("native justification not kept: %s", got)
	}
	if cdxJustificationOf(&VEX{}) != "" {
		t.Error("empty justification")
	}
	for _, s := range AllVEXStatuses() {
		st := cdxStateOf(s)
		if back, ok := NormalizeVEXStatus(st); !ok || back != s {
			t.Errorf("%s -> %s -> %s", s, st, back)
		}
	}
	if cdxStateOf("bogus") != "" {
		t.Error("bogus status")
	}
	cases := []struct {
		s    Score
		want string
		ok   bool
	}{
		{Score{System: ScoreSystemCVSS, Version: "2.0"}, "CVSSv2", true},
		{Score{System: ScoreSystemCVSS, Version: "3.0"}, "CVSSv3", true},
		{Score{System: ScoreSystemCVSS, Version: "3.1"}, "CVSSv31", true},
		{Score{System: ScoreSystemCVSS, Version: "4.0"}, "CVSSv4", true},
		{Score{System: ScoreSystemCVSS}, "other", true},
		{Score{System: ScoreSystemSSVC}, "SSVC", true},
		{Score{System: ScoreSystemVendor}, "other", true},
		{Score{System: ScoreSystemEPSS}, "", false},
	}
	for _, c := range cases {
		if got, ok := cdxMethodOf(&c.s); got != c.want || ok != c.ok {
			t.Errorf("%+v -> %s %v", c.s, got, ok)
		}
	}
	if cdxSeverityOf(SeverityInfo) != "info" || cdxSeverityOf("bogus") != "" {
		t.Error("cdxSeverityOf")
	}
	if got := cdxExtraKey(strings.Repeat("a", 70)); len(got) != 64 {
		t.Errorf("cdxExtraKey: %d", len(got))
	}
}

func TestExportCycloneDXNativeReport(t *testing.T) {
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	epss := 0.4
	r := &Report{
		Version:  SchemaVersion,
		Metadata: ReportMetadata{Timestamp: ts, Properties: Properties{"bom_version": float64(7)}},
		Assets:   []Asset{{ID: "img", Type: AssetTypeContainer, Value: "registry.example/app:1"}, {Type: AssetTypeHost, Value: "h"}},
		Dependencies: []Dependency{
			{ID: "a", Name: "a", Version: "1", Relationship: "direct", DependsOn: []string{"b", "a", "missing"},
				Properties: Properties{"hash_sha-256": "00ff", "hash_bogus": "x", "custom": "v", "number": 3}},
			{Name: "b", Version: "2", PURL: "pkg:npm/b@2"},
			{Name: "b", Version: "2", PURL: "pkg:npm/b@2"},
			{Name: ""},
		},
		Findings: []Finding{
			{Type: FindingTypeVulnerability, Title: "x", Severity: SeverityHigh, RuleID: "rule-1",
				Vulnerability: &VulnerabilityDetails{CVEIDs: []string{"CVE-2024-0001", "CVE-2024-0002"}, Package: "c", AffectedVersion: "3", CWEID: "CWE-20", AffectedVersionRange: "<4"},
				Scores:        []Score{{System: ScoreSystemEPSS, Value: &epss}, {System: ScoreSystemSSVC, Label: "Act", Vector: "SSVCv2/E:A"}},
				Status:        FindingStatusFalsePositive, References: []string{"https://example.com/r"}},
			{Type: FindingTypeVulnerability, Title: "y", Severity: SeverityLow, RuleID: "CVE-2024-0003",
				Vulnerability: &VulnerabilityDetails{PURL: "pkg:npm/b@2", Package: "b", AffectedVersion: "2"},
				VEX:           &VEX{Status: VEXStatusFixed, AsOf: &ts}},
			{Type: FindingTypeVulnerability, Title: "z", Severity: SeverityMedium,
				Vulnerability: &VulnerabilityDetails{IDs: []VulnerabilityID{{Type: VulnerabilityIDGHSA, ID: "GHSA-aaaa-bbbb-cccc"}}, Package: "a", AffectedVersion: "1"}},
			{Type: FindingTypeVulnerability, Title: "no id", Severity: SeverityMedium},
			{Type: FindingTypeSecret, Title: "s", Severity: SeverityHigh, Vulnerability: &VulnerabilityDetails{CVEID: "CVE-2024-9"}},
		},
	}
	out, err := ToCycloneDX(r, &CycloneDXOptions{SubjectAssetID: "img"})
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
	again, _ := ToCycloneDX(r, &CycloneDXOptions{SubjectAssetID: "img"})
	if string(again) != s {
		t.Error("not deterministic")
	}
	if serial := cdxSerial(r); len(serial) != len("urn:uuid:")+36 || !strings.HasPrefix(serial, "urn:uuid:") || serial[23] != '8' {
		t.Error("serial")
	}
	// No assets, no graph, no options.
	out, err = ToCycloneDX(&Report{Findings: []Finding{{Type: FindingTypeVulnerability, Severity: SeverityInfo, RuleID: "OSV-1", Vulnerability: &VulnerabilityDetails{Package: "p"}}}}, nil)
	if err != nil || !strings.Contains(string(out), `"severity": "info"`) {
		t.Errorf("minimal: %v\n%s", err, out)
	}
	if _, err := ToCycloneDX(nil, nil); err == nil {
		t.Error("nil report")
	}
	for _, a := range []Asset{{Type: AssetTypeHost, Value: "pkg:generic/x@1"}, {Type: AssetTypeRepository, Value: "r", Name: "n"}} {
		c := cdxSubjectOf(&a)
		if c.Type == "" || c.BOMRef == "" || c.Name == "" {
			t.Errorf("subject %+v", c)
		}
	}
}

func TestExportOCSFNativeReport(t *testing.T) {
	ts := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	r := &Report{
		Version:  SchemaVersion,
		Metadata: ReportMetadata{Timestamp: ts},
		Tool:     &Tool{Name: "scanner", Vendor: "Example", Version: "1"},
	}
	statuses := append(AllFindingStatuses(), "")
	for i, st := range statuses {
		f := Finding{ID: "f" + itoa(i), Type: FindingTypeVulnerability, Title: "t", Severity: AllSeverities()[i%5], Status: st, AssetValue: "10.0.0.1", AssetType: AssetTypeIPAddress}
		if i == 0 {
			f.FirstSeenAt = &ts
		}
		r.Findings = append(r.Findings, f)
	}
	r.Findings = append(r.Findings,
		Finding{Type: FindingTypeCompliance, Title: "c", Severity: "bogus", Compliance: &ComplianceDetails{Framework: "cis", ControlID: "1.1", Result: "manual"}},
		Finding{Type: FindingTypeCompliance, Title: "c2", Severity: SeverityLow, Compliance: &ComplianceDetails{Result: "pass"}},
		Finding{Type: FindingTypeMisconfiguration, Title: "", RuleID: "CKV_1", Severity: SeverityLow, Misconfiguration: &MisconfigurationDetails{PolicyID: "CKV_1", Provider: "aws"},
			Remediation: &Remediation{Recommendation: "fix it"}},
		Finding{Type: FindingTypeVulnerability, Title: "legacy", Severity: SeverityHigh, Location: &FindingLocation{Path: "src/a.go", StartLine: 2},
			Vulnerability: &VulnerabilityDetails{CVEID: "cve-2024-1", CVSSVector: "CVSS:3.1/AV:N", CWEIDs: []string{"CWE-1", "CWE-2", "CWE-3"}}},
	)
	events, err := ToOCSF(r, &OCSFOptions{Time: ts.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	for i, st := range statuses {
		ev := events[i]
		if got := ocsfStatusOf(ev.StatusID, ev.Status); got != st {
			t.Errorf("status %q -> %d %q -> %q", st, ev.StatusID, ev.Status, got)
		}
		if ocsfSeverityOf(ev.SeverityID) != r.Findings[i].Severity {
			t.Errorf("severity %s", r.Findings[i].Severity)
		}
		if ev.Resources[0].Name != "10.0.0.1" || ev.Metadata.Product.VendorName != "Example" {
			t.Errorf("resource/product %+v", ev)
		}
	}
	if events[0].Time != ts.UnixMilli() || events[1].Time != ts.Add(time.Hour).UnixMilli() {
		t.Errorf("times %d %d", events[0].Time, events[1].Time)
	}
	if events[1].ActivityID != OCSFActivityClose {
		t.Errorf("resolved -> %d", events[1].ActivityID)
	}
	n := len(statuses)
	if c := events[n].Compliance; c.StatusID != 99 || c.Status != "manual" || events[n].SeverityID != 0 {
		t.Errorf("manual: %+v", events[n])
	}
	if c := events[n+1].Compliance; c.StatusID != 1 || len(c.Standards) != 0 {
		t.Errorf("pass: %+v", c)
	}
	if ev := events[n+2]; ev.ClassUID != OCSFClassComplianceFinding || ev.Compliance.Control != "CKV_1" || ev.Compliance.StatusID != 3 || ev.Remediation == nil || ev.FindingInfo.Title != "CKV_1" {
		t.Errorf("misconfiguration: %+v", ev)
	}
	ev := events[n+3]
	if len(ev.Vulnerabilities) != 3 || ev.Vulnerabilities[0].CVE.UID != "CVE-2024-1" || ev.Vulnerabilities[2].CWE.UID != "CWE-3" ||
		ev.Vulnerabilities[0].CVE.CVSS[0].VectorString != "CVSS:3.1/AV:N" || ev.Vulnerabilities[0].AffectedCode[0].File.Name != "a.go" {
		t.Errorf("legacy: %+v", ev.Vulnerabilities)
	}
	if _, err := ToOCSF(nil, nil); err == nil {
		t.Error("nil report")
	}
	if evs, err := ToOCSF(&Report{}, nil); err != nil || len(evs) != 0 {
		t.Error("empty report")
	}
}

func TestExportOCSFSecretMasked(t *testing.T) {
	raw := "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
	r := &Report{Findings: []Finding{{Type: FindingTypeSecret, Title: "Access token " + raw, Description: "found " + raw, Severity: SeverityHigh,
		Location: &FindingLocation{Path: ".env", Snippet: raw}, Secret: &SecretDetails{SecretType: "token", Service: "scm", MaskedValue: raw}}}}
	events, err := ToOCSF(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(events)
	if ContainsSecret(string(b), raw) {
		t.Fatalf("raw secret in OCSF export: %s", b)
	}
	if events[0].Unmapped["secret_masked_value"] == "" || events[0].Unmapped["secret_service"] != "scm" {
		t.Errorf("unmapped: %v", events[0].Unmapped)
	}
	out, err := ToCycloneDX(r, nil)
	if err != nil || ContainsSecret(string(out), raw) {
		t.Fatalf("CycloneDX: %v %s", err, out)
	}
}
