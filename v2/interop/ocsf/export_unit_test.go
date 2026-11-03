package ocsf

import (
	"strconv"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/internal/interoptest"

	"encoding/json"
	"testing"
	"time"
)

func TestExportOCSFNativeReport(t *testing.T) {
	ts := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	r := &ctis.Report{
		Version:  ctis.SchemaVersion,
		Metadata: ctis.ReportMetadata{ID: interoptest.ReportID, GeneratedAt: ts},
		Tool:     &ctis.Tool{Name: "scanner", Vendor: "Example", Version: "1"},
		Assets:   []ctis.Asset{{ID: "ip", Type: ctis.AssetTypeIPAddress, Value: "10.0.0.1"}},
	}
	statuses := append(ctis.AllFindingStatuses(), "")
	for i, st := range statuses {
		f := ctis.Finding{ID: "f" + strconv.Itoa(i), Type: ctis.FindingTypeVulnerability, Title: "t", Severity: ctis.AllSeverities()[i%5], Status: st, AssetRef: "ip"}
		if i == 0 {
			f.FirstSeenAt = &ts
		}
		r.Findings = append(r.Findings, f)
	}
	r.Findings = append(r.Findings,
		ctis.Finding{Type: ctis.FindingTypeCompliance, Title: "c", Severity: "bogus", Kind: "review", Compliance: &ctis.ComplianceDetails{Framework: "cis", ControlID: "1.1"}},
		ctis.Finding{Type: ctis.FindingTypeCompliance, Title: "c2", Severity: ctis.SeverityLow, Kind: "pass", Compliance: &ctis.ComplianceDetails{}},
		ctis.Finding{Type: ctis.FindingTypeMisconfiguration, Title: "", RuleID: "CKV_1", Severity: ctis.SeverityLow, Misconfiguration: &ctis.MisconfigurationDetails{PolicyID: "CKV_1", Provider: "aws"},
			Remediation: &ctis.Remediation{Recommendation: "fix it"}},
		ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "legacy", Severity: ctis.SeverityHigh, Location: &ctis.FindingLocation{Path: "src/a.go", StartLine: 2},
			Vulnerability: &ctis.VulnerabilityDetails{IDs: []ctis.VulnerabilityID{{Type: ctis.VulnerabilityIDCVE, ID: "cve-2024-1"}}, CWEIDs: []string{"CWE-1", "CWE-2", "CWE-3"}},
			Scores:        []ctis.Score{{System: ctis.ScoreSystemCVSS, Version: "3.1", Vector: "CVSS:3.1/AV:N"}}},
	)
	events, err := Events(r, &Options{Time: ts.Add(time.Hour)})
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
	if events[1].ActivityID != ActivityClose {
		t.Errorf("resolved -> %d", events[1].ActivityID)
	}
	n := len(statuses)
	if c := events[n].Compliance; c.StatusID != 99 || c.Status != "review" || events[n].SeverityID != 0 {
		t.Errorf("manual: %+v", events[n])
	}
	if c := events[n+1].Compliance; c.StatusID != 1 || len(c.Standards) != 0 {
		t.Errorf("pass: %+v", c)
	}
	if ev := events[n+2]; ev.ClassUID != ClassComplianceFinding || ev.Compliance.Control != "CKV_1" || ev.Compliance.StatusID != 3 || ev.Remediation == nil || ev.FindingInfo.Title != "CKV_1" {
		t.Errorf("misconfiguration: %+v", ev)
	}
	ev := events[n+3]
	if len(ev.Vulnerabilities) != 3 || ev.Vulnerabilities[0].CVE.UID != "CVE-2024-1" || ev.Vulnerabilities[2].CWE.UID != "CWE-3" ||
		ev.Vulnerabilities[0].CVE.CVSS[0].VectorString != "CVSS:3.1/AV:N" || ev.Vulnerabilities[0].AffectedCode[0].File.Name != "a.go" {
		t.Errorf("legacy: %+v", ev.Vulnerabilities)
	}
	if _, err := Events(nil, nil); err == nil {
		t.Error("nil report")
	}
	if evs, err := Events(&ctis.Report{}, nil); err != nil || len(evs) != 0 {
		t.Error("empty report")
	}
}

func TestExportOCSFSecretMasked(t *testing.T) {
	raw := "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
	r := &ctis.Report{Findings: []ctis.Finding{{Type: ctis.FindingTypeSecret, Title: "Access token " + raw, Description: "found " + raw, Severity: ctis.SeverityHigh,
		Location: &ctis.FindingLocation{Path: ".env", Snippet: raw}, Secret: &ctis.SecretDetails{Type: "token", Service: "scm", MaskedValue: raw}}}}
	events, err := Events(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(events)
	if ctis.ContainsSecret(string(b), raw) {
		t.Fatalf("raw secret in OCSF export: %s", b)
	}
	if events[0].Unmapped["secret_masked_value"] == "" || events[0].Unmapped["secret_service"] != "scm" {
		t.Errorf("unmapped: %v", events[0].Unmapped)
	}
}
