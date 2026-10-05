package importer

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/ctis"
)

// The guard drops what is not valid CTIS, with an issue, so Parse never
// returns an invalid report whatever a parser built.
func TestGuard_DropsInvalidEntities(t *testing.T) {
	b := newBuilder(context.Background(), FormatNessus, Options{Limits: DefaultLimits()})
	r := b.res.Report
	r.Assets = []ctis.Asset{
		{ID: "a", Type: ctis.AssetTypeHost, Value: "a.example.com"},
		{ID: "bad", Type: ctis.AssetTypeHost, Value: ""},        // no value
		{ID: "a", Type: ctis.AssetTypeHost, Value: "duplicate"}, // duplicate id
	}
	r.Findings = []ctis.Finding{
		{Type: ctis.FindingTypeVulnerability, Title: "ok", Severity: ctis.SeverityHigh, AssetRef: "a"},
		{Type: ctis.FindingTypeVulnerability, Title: "", Severity: ctis.SeverityHigh, AssetRef: "a"},        // no title
		{Type: ctis.FindingTypeVulnerability, Title: "orphan", Severity: ctis.SeverityLow, AssetRef: "bad"}, // asset dropped
	}
	r.Dependencies = []ctis.Dependency{{Name: "lodash"}, {Name: ""}, {ID: "x", Name: "a"}, {ID: "x", Name: "b"}}
	b.res.VEX = []VEXStatement{
		{VulnerabilityIDs: []ctis.VulnerabilityID{{Type: ctis.VulnerabilityIDCVE, ID: "CVE-2024-0001"}}, Products: []Product{{PURL: "pkg:npm/a"}}, VEX: ctis.VEX{Status: ctis.VEXStatusAffected}},
		{VulnerabilityIDs: []ctis.VulnerabilityID{{Type: ctis.VulnerabilityIDCVE, ID: "CVE-2024-0002"}}, Products: []Product{{PURL: "pkg:npm/a"}}, VEX: ctis.VEX{Status: ctis.VEXStatusNotAffected}}, // bare claim
		{Products: []Product{{PURL: "pkg:npm/a"}}, VEX: ctis.VEX{Status: ctis.VEXStatusFixed}},                                                                                                       // no id
	}
	if err := b.guard(); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("report still invalid: %v", err)
	}
	if len(r.Assets) != 1 || len(r.Findings) != 1 || len(r.Dependencies) != 2 || len(b.res.VEX) != 1 {
		t.Fatalf("kept %d assets, %d findings, %d deps, %d statements", len(r.Assets), len(r.Findings), len(r.Dependencies), len(b.res.VEX))
	}
	if len(b.res.Issues) != 4 || !strings.Contains(b.res.Issues[1].Message, "2 finding(s) left out") {
		t.Fatalf("issues = %+v", b.res.Issues)
	}
	if b.res.Stats.BySeverity[ctis.SeverityLow] != 0 || b.res.Stats.BySeverity[ctis.SeverityHigh] != 1 {
		t.Fatalf("by severity = %v", b.res.Stats.BySeverity)
	}
}
