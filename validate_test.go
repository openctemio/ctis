package ctis

import (
	"math"
	"strings"
	"testing"
	"time"
)

func validReport() *Report {
	return &Report{
		Version:  "1.0",
		Metadata: ReportMetadata{Timestamp: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)},
		Tool:     &Tool{Name: "scanner"},
		Findings: []Finding{
			{
				ID:       "f1",
				Type:     FindingTypeVulnerability,
				Title:    "Test finding",
				Severity: SeverityHigh,
				Status:   FindingStatusOpen,
				AssetRef: "a1",
				Vulnerability: &VulnerabilityDetails{
					CVSSScore: 9.8, EPSSScore: 0.97, EPSSPercentile: 0.999, VPRScore: 9.0,
				},
			},
		},
		Assets: []Asset{
			{
				ID:          "a1",
				Type:        AssetTypeRepository,
				Value:       "github.com/org/repo",
				Criticality: CriticalityMedium,
			},
		},
	}
}

func TestReport_Validate_Valid(t *testing.T) {
	if err := validReport().Validate(); err != nil {
		t.Fatalf("valid report must pass, got: %v", err)
	}
}

func TestReport_Validate_Nil(t *testing.T) {
	var r *Report
	if err := r.Validate(); err == nil {
		t.Fatal("nil report must fail validation")
	}
}

func TestReport_Validate_MissingVersion(t *testing.T) {
	r := validReport()
	r.Version = ""
	if err := r.Validate(); err == nil {
		t.Fatal("missing version must fail")
	}
}

func TestReport_Validate_BadFinding(t *testing.T) {
	cases := map[string]func(*Finding){
		"empty title":      func(f *Finding) { f.Title = "" },
		"invalid type":     func(f *Finding) { f.Type = "bogus" },
		"invalid severity": func(f *Finding) { f.Severity = "spicy" },
		"invalid status":   func(f *Finding) { f.Status = "frozen" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := validReport()
			mutate(&r.Findings[0])
			if err := r.Validate(); err == nil {
				t.Errorf("%s must fail validation", name)
			}
		})
	}
}

func TestReport_Validate_BadAsset(t *testing.T) {
	cases := map[string]func(*Asset){
		"empty value":         func(a *Asset) { a.Value = "" },
		"invalid type":        func(a *Asset) { a.Type = "bogus" },
		"invalid criticality": func(a *Asset) { a.Criticality = "ultra" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := validReport()
			mutate(&r.Assets[0])
			if err := r.Validate(); err == nil {
				t.Errorf("%s must fail validation", name)
			}
		})
	}
}

// Score's fail-safe: an unrecognized severity scores Medium (5.0), not 0, so a
// drifted/typo'd severity still surfaces in triage instead of being hidden.
func TestSeverity_Score_UnknownIsFailSafe(t *testing.T) {
	if got := Severity("bogus").Score(); got != 5.0 {
		t.Errorf("unknown severity Score() = %v, want 5.0 (fail-safe Medium)", got)
	}
	if got := SeverityInfo.Score(); got != 0.0 {
		t.Errorf("info Score() = %v, want 0.0", got)
	}
}

func TestReport_Validate_Report(t *testing.T) {
	cases := map[string]func(*Report){
		"zero timestamp":       func(r *Report) { r.Metadata.Timestamp = time.Time{} },
		"garbage version":      func(r *Report) { r.Version = "9.9-garbage" },
		"other major":          func(r *Report) { r.Version = "2.0" },
		"version with v":       func(r *Report) { r.Version = "v1.3" },
		"tool without name":    func(r *Report) { r.Tool = &Tool{} },
		"duplicate asset id":   func(r *Report) { r.Assets = append(r.Assets, r.Assets[0]) },
		"duplicate finding id": func(r *Report) { r.Findings = append(r.Findings, r.Findings[0]) },
		"dangling asset_ref":   func(r *Report) { r.Findings[0].AssetRef = "nope" },
		"asset confidence":     func(r *Report) { r.Assets[0].Confidence = 500 },
		"finding confidence":   func(r *Report) { r.Findings[0].Confidence = -1 },
		"rank":                 func(r *Report) { r.Findings[0].Rank = 101 },
		"cvss above 10":        func(r *Report) { r.Findings[0].Vulnerability.CVSSScore = 99 },
		"cvss negative":        func(r *Report) { r.Findings[0].Vulnerability.CVSSScore = -0.1 },
		"cvss NaN":             func(r *Report) { r.Findings[0].Vulnerability.CVSSScore = math.NaN() },
		"epss above 1":         func(r *Report) { r.Findings[0].Vulnerability.EPSSScore = 7 },
		"epss percentile 0-100": func(r *Report) {
			r.Findings[0].Vulnerability.EPSSPercentile = 97.5
		},
		"vpr":                     func(r *Report) { r.Findings[0].Vulnerability.VPRScore = math.Inf(1) },
		"dependency without name": func(r *Report) { r.Dependencies = []Dependency{{Version: "1"}} },
		"duplicate dependency id": func(r *Report) {
			r.Dependencies = []Dependency{{ID: "d", Name: "a"}, {ID: "d", Name: "b"}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := validReport()
			mutate(r)
			if err := r.Validate(); err == nil {
				t.Errorf("%s must fail validation", name)
			}
		})
	}

	// Accepted: any minor of major 1, a report without tool, findings
	// without asset_ref, boundary scores.
	r := validReport()
	r.Version = "1.42"
	r.Tool = nil
	r.Findings[0].AssetRef = ""
	r.Findings[0].Vulnerability = &VulnerabilityDetails{CVSSScore: 10, EPSSScore: 1, EPSSPercentile: 0}
	if err := r.Validate(); err != nil {
		t.Errorf("must pass: %v", err)
	}
}

func TestReport_Validate_ReportsAllProblemsCapped(t *testing.T) {
	r := validReport()
	r.Version = ""
	for i := 0; i < 500; i++ {
		r.Findings = append(r.Findings, Finding{})
	}
	err := r.Validate()
	if err == nil {
		t.Fatal("must fail")
	}
	if n := strings.Count(err.Error(), "; ") + 1; n != maxValidateProblems {
		t.Errorf("listed %d problems, want the cap %d", n, maxValidateProblems)
	}
	if !strings.Contains(err.Error(), "version is required") {
		t.Error("the first problems must be listed")
	}
}
