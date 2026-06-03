package ctis

import "testing"

func validReport() *Report {
	return &Report{
		Version: "1.0",
		Findings: []Finding{
			{
				ID:       "f1",
				Type:     FindingTypeVulnerability,
				Title:    "Test finding",
				Severity: SeverityHigh,
				Status:   FindingStatusOpen,
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
