package ctis

import "testing"

// SARIF result.kind is the evaluation state of a result. CTIS carries it as
// finding.kind, in snake_case (the SARIF spelling "notApplicable" becomes
// "not_applicable"). FromSARIF used to drop it, so every SARIF-sourced finding
// lost the difference between a failed check and a passed or inapplicable one.
// Values outside SARIF's set are left unset rather than emitted, since the
// schema enum would reject them.
func TestFromSARIF_ResultKindAndBaselineState(t *testing.T) {
	report, err := FromSARIF(readTestdata(t, "sarif/kinds.sarif"), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ kind, baseline string }{
		{"fail", "new"},
		{"review", "unchanged"},
		{"not_applicable", ""},
		{"pass", "absent"},
		{"open", ""},
		{"informational", "updated"},
		{"", ""}, // "warning" / "modified" are not SARIF values
		{"", ""}, // absent kind: left unset, not defaulted
	}
	if len(report.Findings) != len(want) {
		t.Fatalf("got %d findings, want %d", len(report.Findings), len(want))
	}
	for i, w := range want {
		f := report.Findings[i]
		if f.Kind != w.kind || f.BaselineState != w.baseline {
			t.Errorf("finding %d (%q): kind=%q baseline_state=%q, want %q/%q", i, f.Title, f.Kind, f.BaselineState, w.kind, w.baseline)
		}
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("converter output fails Validate: %v", err)
	}
}

func TestSARIFKind_Spellings(t *testing.T) {
	cases := map[string]string{
		"notApplicable":  "not_applicable",
		"NotApplicable":  "not_applicable",
		"not_applicable": "not_applicable",
		"pass":           "pass",
		"FAIL":           "fail",
		"Review":         "review",
		"open":           "open",
		"informational":  "informational",
		"":               "",
		"warning":        "",
		"notapplicable":  "not_applicable",
	}
	for in, want := range cases {
		if got := sarifKind(in); got != want {
			t.Errorf("sarifKind(%q) = %q, want %q", in, got, want)
		}
	}
	if got := sarifKind("\treview\n"); got != "review" {
		t.Errorf("surrounding whitespace: sarifKind = %q, want review", got)
	}
	if got := sarifBaselineState("Unchanged"); got != "unchanged" {
		t.Errorf("sarifBaselineState(Unchanged) = %q, want unchanged", got)
	}
	if got := sarifBaselineState("modified"); got != "" {
		t.Errorf("sarifBaselineState(modified) = %q, want unset", got)
	}
}
