package sarif

import (
	"encoding/json"
	"testing"
)

// SARIF result.kind is the evaluation state of a result. CTIS carries it as
// finding.kind, in snake_case (the SARIF spelling "notApplicable" becomes
// "not_applicable"). Import used to drop it, so every SARIF-sourced finding
// lost the difference between a failed check and a passed or inapplicable one.
// Values outside SARIF's set are left unset rather than emitted, since the
// schema enum would reject them.
func TestFromSARIF_ResultKindAndBaselineState(t *testing.T) {
	report, err := Import(readTestdata(t, "sarif/kinds.sarif"), nil)
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

// kindAndBaseline imports a one-result log whose result has the given kind
// and baselineState (the mapping's set rules decide both).
func kindAndBaseline(t *testing.T, kind, baseline string) (string, string) {
	t.Helper()
	res := map[string]any{"ruleId": "r", "message": map[string]any{"text": "m"}, "kind": kind, "baselineState": baseline}
	log := map[string]any{"version": "2.1.0", "runs": []any{map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "t"}}, "results": []any{res}}}}
	data, err := json.Marshal(log)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Import(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r.Findings[0].Kind, r.Findings[0].BaselineState
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
		"\treview\n":     "review",
	}
	for in, want := range cases {
		if got, _ := kindAndBaseline(t, in, ""); got != want {
			t.Errorf("kind %q = %q, want %q", in, got, want)
		}
	}
	if _, got := kindAndBaseline(t, "", "Unchanged"); got != "unchanged" {
		t.Errorf("baselineState Unchanged = %q, want unchanged", got)
	}
	if _, got := kindAndBaseline(t, "", "modified"); got != "" {
		t.Errorf("baselineState modified = %q, want unset", got)
	}
}
