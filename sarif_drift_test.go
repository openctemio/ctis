package ctis

import "testing"

// A SARIF result with no result-level "level" must inherit the rule's
// defaultConfiguration.level (SARIF spec) instead of collapsing to medium.
func TestFromSARIF_RuleLevelSeverityFallback(t *testing.T) {
	sarif := []byte(`{
	  "version": "2.1.0",
	  "runs": [{
	    "tool": {"driver": {"name": "demo", "rules": [
	      {"id": "RULE-CRIT", "defaultConfiguration": {"level": "error"}},
	      {"id": "RULE-NOTE", "defaultConfiguration": {"level": "note"}}
	    ]}},
	    "results": [
	      {"ruleId": "RULE-CRIT", "message": {"text": "no result level → use rule error"}},
	      {"ruleId": "RULE-NOTE", "message": {"text": "no result level → use rule note"}},
	      {"ruleId": "RULE-CRIT", "level": "warning", "message": {"text": "result level wins"}}
	    ]
	  }]
	}`)

	report, err := FromSARIF(sarif, nil)
	if err != nil {
		t.Fatalf("FromSARIF: %v", err)
	}
	if len(report.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(report.Findings))
	}
	if report.Findings[0].Severity != SeverityHigh {
		t.Errorf("rule error → High, got %s", report.Findings[0].Severity)
	}
	if report.Findings[1].Severity != SeverityLow {
		t.Errorf("rule note → Low, got %s", report.Findings[1].Severity)
	}
	if report.Findings[2].Severity != SeverityMedium {
		t.Errorf("result warning overrides rule → Medium, got %s", report.Findings[2].Severity)
	}
}

func TestFindingStatus_IsValid_IncludesSuppressed(t *testing.T) {
	if !FindingStatusSuppressed.IsValid() {
		t.Error("suppressed must be a valid finding status (schema parity)")
	}
	for _, s := range AllFindingStatuses() {
		if !s.IsValid() {
			t.Errorf("%s in AllFindingStatuses but not IsValid", s)
		}
	}
	if FindingStatus("bogus").IsValid() {
		t.Error("bogus must be invalid")
	}
}
