package ctis

import (
	"fmt"
	"strings"
)

// Validate checks a report's structural invariants — required fields and enum
// membership — using only the standard library (CTIS is intentionally
// zero-external-dependency). It is the canonical integrity gate: producers
// (agents/SDK) and consumers (the API ingest boundary) should reject a report
// that fails Validate rather than persist malformed or schema-drifted data.
//
// Validate reports ALL problems it finds in one error (joined with "; ") so a
// caller sees the full picture rather than fixing one issue at a time. It does
// not mutate the report and makes no network/IO calls.
func (r *Report) Validate() error {
	if r == nil {
		return fmt.Errorf("invalid CTIS report: report is nil")
	}

	var problems []string

	if strings.TrimSpace(r.Version) == "" {
		problems = append(problems, "version is required")
	}

	for i, f := range r.Findings {
		if strings.TrimSpace(f.Title) == "" {
			problems = append(problems, fmt.Sprintf("findings[%d]: title is required", i))
		}
		if !f.Type.IsValid() {
			problems = append(problems, fmt.Sprintf("findings[%d]: invalid type %q", i, f.Type))
		}
		if !f.Severity.IsValid() {
			problems = append(problems, fmt.Sprintf("findings[%d]: invalid severity %q", i, f.Severity))
		}
		// Status is optional; validate only when set.
		if f.Status != "" && !f.Status.IsValid() {
			problems = append(problems, fmt.Sprintf("findings[%d]: invalid status %q", i, f.Status))
		}
	}

	for i, a := range r.Assets {
		if strings.TrimSpace(a.Value) == "" {
			problems = append(problems, fmt.Sprintf("assets[%d]: value is required", i))
		}
		if !a.Type.IsValid() {
			problems = append(problems, fmt.Sprintf("assets[%d]: invalid type %q", i, a.Type))
		}
		// Criticality is optional; validate only when set.
		if a.Criticality != "" && !a.Criticality.IsValid() {
			problems = append(problems, fmt.Sprintf("assets[%d]: invalid criticality %q", i, a.Criticality))
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid CTIS report: %s", strings.Join(problems, "; "))
	}
	return nil
}
