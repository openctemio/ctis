package ctis

import (
	"encoding/json"
	"strings"
	"testing"
)

// SARIF suppressions (a nosemgrep comment, a CodeQL alert suppression) were
// dropped, so a suppressed result looked like an open finding.
func TestFromSARIF_Suppressions(t *testing.T) {
	cases := []struct {
		name        string
		sups        string
		wantKind    string
		wantStatus  string
		wantFinding FindingStatus
	}{
		{"none", ``, "", "", ""},
		{"empty list", `[]`, "", "", ""},
		{"inSource, status absent means accepted", `[{"kind":"inSource"}]`, "in_source", "accepted", FindingStatusSuppressed},
		{"external accepted", `[{"kind":"external","status":"accepted","justification":"baseline"}]`, "external", "accepted", FindingStatusSuppressed},
		{"under review is not suppressed", `[{"kind":"external","status":"underReview"}]`, "external", "under_review", ""},
		{"rejected wins over accepted", `[{"kind":"inSource"},{"kind":"external","status":"rejected"}]`, "external", "rejected", ""},
		{"under review wins over accepted", `[{"kind":"inSource","status":"accepted"},{"kind":"external","status":"under_review"}]`, "external", "under_review", ""},
		{"unknown kind left unset", `[{"kind":"bogus"}]`, "", "accepted", FindingStatusSuppressed},
		{"unknown status ignored", `[{"kind":"inSource","status":"maybe"}]`, "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sup := ""
			if tc.sups != "" {
				sup = `,"suppressions":` + tc.sups
			}
			log := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[{"ruleId":"r","message":{"text":"m"}` + sup + `}]}]}`
			r, err := FromSARIF([]byte(log), nil)
			if err != nil {
				t.Fatal(err)
			}
			assertReportValid(t, loadSchemaSet(t), r)
			f := r.Findings[0]
			if f.Status != tc.wantFinding {
				t.Errorf("status = %q, want %q", f.Status, tc.wantFinding)
			}
			if tc.wantStatus == "" {
				if f.Suppression != nil {
					t.Errorf("suppression = %+v, want none", f.Suppression)
				}
				return
			}
			if f.Suppression == nil || f.Suppression.Kind != tc.wantKind || f.Suppression.Status != tc.wantStatus {
				t.Errorf("suppression = %+v, want kind %q status %q", f.Suppression, tc.wantKind, tc.wantStatus)
			}
		})
	}
}

// A hostile justification is bounded and loses control characters.
func TestFromSARIF_SuppressionJustificationHostile(t *testing.T) {
	just := "ok\x1b[31m\x00\nnext " + strings.Repeat("é", 5000)
	b, _ := json.Marshal(just)
	log := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[{"ruleId":"r","message":{"text":"m"},"suppressions":[{"kind":"external","justification":` + string(b) + `}]}]}]}`
	r, err := FromSARIF([]byte(log), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := r.Findings[0].Suppression.Justification
	if len(got) > maxSuppressionJustification {
		t.Errorf("justification is %d bytes, cap %d", len(got), maxSuppressionJustification)
	}
	if strings.ContainsAny(got, "\x1b\x00") || !strings.HasPrefix(got, "ok[31m\nnext ") {
		t.Errorf("justification = %.40q", got)
	}
	if !json.Valid([]byte(`"` + strings.ReplaceAll(got, "\n", `\n`) + `"`)) {
		t.Error("justification was cut inside a character")
	}
}

// Semgrep OSS writes "requires login" as every result's matchBasedId; it is
// not a fingerprint.
func TestFromSARIF_PlaceholderFingerprintIgnored(t *testing.T) {
	r, err := FromSARIF(readTestdata(t, "sarif/semgrep-suppressed.sarif"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range r.Findings {
		if f.Fingerprint != "" {
			t.Errorf("finding %d fingerprint = %q, want unset", i, f.Fingerprint)
		}
	}
	if got := sarifFingerprint(map[string]string{"a": "Requires Login", "b": "abc"}); got != "abc" {
		t.Errorf("sarifFingerprint skipped to %q, want abc", got)
	}
}

func TestTruncateUTF8(t *testing.T) {
	if got := truncateUTF8("aé", 2); got != "a" {
		t.Errorf("got %q", got)
	}
	if got := truncateUTF8("abc", 5); got != "abc" {
		t.Errorf("got %q", got)
	}
}
