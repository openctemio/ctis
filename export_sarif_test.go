package ctis

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// sarifRoundTrip reads a SARIF fixture, exports it and reads it back.
func sarifRoundTrip(t *testing.T, data []byte, opts *ConvertOptions) (first, second *Report, out []byte) {
	t.Helper()
	first, err := FromSARIF(data, opts)
	if err != nil {
		t.Fatal(err)
	}
	out, err = ToSARIF(first)
	if err != nil {
		t.Fatal(err)
	}
	second, err = FromSARIF(out, opts)
	if err != nil {
		t.Fatal(err)
	}
	second.Metadata.GeneratedAt = first.Metadata.GeneratedAt
	return first, second, out
}

func TestExportSARIFRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		losses  string
		golden  string
		opts    *ConvertOptions
	}{
		{"features", "export/sarif/features.sarif", "sarif/features.losses.json", "export/sarif/features.golden.sarif", nil},
		{"semgrep", "sarif/semgrep.sarif", "sarif/semgrep.losses.json", "", nil},
		{"semgrep-suppressed", "sarif/semgrep-suppressed.sarif", "sarif/semgrep-suppressed.losses.json", "", nil},
		{"codeql", "sarif/codeql.sarif", "sarif/codeql.losses.json", "", nil},
		{"trivy", "sarif/trivy.sarif", "sarif/trivy.losses.json", "", nil},
		{"kinds", "sarif/kinds.sarif", "sarif/kinds.losses.json", "", nil},
		{"betterleaks", "sarif/betterleaks.sarif", "sarif/betterleaks.losses.json", "", nil},
		{"repository-asset", "sarif/semgrep.sarif", "sarif/semgrep.losses.json", "", &ConvertOptions{AssetType: AssetTypeRepository, AssetValue: "github.com/example/app", Branch: "main", CommitSHA: "abc123", DefaultConfidence: 90}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first, second, out := sarifRoundTrip(t, readTestdata(t, tc.fixture), tc.opts)
			if len(first.Findings) == 0 {
				t.Fatal("fixture has no findings")
			}
			for _, d := range ExportRoundTripDiff(t, first, second, tc.losses) {
				t.Error(d)
			}
			if tc.golden != "" {
				ExportCheckGolden(t, tc.golden, out)
			}
			// Deterministic: the same report gives the same bytes.
			again, err := ToSARIF(first)
			if err != nil || !bytes.Equal(again, out) {
				t.Fatalf("second export differs (err %v)", err)
			}
		})
	}
}

func TestExportSARIFNeverWritesRawSecret(t *testing.T) {
	raw := readTestdata(t, "sarif/gitleaks-unredacted.sarif")
	var log SARIFLog
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatal(err)
	}
	var secrets []string
	for _, r := range log.Runs[0].Results {
		for _, l := range r.Locations {
			if l.PhysicalLocation != nil && l.PhysicalLocation.Region != nil && l.PhysicalLocation.Region.Snippet != nil {
				secrets = append(secrets, l.PhysicalLocation.Region.Snippet.Text)
			}
		}
	}
	if len(secrets) == 0 {
		t.Fatal("fixture has no snippet")
	}
	// A report that still holds the raw value (a producer that skipped the
	// masking) must not leak it through the exporter.
	r := &Report{Version: SchemaVersion, Tool: &Tool{Name: "custom"}, Findings: []Finding{{
		Type: FindingTypeSecret, Title: "Leaked key " + secrets[0], Severity: SeverityHigh, RuleID: "generic-key",
		Location: &FindingLocation{Path: "config.env", StartLine: 1, Snippet: secrets[0]},
		Secret:   &SecretDetails{Type: "api_key", MaskedValue: secrets[0]},
	}}}
	out, err := ToSARIF(r)
	if err != nil {
		t.Fatal(err)
	}
	if ContainsSecret(string(out), secrets...) {
		t.Fatalf("raw secret in SARIF export:\n%s", out)
	}
	if r.Findings[0].Location.Snippet != secrets[0] {
		t.Fatal("the exporter modified the caller's report")
	}
}

func TestExportSARIFNativeReport(t *testing.T) {
	ts := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	score := 9.8
	r := &Report{
		Version:  SchemaVersion,
		Metadata: ReportMetadata{ID: testReportID, GeneratedAt: ts, Branch: &BranchInfo{Name: "main", CommitSHA: "abc", RepositoryURL: "https://git.example.com/app"}},
		Findings: []Finding{
			{Type: FindingTypeVulnerability, Title: "Critical CVE", Severity: SeverityCritical, RuleID: "CVE-2024-3094",
				Vulnerability: &VulnerabilityDetails{CWEIDs: []string{"CWE-506"}}, Scores: []Score{{System: ScoreSystemCVSS, Version: "3.1", Value: &score}}, Status: FindingStatusFalsePositive},
			{Type: FindingTypeCompliance, Title: "No rule", Severity: SeverityInfo, Kind: "pass", Confidence: 50,
				Location: &FindingLocation{LogicalLocation: &LogicalLocation{Name: "main"}}},
			{Type: FindingTypeMisconfiguration, Title: "", Message: "from message", Severity: "bogus",
				Suppression: &Suppression{Kind: "external", Status: "rejected", Reason: "disputed"},
				Location:    &FindingLocation{StartLine: 3}},
			{Type: FindingTypeSecret, Title: "Token", Severity: SeverityLow, RuleID: "tok",
				EvidenceItems: []EvidenceItem{{Kind: EvidenceKindRawText, Text: "x"}, {Kind: EvidenceKindHTTPExchange, HTTP: &EvidenceHTTP{
					Request: &EvidenceRequest{Method: "POST", URL: "https://a.example/x?token=abcdefgh", HTTPVersion: "HTTP/2",
						Headers: []EvidenceHeader{{Name: "Authorization", Value: "Bearer abcdefghijklmnop"}, {Name: "X-A", Value: "1"}, {Name: "X-A", Value: "2"}},
						Body:    "AAEC", BodyEncoding: BodyEncodingBase64},
					Response: &EvidenceResponse{Status: 401, HTTPVersion: "bad"},
				}, Sensitive: []SensitiveSpan{{Pointer: "/http/request/url", Start: intp(26), End: intp(34)}}}}},
		},
	}
	out, err := ToSARIF(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{`"repositoryUri": "https://git.example.com/app"`, `"security-severity": "9.8"`, `"ruleId": "ctis/compliance"`,
		`"kind": "external"`, `"status": "rejected"`, `"justification": "false_positive"`, `"binary": "AAEC"`, `token=********`, `"X-A": "1, 2"`,
		`"Authorization": "REDACTED"`, `"precision": "low"`, `"text": "from message"`, `"protocol": "http"`} {
		if !strings.Contains(s, want) {
			t.Errorf("export lacks %s:\n%s", want, s)
		}
	}
	if strings.Contains(s, "abcdefghijklmnop") || strings.Contains(s, "abcdefgh\"") {
		t.Errorf("sensitive value leaked:\n%s", s)
	}
	back, err := FromSARIF(out, nil)
	if err != nil {
		t.Fatal(err)
	}
	if back.Findings[0].Severity != SeverityCritical || back.Findings[0].Status != FindingStatusSuppressed ||
		back.Findings[2].Type != FindingTypeMisconfiguration || back.Findings[3].Type != FindingTypeSecret {
		t.Errorf("read back: %+v", back.Findings)
	}
	if _, err := ToSARIF(nil); err == nil {
		t.Error("nil report: no error")
	}
}

func TestExportSARIFSecuritySeverityBands(t *testing.T) {
	for _, s := range AllSeverities() {
		f := &Finding{Severity: s}
		v, ok := sarifSecuritySeverity(f)
		if s == SeverityUnknown {
			if ok {
				t.Errorf("unknown severity got a score %s", v)
			}
			continue
		}
		if !ok {
			t.Fatalf("%s: no score", s)
		}
		log := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[{"message":{"text":"t"},"properties":{"security-severity":"` + v + `"}}]}]}`)
		r, err := FromSARIF(log, nil)
		if err != nil || r.Findings[0].Severity != s {
			t.Errorf("%s -> %s -> %v (%v)", s, v, r.Findings[0].Severity, err)
		}
	}
}

func TestExportMaskSensitiveSpans(t *testing.T) {
	spans := []SensitiveSpan{{Pointer: "/p", Start: intp(2), End: intp(4)}, {Pointer: "/p", Start: intp(3), End: intp(6)}}
	if got := maskSensitiveSpans("abcdefgh", "/p", spans); got != "ab********gh" {
		t.Errorf("got %q", got)
	}
	if got := maskSensitiveSpans("abc", "/p", []SensitiveSpan{{Pointer: "/p", Start: intp(1), End: intp(9)}}); got != redactedSecret {
		t.Errorf("out of range: %q", got)
	}
	if got := maskSensitiveSpans("abc", "/q", spans); got != "abc" {
		t.Errorf("other pointer: %q", got)
	}
	if got := maskSensitiveSpans("", "/p", spans); got != "" {
		t.Errorf("empty: %q", got)
	}
}

// TestExportSARIFFromCTIS exports CTIS example reports and reads them back:
// every member SARIF carries comes back; the rest are the documented
// accepted losses of the sidecar.
func TestExportSARIFFromCTIS(t *testing.T) {
	for _, name := range []string{"sast", "secret"} {
		t.Run(name, func(t *testing.T) {
			var r Report
			if err := json.Unmarshal(readTestdataRoot(t, "examples/"+name+".json"), &r); err != nil {
				t.Fatal(err)
			}
			out, err := ToSARIF(&r)
			if err != nil {
				t.Fatal(err)
			}
			back, err := FromSARIF(out, &ConvertOptions{DefaultConfidence: 90})
			if err != nil {
				t.Fatal(err)
			}
			want := r
			want.Findings = make([]Finding, len(r.Findings))
			for i := range r.Findings {
				c, err := exportFinding(&r.Findings[i])
				if err != nil {
					t.Fatal(err)
				}
				want.Findings[i] = c
			}
			for _, d := range ExportRoundTripDiff(t, map[string]any{"findings": want.Findings}, map[string]any{"findings": back.Findings}, "sarif/ctis-"+name+".losses.json") {
				t.Error(d)
			}
		})
	}
}

func readTestdataRoot(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
