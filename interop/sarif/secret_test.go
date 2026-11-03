package ctis

import (
	"encoding/json"
	"strings"
	"testing"
)

// Fake credentials, assembled at run time so that no secret scanner flags the
// repository. awsKey matches gitleaks' aws-access-token rule.
var (
	awsKey      = "AKIA" + "IOSFODNN7EXAMPLF"
	shortSecret = "hunter2" + "pass"
)

// unredactedGitleaks is real gitleaks 8 SARIF output (run without --redact)
// with the matched secret restored into region.snippet, as gitleaks writes it.
func unredactedGitleaks(t *testing.T) []byte {
	t.Helper()
	b := string(readTestdata(t, "sarif/gitleaks-unredacted.sarif"))
	b = strings.ReplaceAll(b, "{{SECRET}}", awsKey)
	b = strings.ReplaceAll(b, "{{SHORT}}", shortSecret)
	return []byte(b)
}

// Secret scanners put the raw secret in the SARIF snippet. FromSARIF copied it
// into location.snippet, so the live credential was in the CTIS report.
func TestFromSARIF_SecretSnippetIsMasked(t *testing.T) {
	opts := DefaultConvertOptions()
	opts.AssetValue = "github.com/example/shop"
	report, err := FromSARIF(unredactedGitleaks(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	assertReportValid(t, loadSchemaSet(t), report)
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{awsKey, shortSecret} {
		if strings.Contains(string(out), raw) {
			t.Errorf("raw secret %q is in the CTIS report:\n%s", raw, out)
		}
	}
	if len(report.Findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(report.Findings))
	}
	want := []string{"AKIA********", "REDACTED"}
	for i, w := range want {
		f := report.Findings[i]
		if f.Type != FindingTypeSecret {
			t.Errorf("finding %d type = %q, want secret", i, f.Type)
		}
		if got := f.Location.Snippet; got != w {
			t.Errorf("finding %d snippet = %q, want %q", i, got, w)
		}
		if f.Secret != nil {
			t.Errorf("finding %d: secret block set (%+v); masked_value changes receiver fingerprints", i, f.Secret)
		}
	}
	// The second result repeats the secret in its message (the title).
	if got := report.Findings[1].Title; strings.Contains(got, shortSecret) || !strings.Contains(got, "REDACTED") {
		t.Errorf("title = %q, want the secret masked", got)
	}
}

func TestFromSARIF_SecretRedactionCases(t *testing.T) {
	const partial = "AKIAIOSFODNN..." // gitleaks --redact=25 keeps a prefix
	cases := []struct {
		name     string
		tool     string
		toolType string
		ruleTags string
		snippet  string
		want     string
	}{
		{"already redacted", "gitleaks", "", "", "REDACTED", "REDACTED"},
		{"asterisks", "trivy", "", `"secret"`, "****************", "****************"},
		{"partial redaction is masked again", "gitleaks", "", "", partial, "REDACTED"},
		{"long secret keeps a prefix", "betterleaks", "", "", awsKey, "AKIA********"},
		{"short secret is hidden", "gitleaks", "", "", shortSecret, "REDACTED"},
		{"secret tool under a sast override", "gitleaks", "sast", "", awsKey, "AKIA********"},
		{"unknown tool, secret rule tag", "acme-scanner", "", `"secret"`, awsKey, "AKIA********"},
		{"ToolType secret", "acme-scanner", "secret", "", awsKey, "AKIA********"},
		{"code finding is untouched", "semgrep", "", "", "password = os.Getenv(\"X\")", "password = os.Getenv(\"X\")"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snippet, _ := json.Marshal(tc.snippet)
			log := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"` + tc.tool + `","rules":[{"id":"r","properties":{"tags":[` + tc.ruleTags + `]}}]}},
			  "results":[{"ruleId":"r","message":{"text":"found ` + strings.Trim(string(snippet), `"`) + `"},
			    "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.env"},"region":{"startLine":1,"snippet":{"text":` + string(snippet) + `}}}}]}]}]}`
			opts := DefaultConvertOptions()
			opts.ToolType = tc.toolType
			report, err := FromSARIF([]byte(log), opts)
			if err != nil {
				t.Fatal(err)
			}
			f := report.Findings[0]
			if got := f.Location.Snippet; got != tc.want {
				t.Errorf("snippet = %q, want %q", got, tc.want)
			}
			if tc.want != tc.snippet && strings.Contains(f.Title, strings.TrimSpace(tc.snippet)) {
				t.Errorf("title %q still holds the secret", f.Title)
			}
		})
	}
}

func TestMaskSecret(t *testing.T) {
	for in, want := range map[string]string{
		"":                     "REDACTED",
		"abc":                  "REDACTED",
		"0123456789abcde":      "REDACTED", // 15
		"0123456789abcdef":     "0123********",
		"  0123456789abcdef  ": "0123********",
		"ключключключключключ":   "ключ********", // runes, not bytes
		strings.Repeat("x", 1e5): "xxxx********",
	} {
		if got := maskSecret(in); got != want {
			t.Errorf("maskSecret(%.20q) = %q, want %q", in, got, want)
		}
	}
}
