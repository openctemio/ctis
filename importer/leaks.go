package importer

import (
	"strings"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/fingerprint"
)

// The secret record of betterleaks (and of the gitleaks-compatible report
// format it kept): one JSON object per leaked secret.

// leakRecord is one record of a leaks report.
type leakRecord struct {
	Description string    `json:"Description"`
	StartLine   int       `json:"StartLine"`
	EndLine     int       `json:"EndLine"`
	StartColumn int       `json:"StartColumn"`
	EndColumn   int       `json:"EndColumn"`
	Line        string    `json:"Line"`
	Match       string    `json:"Match"`
	Secret      string    `json:"Secret"`
	File        string    `json:"File"`
	SymlinkFile string    `json:"SymlinkFile"`
	Commit      string    `json:"Commit"`
	Link        string    `json:"Link"`
	Entropy     float64   `json:"Entropy"`
	Author      string    `json:"Author"`
	Email       string    `json:"Email"`
	Date        string    `json:"Date"`
	Message     string    `json:"Message"`
	Tags        []flexStr `json:"Tags"`
	RuleID      string    `json:"RuleID"`
	Fingerprint string    `json:"Fingerprint"`
}

// leakFinding maps a leak record to a CTIS secret finding of the given
// tool. The raw secret never leaves this function: the snippet, the title
// and the message hold it masked the way FromSARIF masks a secret match
// (ctis.MaskSecretMatch), and the fingerprint input is the masked value
// (CTIS spec 5.2). The commit author and e-mail are kept: they say who
// committed the secret, which is who must rotate it.
func leakFinding(rec *leakRecord, tool string, key []byte) (ctis.Finding, bool) {
	rule := line(rec.RuleID, capShort)
	file := line(rec.File, 1024)
	if rule == "" || file == "" {
		return ctis.Finding{}, false
	}
	raw := rec.Secret
	if raw == "" {
		raw = rec.Match
	}
	desc := text(maskIn(rec.Description, raw), capTitle)
	if desc == "" {
		desc = rule
	}
	f := ctis.Finding{
		Type:       ctis.FindingTypeSecret,
		Title:      desc,
		Severity:   leakSeverity(rule),
		RuleID:     rule,
		Confidence: 85,
		Message:    line("Secret detected: "+desc+" in "+file, 8<<10),
		Location: &ctis.FindingLocation{
			Path:        file,
			StartLine:   nonNeg(rec.StartLine),
			EndLine:     nonNeg(rec.EndLine),
			StartColumn: nonNeg(rec.StartColumn),
			EndColumn:   nonNeg(rec.EndColumn),
			Commit:      commitOf(line(rec.Commit, 128), line(rec.Author, capShort), line(rec.Email, capShort), parseTime(rec.Date)),
		},
		Secret: &ctis.SecretDetails{
			Type:    leakSecretType(rule),
			Service: leakService(rule),
		},
		Native: &ctis.NativeIdentity{Scheme: ctis.NativeSchemeOther, VulnID: rule},
	}
	if rec.Entropy > 0 && rec.Entropy < 1e6 {
		f.Secret.Entropy = rec.Entropy
	}
	if raw != "" {
		f.Secret.MaskedValue = ctis.MaskSecretMatch(raw)
		f.Secret.Length = len([]rune(raw))
		if m := rec.Match; m != "" {
			f.Location.Snippet = text(maskIn(m, raw), 16<<10)
		}
	}
	// The source's own fingerprint is kept as a partial fingerprint; the
	// CTIS fingerprint (recipe v2) needs the HMAC digest of the secret, which
	// only a producer holding a key can make. Without a key it stays empty
	// and the receiver computes its own.
	if fp := line(rec.Fingerprint, 512); fp != "" && !containsSecret(fp, raw) {
		f.PartialFingerprints = map[string]string{leaksFingerprintKey: fp}
	}
	if len(key) > 0 && raw != "" {
		if d, err := fingerprint.NewSecretDigest(key, []byte(raw)); err == nil {
			f.Fingerprint = fingerprint.V2Secret(rec.File, rec.RuleID, d)
		}
	}
	f.Tags = addTags(nil, tool, "secret")
	for _, t := range rec.Tags {
		f.Tags = addTags(f.Tags, t.String())
	}
	extras(&f, "symlink_file", rec.SymlinkFile, "commit_link", rec.Link, "commit_message", maskIn(rec.Message, raw))
	// The secret, the match line and each secret-looking word of the match
	// are masked in every field, so a description or commit message that
	// repeats the bare secret, when only the match line was reported, does
	// not carry it.
	ctis.RedactSecretFinding(&f, rec.Secret, rec.Match)
	return f, true
}

// leaksFingerprintKey is the partial fingerprint key of the fingerprint a
// leaks report carries (commit:file:rule:line).
const leaksFingerprintKey = "leaksFingerprint/v1"

func nonNeg(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

// containsSecret reports whether s holds the raw secret (gitleaks
// fingerprints are commit:file:rule:line and never do, but a hostile file
// could put the secret there).
func containsSecret(s, raw string) bool {
	return len(raw) >= 4 && strings.Contains(s, raw)
}

// maskIn replaces every occurrence of the raw secret in s by its masked
// form; with no secret, s is returned unchanged.
func maskIn(s, raw string) string {
	if raw == "" || s == "" {
		return s
	}
	return strings.ReplaceAll(s, raw, ctis.MaskSecretMatch(raw))
}

// leakSeverity infers a severity from the rule id (leak reports carry
// none): cloud credentials and private keys are critical, anything else
// high.
func leakSeverity(ruleID string) ctis.Severity {
	id := strings.ToLower(ruleID)
	for _, p := range []string{"aws-access-key", "aws-secret", "gcp-service-account", "azure-", "private-key", "jwt-", "github-pat", "github-fine-grained", "gitlab-pat"} {
		if strings.Contains(id, p) {
			return ctis.SeverityCritical
		}
	}
	return ctis.SeverityHigh
}

// leakSecretType names the CTIS secret type of a rule id (the values the
// CTIS schema allows).
func leakSecretType(ruleID string) string {
	id := strings.ToLower(ruleID)
	switch {
	case strings.Contains(id, "private-key"):
		return "private_key"
	case strings.Contains(id, "ssh"):
		return "ssh_key"
	case strings.Contains(id, "jwt"):
		return "jwt"
	case strings.Contains(id, "aws"):
		return "aws_key"
	case strings.Contains(id, "gcp"):
		return "gcp_key"
	case strings.Contains(id, "azure"):
		return "azure_key"
	case strings.Contains(id, "password"):
		return "password"
	case strings.Contains(id, "token"):
		return "token"
	case strings.Contains(id, "api-key") || strings.Contains(id, "api_key"):
		return "api_key"
	case strings.Contains(id, "certificate") || strings.Contains(id, "cert"):
		return "certificate"
	}
	return "generic_secret"
}

// leakServices are matched in this order, so the result is stable.
var leakServices = []string{"aws", "gcp", "azure", "github", "gitlab", "slack", "stripe", "twilio", "sendgrid", "mailgun", "heroku", "npm", "pypi", "docker", "firebase", "telegram", "discord", "shopify"}

func leakService(ruleID string) string {
	id := strings.ToLower(ruleID)
	for _, s := range leakServices {
		if strings.Contains(id, s) {
			return s
		}
	}
	return ""
}
