package importer

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/openctemio/ctis"
)

// gitleaks JSON report: an array of leaks. The mapping is spec_gitleaks.go.
//
// The raw secret never leaves the parser: Secret is masked with the rule of
// the root package's SARIF converter (the first four characters of a value
// of at least 16 characters, else REDACTED), and Match and Line, which hold
// the secret with its context, are not read. The commit author, e-mail and
// message are personal data and are not read either.

func init() {
	parsers[FormatGitleaks] = parseGitleaks
	tools[FormatGitleaks] = ctis.Tool{Name: "gitleaks", Capabilities: []string{"secret"}}
}

type glLeak struct {
	Description string    `json:"Description"`
	StartLine   flexStr   `json:"StartLine"`
	EndLine     flexStr   `json:"EndLine"`
	StartColumn flexStr   `json:"StartColumn"`
	EndColumn   flexStr   `json:"EndColumn"`
	Secret      string    `json:"Secret"`
	File        string    `json:"File"`
	SymlinkFile string    `json:"SymlinkFile"`
	Commit      string    `json:"Commit"`
	Entropy     flexStr   `json:"Entropy"`
	Date        string    `json:"Date"`
	Tags        []flexStr `json:"Tags"`
	RuleID      string    `json:"RuleID"`
	Fingerprint string    `json:"Fingerprint"`
	Link        string    `json:"Link"`
}

// glRedacted and the prefix rule are the root package's SARIF secret
// masking (maskSecret), repeated here because it is not exported.
const (
	glRedacted     = "REDACTED"
	glPrefixLen    = 4
	glMinPrefixLen = 16
)

// glMask masks a secret: its first four characters followed by asterisks
// when it has at least 16, else REDACTED. The length is not revealed.
func glMask(s string) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) < glMinPrefixLen {
		return glRedacted
	}
	return string(r[:glPrefixLen]) + "********"
}

// glScrub replaces every occurrence of the secret in a text with its mask.
func glScrub(s, secret, masked string) string {
	if needle := strings.TrimSpace(secret); len(needle) >= 6 {
		s = strings.ReplaceAll(s, needle, masked)
	}
	return s
}

const glItems = "/[]"

func parseGitleaks(b *builder, r io.Reader) error {
	data, err := readAll(r, FormatGitleaks, b.lim)
	if err != nil {
		return err
	}
	doc, err := scanJSON(data, FormatGitleaks, b.lim, b.obs, glItems)
	if err != nil {
		return err
	}
	var raw []json.RawMessage
	if err := doc.decode(&raw); err != nil {
		return err
	}
	var assetID string
	for i, item := range raw {
		b.res.Stats.Records++
		if err := b.tick(); err != nil {
			return err
		}
		ptr := "/" + strconv.Itoa(i)
		var l glLeak
		if err := json.Unmarshal(item, &l); err != nil {
			b.issue(doc.issueAt(glItems, i, ptr, "skipped: "+jsonErrText(err)))
			b.res.Stats.Skipped++
			continue
		}
		rule := line(l.RuleID, capShort)
		if rule == "" {
			b.issue(doc.issueAt(glItems, i, ptr, "leak without a RuleID: skipped"))
			b.res.Stats.Skipped++
			continue
		}
		if assetID == "" {
			if assetID, err = b.asset(b.defaultAsset()); err != nil {
				return err
			}
		}
		if err := b.finding(glFinding(&l, rule, assetID, ptr)); err != nil {
			return err
		}
	}
	return nil
}

func glFinding(l *glLeak, rule, assetID, ptr string) ctis.Finding {
	masked := glRedacted
	if strings.TrimSpace(l.Secret) != "" {
		masked = glMask(l.Secret)
	}
	desc := glScrub(l.Description, l.Secret, masked)
	title := line(desc, capTitle)
	if title == "" {
		title = rule
	}
	f := ctis.Finding{
		Type:        ctis.FindingTypeSecret,
		Title:       title,
		Severity:    ctis.SeverityHigh,
		RuleID:      rule,
		RuleName:    title,
		AssetRef:    assetID,
		Description: text(desc, capDescription),
		Native: &ctis.NativeIdentity{
			Scheme:     ctis.NativeSchemeOther,
			VulnID:     line(rule, ctis.MaxNativeIDLen),
			InstanceID: line(glScrub(l.Fingerprint, l.Secret, masked), ctis.MaxNativeIDLen),
			RawRef:     ptr,
		},
		Secret: &ctis.SecretDetails{SecretType: glSecretType(rule)},
	}
	if e, err := strconv.ParseFloat(l.Entropy.String(), 64); err == nil && e >= 0 && e < 1e6 {
		f.Secret.Entropy = e
	}
	if p := line(l.File, 1024); p != "" {
		loc := &ctis.FindingLocation{Path: p, Snippet: masked, CommitSHA: line(l.Commit, 64)}
		loc.StartLine = glInt(l.StartLine)
		loc.EndLine = glInt(l.EndLine)
		loc.StartColumn = glInt(l.StartColumn)
		loc.EndColumn = glInt(l.EndColumn)
		if loc.EndLine < loc.StartLine {
			loc.EndLine = 0
		}
		f.Location = loc
	}
	if d := parseTime(l.Date); d != nil {
		f.CommitDate = d
	}
	for _, t := range l.Tags {
		f.Tags = addTags(f.Tags, t.String())
	}
	if validURL(l.Link) {
		f.References = addRefs(f.References, l.Link)
	}
	if l.Commit != "" && f.Location == nil {
		extra(&f, "commit", l.Commit)
	}
	extra(&f, "symlink_file", l.SymlinkFile)
	return f
}

func glInt(s flexStr) int {
	n, err := strconv.Atoi(s.String())
	if err != nil || n < 0 || n > 1<<30 {
		return 0
	}
	return n
}

// glSecretType maps a rule id to the CTIS secret type vocabulary; the rule
// id itself is kept as native.vuln_id.
func glSecretType(rule string) string {
	r := strings.ToLower(rule)
	has := func(words ...string) bool {
		for _, w := range words {
			if strings.Contains(r, w) {
				return true
			}
		}
		return false
	}
	switch {
	case has("private-key", "private_key", "privatekey"):
		return "private_key"
	case has("ssh"):
		return "ssh_key"
	case has("aws"):
		return "aws_key"
	case has("gcp", "google"):
		return "gcp_key"
	case has("azure"):
		return "azure_key"
	case has("jwt"):
		return "jwt"
	case has("oauth", "client-secret", "client_secret"):
		return "oauth"
	case has("postgres", "mysql", "mongodb", "database", "jdbc", "redis"):
		return "database_credential"
	case has("password", "passwd"):
		return "password"
	case has("certificate", "pkcs"):
		return "certificate"
	case has("encryption", "age-secret"):
		return "encryption_key"
	case has("api-key", "apikey", "api_key"):
		return "api_key"
	case has("token", "pat"):
		return "token"
	}
	return "generic_secret"
}
