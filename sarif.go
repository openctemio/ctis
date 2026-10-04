package ctis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/openctemio/ctis/severity"
)

// =============================================================================
// SARIF Types (for parsing tool output)
// =============================================================================

// SARIFLog is the root SARIF document.
type SARIFLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema,omitempty"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single run of a tool.
type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Results     []SARIFResult     `json:"results"`
	Artifacts   []SARIFArtifact   `json:"artifacts,omitempty"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`
}

// SARIFTool describes the tool.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver contains tool metadata.
type SARIFDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version,omitempty"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	InformationURI  string      `json:"informationUri,omitempty"`
	Rules           []SARIFRule `json:"rules,omitempty"`
}

// SARIFRule describes a rule/check.
type SARIFRule struct {
	ID                   string           `json:"id"`
	Name                 string           `json:"name,omitempty"`
	ShortDescription     *SARIFMessage    `json:"shortDescription,omitempty"`
	FullDescription      *SARIFMessage    `json:"fullDescription,omitempty"`
	HelpURI              string           `json:"helpUri,omitempty"`
	Help                 *SARIFMessage    `json:"help,omitempty"`
	DefaultConfiguration *SARIFRuleConfig `json:"defaultConfiguration,omitempty"`
	Properties           map[string]any   `json:"properties,omitempty"`
}

// SARIFRuleConfig holds rule configuration.
type SARIFRuleConfig struct {
	Level string `json:"level,omitempty"`
}

// SARIFResult represents a finding.
type SARIFResult struct {
	RuleID string `json:"ruleId,omitempty"`
	// RuleIndex is the index of the rule in tool.driver.rules. Nil when the
	// result does not carry one (SARIF's default is -1, "absent").
	RuleIndex           *int                     `json:"ruleIndex,omitempty"`
	Rule                *SARIFReportingReference `json:"rule,omitempty"`
	Level               string                   `json:"level,omitempty"`
	Message             SARIFMessage             `json:"message"`
	Locations           []SARIFLocation          `json:"locations,omitempty"`
	Fingerprints        map[string]string        `json:"fingerprints,omitempty"`
	PartialFingerprints map[string]string        `json:"partialFingerprints,omitempty"`
	CorrelationGUID     string                   `json:"correlationGuid,omitempty"`
	BaselineState       string                   `json:"baselineState,omitempty"`
	// Kind is the evaluation state of the result: notApplicable, pass, fail,
	// review, open or informational (SARIF 2.1.0 section 3.27.9).
	Kind string `json:"kind,omitempty"`
	// Suppressions are the result's suppressions (SARIF 2.1.0 section
	// 3.27.23), e.g. a nosemgrep comment or a CodeQL alert suppression.
	Suppressions []SARIFSuppression `json:"suppressions,omitempty"`
	Properties   map[string]any     `json:"properties,omitempty"`
}

// SARIFSuppression is one SARIF suppression object (section 3.35).
type SARIFSuppression struct {
	// Kind is inSource or external.
	Kind string `json:"kind,omitempty"`
	// Status is accepted (the default when absent), underReview or rejected.
	Status        string `json:"status,omitempty"`
	Justification string `json:"justification,omitempty"`
}

// SARIFReportingReference is a result's reference to its rule
// (SARIF reportingDescriptorReference).
type SARIFReportingReference struct {
	ID    string `json:"id,omitempty"`
	Index *int   `json:"index,omitempty"`
}

// SARIFMessage holds text.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation represents a code location.
type SARIFLocation struct {
	PhysicalLocation *SARIFPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations,omitempty"`
}

// SARIFLogicalLocation names the function, method or class of a location.
type SARIFLogicalLocation struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}

// SARIFPhysicalLocation contains file/region info.
type SARIFPhysicalLocation struct {
	ArtifactLocation *SARIFArtifactLocation `json:"artifactLocation,omitempty"`
	Region           *SARIFRegion           `json:"region,omitempty"`
}

// SARIFArtifactLocation contains file path.
type SARIFArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseId string `json:"uriBaseId,omitempty"`
}

// SARIFRegion contains line/column info.
type SARIFRegion struct {
	StartLine   int           `json:"startLine,omitempty"`
	EndLine     int           `json:"endLine,omitempty"`
	StartColumn int           `json:"startColumn,omitempty"`
	EndColumn   int           `json:"endColumn,omitempty"`
	Snippet     *SARIFSnippet `json:"snippet,omitempty"`
}

// SARIFSnippet contains code snippet.
type SARIFSnippet struct {
	Text string `json:"text"`
}

// SARIFArtifact represents a scanned file.
type SARIFArtifact struct {
	Location SARIFArtifactLocation `json:"location"`
}

// SARIFInvocation contains execution details.
type SARIFInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	CommandLine         string `json:"commandLine,omitempty"`
}

// =============================================================================
// SARIF to CTIS Conversion
// =============================================================================

// ConvertOptions configures SARIF to CTIS conversion.
type ConvertOptions struct {
	// Asset to associate findings with
	AssetType  AssetType
	AssetValue string
	AssetID    string

	// Branch/commit info (legacy - use BranchInfo for full context)
	Branch    string
	CommitSHA string

	// Branch information for branch-aware finding lifecycle
	// Provides full CI/CD context for auto-resolve and expiry features
	BranchInfo *BranchInfo

	// Default confidence
	DefaultConfidence int

	// Tool type hints (for finding type detection)
	ToolType string // "sast", "sca", "secret", "iac", "web3"
}

// DefaultConvertOptions returns default conversion options.
func DefaultConvertOptions() *ConvertOptions {
	return &ConvertOptions{
		AssetType:         AssetTypeRepository,
		DefaultConfidence: 90,
	}
}

// FromSARIF converts a SARIF 2.1.0 log to a CTIS report.
//
// Every run is converted. The report's tool is the first run's driver; when
// the log has more than one run, each finding names its run's tool in
// properties["sarif_tool"].
//
// Mapping:
//   - severity: the GitHub "security-severity" score (result, then rule) via
//     severity.FromCVSS; else the result level, else the rule's default level;
//     else medium (SARIF's default level is warning).
//   - type: ConvertOptions.ToolType; else the rule's tags (vulnerability,
//     misconfiguration, secret, as Trivy writes them); else a CVE/GHSA rule
//     id means vulnerability; else the tool name.
//   - CWE: rule properties "cwe" (string or array) and tags such as
//     "external/cwe/cwe-079" (CodeQL) or "CWE-89: ..." (Semgrep).
//   - fingerprint: the result's "fingerprints" entry with the lowest key, so
//     the choice is deterministic; values over 64 characters are SHA-256
//     hashed. partialFingerprints are passed through unchanged as
//     partial_fingerprints.
//   - tags: properties.tags of the result, then of the rule, deduplicated
//     ignoring case in first-seen order; at most 50, each at most 128 bytes.
//
// The converter asserts no business context: the asset it creates has no
// criticality.
func FromSARIF(data []byte, opts *ConvertOptions) (*Report, error) {
	if opts == nil {
		opts = DefaultConvertOptions()
	}

	var sarif SARIFLog
	if err := json.Unmarshal(data, &sarif); err != nil {
		return nil, fmt.Errorf("parse sarif: %w", err)
	}

	report := NewReport()

	if len(sarif.Runs) == 0 {
		return report, nil
	}

	first := sarif.Runs[0].Tool.Driver
	report.Tool = &Tool{
		Name:    first.Name,
		Version: first.Version,
		InfoURL: first.InformationURI,
	}
	if report.Tool.Version == "" {
		report.Tool.Version = first.SemanticVersion
	}

	assetID := ""
	if opts.AssetValue != "" {
		assetID = opts.AssetID
		if assetID == "" {
			assetID = "asset-1"
		}
		report.Assets = append(report.Assets, Asset{
			ID:    assetID,
			Type:  opts.AssetType,
			Value: opts.AssetValue,
		})
	}

	// Set branch info for branch-aware finding lifecycle
	if opts.BranchInfo != nil {
		report.Metadata.Branch = opts.BranchInfo
	} else if opts.Branch != "" {
		// Fallback: create minimal BranchInfo from legacy fields
		report.Metadata.Branch = &BranchInfo{
			Name:      opts.Branch,
			CommitSHA: opts.CommitSHA,
		}
	}

	multiRun := len(sarif.Runs) > 1
	n := 0
	for ri := range sarif.Runs {
		run := &sarif.Runs[ri]
		driver := run.Tool.Driver
		ruleMap := make(map[string]*SARIFRule, len(driver.Rules))
		for i := range driver.Rules {
			ruleMap[driver.Rules[i].ID] = &driver.Rules[i]
		}

		for _, result := range run.Results {
			n++
			rule, ruleID := lookupRule(&result, driver.Rules, ruleMap)
			finding := convertSARIFResult(&result, rule, ruleID, driver.Name, opts)
			finding.ID = fmt.Sprintf("finding-%d", n)
			finding.AssetRef = assetID
			if multiRun {
				if finding.Properties == nil {
					finding.Properties = Properties{}
				}
				finding.Properties["sarif_tool"] = driver.Name
			}
			report.Findings = append(report.Findings, finding)
		}
	}

	report.Tool.Capabilities = detectCapabilities(first.Name, opts.ToolType)
	return report, nil
}

// lookupRule finds the rule a result refers to: by ruleId, else rule.id,
// else the rule index.
func lookupRule(result *SARIFResult, rules []SARIFRule, byID map[string]*SARIFRule) (*SARIFRule, string) {
	id := result.RuleID
	if id == "" && result.Rule != nil {
		id = result.Rule.ID
	}
	if id != "" {
		if r, ok := byID[id]; ok {
			return r, id
		}
	}
	idx := result.RuleIndex
	if idx == nil && result.Rule != nil {
		idx = result.Rule.Index
	}
	if idx != nil && *idx >= 0 && *idx < len(rules) {
		r := &rules[*idx]
		if id == "" {
			id = r.ID
		}
		return r, id
	}
	return nil, id
}

func convertSARIFResult(result *SARIFResult, rule *SARIFRule, ruleID, toolName string, opts *ConvertOptions) Finding {
	finding := Finding{
		Type:       detectResultType(rule, ruleID, toolName, opts.ToolType),
		Title:      result.Message.Text,
		Severity:   sarifSeverity(result, rule),
		Confidence: opts.DefaultConfidence,
		RuleID:     ruleID,
	}
	if finding.Title == "" && rule != nil && rule.ShortDescription != nil {
		finding.Title = rule.ShortDescription.Text
	}
	if finding.Title == "" {
		finding.Title = ruleID
	}

	var vuln VulnerabilityDetails
	if rule != nil {
		if rule.ShortDescription != nil {
			finding.Description = rule.ShortDescription.Text
		}
		if rule.Name != "" {
			finding.RuleName = rule.Name
		}
		if rule.HelpURI != "" {
			finding.References = append(finding.References, rule.HelpURI)
		}
		if precision, ok := rule.Properties["precision"].(string); ok {
			switch precision {
			case "very-high":
				finding.Confidence = 95
			case "high":
				finding.Confidence = 85
			case "medium":
				finding.Confidence = 70
			case "low":
				finding.Confidence = 50
			}
		}
		vuln.CWEIDs = sarifCWEs(rule.Properties)
		vuln.OWASPIDs = sarifOWASP(rule.Properties)
	}
	if cveIDPattern.MatchString(ruleID) {
		vuln.CVEID = strings.ToUpper(ruleID)
	}
	if len(vuln.CWEIDs) > 0 {
		vuln.CWEID = vuln.CWEIDs[0]
	}
	if vuln.CVEID != "" || len(vuln.CWEIDs) > 0 || len(vuln.OWASPIDs) > 0 {
		finding.Vulnerability = &vuln
	}

	branch, commit := opts.Branch, opts.CommitSHA
	if branch == "" && opts.BranchInfo != nil {
		branch, commit = opts.BranchInfo.Name, opts.BranchInfo.CommitSHA
	}
	if len(result.Locations) > 0 {
		loc := result.Locations[0]
		if loc.PhysicalLocation != nil || len(loc.LogicalLocations) > 0 {
			finding.Location = &FindingLocation{Branch: branch, CommitSHA: commit}
		}
		if pl := loc.PhysicalLocation; pl != nil {
			if pl.ArtifactLocation != nil {
				finding.Location.Path = pl.ArtifactLocation.URI
			}
			if r := pl.Region; r != nil {
				finding.Location.StartLine = r.StartLine
				finding.Location.EndLine = r.EndLine
				finding.Location.StartColumn = r.StartColumn
				finding.Location.EndColumn = r.EndColumn
				if r.Snippet != nil {
					finding.Location.Snippet = r.Snippet.Text
				}
			}
		}
		if len(loc.LogicalLocations) > 0 {
			ll := loc.LogicalLocations[0]
			finding.Location.LogicalLocation = &LogicalLocation{
				Name:               ll.Name,
				FullyQualifiedName: ll.FullyQualifiedName,
				Kind:               ll.Kind,
			}
		}
	}

	finding.Fingerprint = sarifFingerprint(result.Fingerprints)
	if len(result.PartialFingerprints) > 0 {
		finding.PartialFingerprints = make(map[string]string, len(result.PartialFingerprints))
		for k, v := range result.PartialFingerprints {
			finding.PartialFingerprints[k] = v
		}
	}
	finding.CorrelationID = result.CorrelationGUID
	finding.BaselineState = sarifBaselineState(result.BaselineState)
	finding.Kind = sarifKind(result.Kind)
	finding.Suppression, finding.Status = sarifSuppression(result.Suppressions)
	var ruleProps map[string]any
	if rule != nil {
		ruleProps = rule.Properties
	}
	finding.Tags = sarifTags(result.Properties, ruleProps)
	if finding.Type == FindingTypeSecret || isSecretTool(strings.ToLower(toolName)) {
		redactSecretFinding(&finding)
	}
	return finding
}

// redactedSecret replaces a secret, or a code line holding one, that is too
// short to show any of it.
const redactedSecret = "REDACTED"

// secretPrefixLen is how many leading characters of a secret maskSecret keeps,
// enough to recognise its kind (AKIA, ghp_, xoxb) and never enough to use it.
const secretPrefixLen = 4

// minMaskedPrefixLen is the shortest secret maskSecret shows a prefix of.
// Shorter ones (passwords, PINs) are hidden entirely.
const minMaskedPrefixLen = 16

// redactSecretFinding keeps a secret scanner's raw match out of the CTIS
// report. Secret scanners put the matched secret in the SARIF region snippet
// (gitleaks and betterleaks do unless run with --redact), and FromSARIF copied
// it into location.snippet, so the live credential travelled in the report and
// was stored wherever the report was. The snippet is masked, and the raw value
// is also masked wherever the title or description repeats it.
//
// The masked value is not written to secret.masked_value: receivers fingerprint
// secret findings by it (spec section 5.2), and setting it would change the
// identity of every finding already ingested from a SARIF secret scan.
func redactSecretFinding(f *Finding) {
	if f.Location == nil || f.Location.Snippet == "" {
		return
	}
	raw := f.Location.Snippet
	if isRedacted(raw) {
		return
	}
	masked := maskSecret(raw)
	f.Location.Snippet = masked
	if needle := strings.TrimSpace(raw); len(needle) >= 6 {
		f.Title = strings.ReplaceAll(f.Title, needle, masked)
		f.Description = strings.ReplaceAll(f.Description, needle, masked)
		f.Message = strings.ReplaceAll(f.Message, needle, masked)
	}
}

// isRedacted reports whether a scanner already fully redacted the snippet:
// gitleaks --redact writes "REDACTED", other tools mask with asterisks. A
// partial redaction (gitleaks --redact=N keeps part of the secret followed by
// "...") is masked again.
func isRedacted(s string) bool {
	t := strings.TrimSpace(s)
	return strings.EqualFold(t, redactedSecret) || strings.Trim(t, "*•") == ""
}

// maskSecret returns the first secretPrefixLen characters of a secret of at
// least minMaskedPrefixLen characters followed by asterisks, or redactedSecret
// for a shorter one. The masked form does not reveal the secret's length.
func maskSecret(s string) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) < minMaskedPrefixLen {
		return redactedSecret
	}
	return string(r[:secretPrefixLen]) + "********"
}

// Bounds on the tags FromSARIF carries, so a hostile or broken SARIF log
// cannot inflate every finding with an unbounded tag list.
const (
	// maxSARIFTags is the most tags one finding gets.
	maxSARIFTags = 50
	// maxSARIFTagLen is the longest tag kept, in bytes. Longer values are
	// dropped rather than cut, so no tag is invented by truncation.
	maxSARIFTagLen = 128
)

// sarifTags collects properties.tags from the result, then from its rule, into
// finding.tags. Order is first seen; duplicates are dropped ignoring case (the
// first spelling wins); surrounding whitespace is trimmed; empty, non-string
// and over-long (maxSARIFTagLen) entries are skipped; at most maxSARIFTags are
// kept. A string tags value is treated as a single tag.
func sarifTags(resultProps, ruleProps map[string]any) []string {
	var out []string
	seen := map[string]bool{}
	for _, props := range []map[string]any{resultProps, ruleProps} {
		var raw []any
		switch t := props["tags"].(type) {
		case string:
			raw = []any{t}
		case []any:
			raw = t
		}
		for _, v := range raw {
			if len(out) >= maxSARIFTags {
				return out
			}
			s, ok := v.(string)
			if !ok {
				continue
			}
			s = strings.TrimSpace(s)
			if s == "" || len(s) > maxSARIFTagLen {
				continue
			}
			key := strings.ToLower(s)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, s)
		}
	}
	return out
}

// sarifKind maps a SARIF result.kind onto the CTIS finding.kind vocabulary.
// SARIF spells one value in camelCase ("notApplicable"); CTIS uses snake_case
// ("not_applicable"). Matching ignores case and underscores, so a producer's
// "NotApplicable" or "not_applicable" also maps. Anything outside the six SARIF
// values returns "" (left unset): the CTIS schema would reject it, and an
// absent kind is not defaulted to SARIF's implicit "fail".
func sarifKind(kind string) string {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(kind), "_", "")) {
	case "notapplicable":
		return "not_applicable"
	case "pass":
		return "pass"
	case "fail":
		return "fail"
	case "review":
		return "review"
	case "open":
		return "open"
	case "informational":
		return "informational"
	default:
		return ""
	}
}

// maxSuppressionJustification is the longest suppression justification kept,
// in bytes; longer ones are cut.
const maxSuppressionJustification = 2048

// sarifSuppression maps a result's SARIF suppressions onto finding.suppression
// and finding.status. SARIF (section 3.27.23) calls a result suppressed when
// at least one suppression is accepted (an absent status means accepted) and
// none is underReview or rejected. The suppression carried is the first one
// with the deciding status: a rejected one, else one under review, else the
// first accepted one. Status is set to suppressed only for a suppressed
// result. Kinds and statuses outside SARIF's values are left unset.
func sarifSuppression(sups []SARIFSuppression) (*Suppression, FindingStatus) {
	if len(sups) == 0 {
		return nil, ""
	}
	rank := map[string]int{"rejected": 3, "under_review": 2, "accepted": 1}
	var pick *SARIFSuppression
	pickStatus := ""
	for i := range sups {
		st := sarifSuppressionStatus(sups[i].Status)
		if rank[st] > rank[pickStatus] {
			pick, pickStatus = &sups[i], st
		}
	}
	if pick == nil {
		return nil, ""
	}
	sup := &Suppression{
		Kind:          sarifSuppressionKind(pick.Kind),
		Status:        pickStatus,
		Justification: truncateUTF8(cleanSuppressionText(pick.Justification), maxSuppressionJustification),
	}
	if pickStatus == "accepted" {
		return sup, FindingStatusSuppressed
	}
	return sup, ""
}

func sarifSuppressionKind(kind string) string {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(kind), "_", "")) {
	case "insource":
		return "in_source"
	case "external":
		return "external"
	}
	return ""
}

// sarifSuppressionStatus maps a SARIF suppression status; absent means
// accepted, an unknown value returns "".
func sarifSuppressionStatus(status string) string {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(status), "_", "")) {
	case "", "accepted":
		return "accepted"
	case "underreview":
		return "under_review"
	case "rejected":
		return "rejected"
	}
	return ""
}

// cleanSuppressionText drops control characters other than tab and newline.
func cleanSuppressionText(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r != '\t' && r != '\n' && (r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0)) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, "\uFFFD")))
}

// truncateUTF8 cuts s to at most maxBytes bytes on a character boundary.
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// sarifBaselineState maps a SARIF result.baselineState onto CTIS
// finding.baseline_state (same four values). Unknown values are left unset.
func sarifBaselineState(state string) string {
	switch s := strings.ToLower(strings.TrimSpace(state)); s {
	case "new", "unchanged", "updated", "absent":
		return s
	default:
		return ""
	}
}

// sarifFingerprint picks the result fingerprint with the lowest key, so the
// same log always yields the same value (map iteration order is random).
// Values longer than 64 characters are SHA-256 hashed to fit receivers that
// store 64.
func sarifFingerprint(fps map[string]string) string {
	if len(fps) == 0 {
		return ""
	}
	keys := make([]string, 0, len(fps))
	for k, v := range fps {
		if v != "" && !isPlaceholderFingerprint(v) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	fp := fps[keys[0]]
	if len(fp) > 64 {
		hash := sha256.Sum256([]byte(fp))
		return hex.EncodeToString(hash[:])
	}
	return fp
}

// isPlaceholderFingerprint reports a fingerprint value that names no finding:
// Semgrep OSS writes "requires login" for every result's matchBasedId, which
// would give all of them the same fingerprint.
func isPlaceholderFingerprint(v string) bool {
	return strings.EqualFold(strings.TrimSpace(v), "requires login")
}

// sarifSeverity applies the precedence documented on FromSARIF.
func sarifSeverity(result *SARIFResult, rule *SARIFRule) Severity {
	if score, ok := securitySeverity(result.Properties); ok {
		return Severity(severity.FromCVSS(score))
	}
	if rule != nil {
		if score, ok := securitySeverity(rule.Properties); ok {
			return Severity(severity.FromCVSS(score))
		}
	}
	level := result.Level
	if level == "" && rule != nil && rule.DefaultConfiguration != nil {
		level = rule.DefaultConfiguration.Level
	}
	return mapSARIFLevel(level)
}

// securitySeverity reads the GitHub code scanning "security-severity"
// property, a CVSS-like score 0.0-10.0 sent as a string or a number.
func securitySeverity(props map[string]any) (float64, bool) {
	var score float64
	switch v := props["security-severity"].(type) {
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			return 0, false
		}
		score = f
	case float64:
		score = v
	default:
		return 0, false
	}
	if math.IsNaN(score) || score < 0 || score > 10 {
		return 0, false
	}
	return score, true
}

var (
	cweTagPattern   = regexp.MustCompile(`(?i)\bcwe[-_/:]?0*([0-9]+)\b`)
	owaspTagPattern = regexp.MustCompile(`\b(A(?:0[1-9]|10):20[0-9]{2})\b`)
	cveIDPattern    = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)
	ghsaIDPattern   = regexp.MustCompile(`(?i)^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`)
)

// sarifCWEs collects CWE ids, in first-seen order, from a rule's "cwe"
// property (string or array) and its tags.
func sarifCWEs(props map[string]any) []string {
	var raw []string
	raw = append(raw, stringOrStrings(props["cwe"])...)
	raw = append(raw, stringOrStrings(props["tags"])...)
	var out []string
	seen := map[string]bool{}
	for _, s := range raw {
		for _, m := range cweTagPattern.FindAllStringSubmatch(s, -1) {
			id := "CWE-" + m[1]
			if m[1] == "" || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// sarifOWASP collects OWASP Top 10 ids (A03:2021) from a rule's tags and
// "owasp" property.
func sarifOWASP(props map[string]any) []string {
	var raw []string
	raw = append(raw, stringOrStrings(props["owasp"])...)
	raw = append(raw, stringOrStrings(props["tags"])...)
	var out []string
	seen := map[string]bool{}
	for _, s := range raw {
		for _, m := range owaspTagPattern.FindAllStringSubmatch(s, -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, m[1])
			}
		}
	}
	return out
}

func stringOrStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// mapSARIFLevel converts SARIF level to CTIS severity.
func mapSARIFLevel(level string) Severity {
	switch strings.ToLower(level) {
	case "error":
		return SeverityHigh
	case "warning":
		return SeverityMedium
	case "note":
		return SeverityLow
	case "none":
		return SeverityInfo
	default:
		return SeverityMedium
	}
}

// detectResultType works out one result's finding type, in the order
// documented on FromSARIF.
func detectResultType(rule *SARIFRule, ruleID, toolName, toolType string) FindingType {
	switch toolType {
	case "secret":
		return FindingTypeSecret
	case "iac":
		return FindingTypeMisconfiguration
	case "web3":
		return FindingTypeWeb3
	case "sca", "sast":
		return FindingTypeVulnerability
	}
	if rule != nil {
		for _, tag := range stringOrStrings(rule.Properties["tags"]) {
			switch strings.ToLower(strings.TrimSpace(tag)) {
			case "vulnerability":
				return FindingTypeVulnerability
			case "misconfiguration":
				return FindingTypeMisconfiguration
			case "secret":
				return FindingTypeSecret
			}
		}
	}
	if cveIDPattern.MatchString(ruleID) || ghsaIDPattern.MatchString(ruleID) {
		return FindingTypeVulnerability
	}
	return detectFindingType(toolName, toolType)
}

// detectFindingType determines finding type based on tool name.
func detectFindingType(toolName string, toolType string) FindingType {
	name := strings.ToLower(toolName)

	// Explicit tool type
	switch toolType {
	case "secret":
		return FindingTypeSecret
	case "iac":
		return FindingTypeMisconfiguration
	case "web3":
		return FindingTypeWeb3
	case "sca", "sast":
		return FindingTypeVulnerability
	}

	if isSecretTool(name) {
		return FindingTypeSecret
	}

	// Web3 scanners
	web3Tools := []string{"slither", "mythril", "securify", "manticore", "echidna", "aderyn"}
	for _, t := range web3Tools {
		if strings.Contains(name, t) {
			return FindingTypeWeb3
		}
	}

	// IaC scanners
	iacTools := []string{"trivy", "checkov", "tfsec", "terrascan", "kics"}
	for _, t := range iacTools {
		if strings.Contains(name, t) {
			return FindingTypeMisconfiguration
		}
	}

	// Default to vulnerability
	return FindingTypeVulnerability
}

// secretToolNames are secret scanners, matched as substrings of the lowercased
// tool name. betterleaks is a gitleaks fork with its own driver name.
var secretToolNames = []string{"gitleaks", "betterleaks", "trufflehog", "detect-secrets", "secret"}

// isSecretTool reports whether a lowercased tool name is a secret scanner.
func isSecretTool(name string) bool {
	for _, t := range secretToolNames {
		if strings.Contains(name, t) {
			return true
		}
	}
	return false
}

// sastToolNames are static analysers whose SARIF is code findings.
var sastToolNames = []string{
	"semgrep", "codeql", "gosec", "bandit", "sonarqube", "sonarcloud",
	"eslint", "brakeman", "spotbugs", "njsscan", "horusec", "bearer",
	"psalm", "phpstan", "flawfinder", "cppcheck",
}

// detectCapabilities determines tool capabilities. The values are the
// capability vocabulary of report.json; receivers derive the detection
// technique from them.
func detectCapabilities(toolName string, toolType string) []string {
	name := strings.ToLower(toolName)

	switch toolType {
	case "secret":
		return []string{"secret"}
	case "iac":
		return []string{"misconfiguration"}
	case "web3":
		return []string{"web3"}
	case "sca":
		return []string{"sca"}
	case "sast":
		return []string{"sast"}
	}

	// Auto-detect
	if isSecretTool(name) {
		return []string{"secret"}
	}
	if strings.Contains(name, "slither") || strings.Contains(name, "mythril") {
		return []string{"web3"}
	}
	if strings.Contains(name, "trivy") || strings.Contains(name, "checkov") {
		return []string{"vulnerability", "misconfiguration"}
	}
	for _, t := range sastToolNames {
		if strings.Contains(name, t) {
			return []string{"sast"}
		}
	}

	return []string{"vulnerability"}
}
