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
	Kind       string         `json:"kind,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
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
	return finding
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
		if v != "" {
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

	// Secret scanners
	secretTools := []string{"gitleaks", "trufflehog", "detect-secrets", "secret"}
	for _, t := range secretTools {
		if strings.Contains(name, t) {
			return FindingTypeSecret
		}
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
	if strings.Contains(name, "secret") || strings.Contains(name, "gitleaks") || strings.Contains(name, "trufflehog") {
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
