package sarif

import (
	"github.com/openctemio/ctis/v2"

	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/openctemio/ctis/v2/severity"
)

// =============================================================================
// SARIF Types (for parsing tool output)
// =============================================================================

// Log is the root SARIF document.
type Log struct {
	Version string `json:"version"`
	Schema  string `json:"$schema,omitempty"`
	Runs    []Run  `json:"runs"`
}

// Run represents a single run of a tool.
type Run struct {
	Tool        Tool         `json:"tool"`
	Results     []Result     `json:"results"`
	Artifacts   []Artifact   `json:"artifacts,omitempty"`
	Invocations []Invocation `json:"invocations,omitempty"`
	// OriginalURIBaseIDs maps a uriBaseId to the absolute location it stood
	// for on the scanning machine (SARIF 2.1.0 section 3.14.14). Only used
	// to make the absolute paths of a taint trace repository-relative; kept
	// raw so a malformed value never fails the log.
	OriginalURIBaseIDs json.RawMessage `json:"originalUriBaseIds,omitempty"`
}

// Tool describes the tool.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver contains tool metadata.
type Driver struct {
	Name            string `json:"name"`
	Version         string `json:"version,omitempty"`
	SemanticVersion string `json:"semanticVersion,omitempty"`
	InformationURI  string `json:"informationUri,omitempty"`
	Rules           []Rule `json:"rules,omitempty"`
}

// Rule describes a rule/check.
type Rule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name,omitempty"`
	ShortDescription     *Message       `json:"shortDescription,omitempty"`
	FullDescription      *Message       `json:"fullDescription,omitempty"`
	HelpURI              string         `json:"helpUri,omitempty"`
	Help                 *Message       `json:"help,omitempty"`
	DefaultConfiguration *RuleConfig    `json:"defaultConfiguration,omitempty"`
	Properties           map[string]any `json:"properties,omitempty"`
}

// RuleConfig holds rule configuration.
type RuleConfig struct {
	Level string `json:"level,omitempty"`
}

// Result represents a finding.
type Result struct {
	RuleID string `json:"ruleId,omitempty"`
	// RuleIndex is the index of the rule in tool.driver.rules. Nil when the
	// result does not carry one (SARIF's default is -1, "absent").
	RuleIndex           *int                `json:"ruleIndex,omitempty"`
	Rule                *ReportingReference `json:"rule,omitempty"`
	Level               string              `json:"level,omitempty"`
	Message             Message             `json:"message"`
	Locations           []Location          `json:"locations,omitempty"`
	Fingerprints        map[string]string   `json:"fingerprints,omitempty"`
	PartialFingerprints map[string]string   `json:"partialFingerprints,omitempty"`
	CorrelationGUID     string              `json:"correlationGuid,omitempty"`
	BaselineState       string              `json:"baselineState,omitempty"`
	// Kind is the evaluation state of the result: notApplicable, pass, fail,
	// review, open or informational (SARIF 2.1.0 section 3.27.9).
	Kind string `json:"kind,omitempty"`
	// Suppressions are the result's suppressions (SARIF 2.1.0 section
	// 3.27.23), e.g. a nosemgrep comment or a CodeQL alert suppression.
	Suppressions []Suppression  `json:"suppressions,omitempty"`
	Properties   map[string]any `json:"properties,omitempty"`
	// WebRequest and WebResponse are the HTTP exchange of a web result
	// (SARIF 2.1.0 sections 3.46 and 3.47).
	WebRequest  *WebRequest  `json:"webRequest,omitempty"`
	WebResponse *WebResponse `json:"webResponse,omitempty"`
	// CodeFlows are the result's taint paths (SARIF 2.1.0 section 3.36),
	// mapped to the finding's data_flow (sarif_codeflow.go). Kept raw and
	// read leniently: a malformed trace never fails the result.
	CodeFlows json.RawMessage `json:"codeFlows,omitempty"`
}

// WebRequest is a SARIF webRequest object (section 3.46).
type WebRequest struct {
	Protocol string            `json:"protocol,omitempty"`
	Version  string            `json:"version,omitempty"`
	Target   string            `json:"target,omitempty"`
	Method   string            `json:"method,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Body     *Content          `json:"body,omitempty"`
}

// WebResponse is a SARIF webResponse object (section 3.47).
type WebResponse struct {
	Protocol           string            `json:"protocol,omitempty"`
	Version            string            `json:"version,omitempty"`
	StatusCode         int               `json:"statusCode,omitempty"`
	ReasonPhrase       string            `json:"reasonPhrase,omitempty"`
	Headers            map[string]string `json:"headers,omitempty"`
	Body               *Content          `json:"body,omitempty"`
	NoResponseReceived bool              `json:"noResponseReceived,omitempty"`
}

// Content is a SARIF artifactContent object: text, or base64 binary.
type Content struct {
	Text   string `json:"text,omitempty"`
	Binary string `json:"binary,omitempty"`
}

// Suppression is one SARIF suppression object (section 3.35).
type Suppression struct {
	// Kind is inSource or external.
	Kind string `json:"kind,omitempty"`
	// Status is accepted (the default when absent), underReview or rejected.
	Status        string `json:"status,omitempty"`
	Justification string `json:"justification,omitempty"`
}

// ReportingReference is a result's reference to its rule
// (SARIF reportingDescriptorReference).
type ReportingReference struct {
	ID    string `json:"id,omitempty"`
	Index *int   `json:"index,omitempty"`
}

// Message holds text.
type Message struct {
	Text string `json:"text"`
}

// Location represents a code location.
type Location struct {
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []LogicalLocation `json:"logicalLocations,omitempty"`
}

// LogicalLocation names the function, method or class of a location.
type LogicalLocation struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}

// PhysicalLocation contains file/region info.
type PhysicalLocation struct {
	ArtifactLocation *ArtifactLocation `json:"artifactLocation,omitempty"`
	Region           *Region           `json:"region,omitempty"`
}

// ArtifactLocation contains file path.
type ArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseId string `json:"uriBaseId,omitempty"`
}

// Region contains line/column info.
type Region struct {
	StartLine   int      `json:"startLine,omitempty"`
	EndLine     int      `json:"endLine,omitempty"`
	StartColumn int      `json:"startColumn,omitempty"`
	EndColumn   int      `json:"endColumn,omitempty"`
	Snippet     *Snippet `json:"snippet,omitempty"`
}

// Snippet contains code snippet.
type Snippet struct {
	Text string `json:"text"`
}

// Artifact represents a scanned file.
type Artifact struct {
	Location ArtifactLocation `json:"location"`
}

// Invocation contains execution details.
type Invocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	CommandLine         string `json:"commandLine,omitempty"`
}

// =============================================================================
// SARIF to CTIS Conversion
// =============================================================================

// Options configures SARIF to CTIS conversion.
type Options struct {
	// Asset to associate findings with
	AssetType  ctis.AssetType
	AssetValue string
	AssetID    string

	// Branch/commit info (legacy - use BranchInfo for full context)
	Branch    string
	CommitSHA string

	// Branch information for branch-aware finding lifecycle
	// Provides full CI/CD context for auto-resolve and expiry features
	BranchInfo *ctis.BranchInfo

	// Default confidence
	DefaultConfidence int

	// Tool type hints (for finding type detection)
	ToolType string // "sast", "sca", "secret", "iac", "web3"

	// NoPassthrough leaves out the members the mapping does not list;
	// by default they are kept under extensions["org.ctis.interop.sarif"].
	NoPassthrough bool
}

// DefaultOptions returns default conversion options.
func DefaultOptions() *Options {
	return &Options{
		AssetType:         ctis.AssetTypeRepository,
		DefaultConfidence: 90,
	}
}

// Import converts a SARIF 2.1.0 log to a CTIS report.
//
// Every run is converted. The report's tool is the first run's driver; when
// the log has more than one run, each finding names its run's tool in
// finding.tool.
//
// Mapping:
//   - severity: the GitHub "security-severity" score (result, then rule) via
//     severity.FromCVSS; else the result level, else the rule's default level;
//     else medium (SARIF's default level is warning).
//   - type: Options.ToolType; else the rule's tags (vulnerability,
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
func Import(data []byte, opts *Options) (*ctis.Report, error) {
	if opts == nil {
		opts = DefaultOptions()
	}

	var sarif Log
	if err := json.Unmarshal(data, &sarif); err != nil {
		return nil, fmt.Errorf("parse sarif: %w", err)
	}
	m, err := importSet.Select(data)
	if err != nil {
		return nil, fmt.Errorf("sarif: version %q: %w", truncateUTF8(sarif.Version, 16), err)
	}
	// One pass over the document: the members the mapping does not list
	// (kept under extensions) and the values of its set rules.
	pt, err := m.Collect(data)
	if err != nil {
		return nil, fmt.Errorf("parse sarif: %w", err)
	}

	report := ctis.NewReport()
	if !opts.NoPassthrough {
		m.Store(&report.Extensions, pt.DocExtension())
	}

	if len(sarif.Runs) == 0 {
		return report, nil
	}

	first := sarif.Runs[0].Tool.Driver
	report.Tool = &ctis.Tool{
		Name:    first.Name,
		Version: first.Version,
	}
	if ctis.IsWebURL(first.InformationURI) {
		report.Tool.InfoURL = first.InformationURI
	}
	if report.Tool.Version == "" {
		report.Tool.Version = first.SemanticVersion
	}

	// Every finding names an asset. Without one from the caller, the
	// findings go on an unclassified asset named after the tool.
	assetID := opts.AssetID
	if assetID == "" {
		assetID = "asset-1"
	}
	assetType, assetValue := opts.AssetType, opts.AssetValue
	if assetValue == "" || !assetType.IsValid() {
		assetType, assetValue = ctis.AssetTypeUnclassified, "sarif:"+first.Name
	}
	report.Assets = append(report.Assets, ctis.Asset{
		ID:    assetID,
		Type:  assetType,
		Value: ctis.NormalizeAssetName(assetType, assetValue),
	})

	// Set branch info for branch-aware finding lifecycle
	if opts.BranchInfo != nil {
		report.Metadata.Branch = opts.BranchInfo
	} else if opts.Branch != "" {
		// Fallback: create minimal BranchInfo from legacy fields
		report.Metadata.Branch = &ctis.BranchInfo{
			Name:      opts.Branch,
			CommitSHA: opts.CommitSHA,
		}
	}

	multiRun := len(sarif.Runs) > 1
	n := 0
	for ri := range sarif.Runs {
		run := &sarif.Runs[ri]
		driver := run.Tool.Driver
		roots := sarifRoots(run.OriginalURIBaseIDs)
		ruleMap := make(map[string]*Rule, len(driver.Rules))
		for i := range driver.Rules {
			ruleMap[driver.Rules[i].ID] = &driver.Rules[i]
		}

		for j, result := range run.Results {
			n++
			rule, ruleID := lookupRule(&result, driver.Rules, ruleMap)
			ptr := fmt.Sprintf("/runs/%d/results/%d", ri, j)
			// The set rules of the mapping and the kept members apply
			// before the secret masking, which then covers them too.
			prep := func(f *ctis.Finding) {
				_ = pt.Apply(ptr, f)
				if !opts.NoPassthrough {
					m.Store(&f.Extensions, pt.RecordExtension(ptr, nil))
				}
			}
			finding := convertSARIFResult(&result, rule, ruleID, driver.Name, roots, opts, prep)
			finding.ID = fmt.Sprintf("finding-%d", n)
			finding.AssetRef = assetID
			if multiRun {
				finding.Tool = &ctis.Tool{Name: driver.Name, Version: driver.Version}
			}
			report.Findings = append(report.Findings, finding)
		}
	}

	report.Tool.Techniques = detectTechniques(first.Name, opts.ToolType)
	return report, nil
}

// lookupRule finds the rule a result refers to: by ruleId, else rule.id,
// else the rule index.
func lookupRule(result *Result, rules []Rule, byID map[string]*Rule) (*Rule, string) {
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

func convertSARIFResult(result *Result, rule *Rule, ruleID, toolName string, roots []string, opts *Options, prep func(*ctis.Finding)) ctis.Finding {
	finding := ctis.Finding{
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

	var vuln ctis.VulnerabilityDetails
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
			if c, ok := imp.Lookup("precision_confidence", precision); ok {
				finding.Confidence, _ = strconv.Atoi(c)
			}
		}
		vuln.CWEIDs = sarifCWEs(rule.Properties)
		vuln.OWASPIDs = sarifOWASP(rule.Properties)
	}
	if cveIDPattern.MatchString(ruleID) || ghsaIDPattern.MatchString(ruleID) {
		vuln.AddID(ruleID, "")
	}
	if len(vuln.IDs) > 0 || len(vuln.CWEIDs) > 0 || len(vuln.OWASPIDs) > 0 {
		finding.Vulnerability = &vuln
	}

	branch, commit := opts.Branch, opts.CommitSHA
	if branch == "" && opts.BranchInfo != nil {
		branch, commit = opts.BranchInfo.Name, opts.BranchInfo.CommitSHA
	}
	if len(result.Locations) > 0 {
		loc := result.Locations[0]
		if loc.PhysicalLocation != nil || len(loc.LogicalLocations) > 0 {
			finding.Location = &ctis.FindingLocation{Branch: branch}
			if commit != "" {
				finding.Location.Commit = &ctis.CommitInfo{SHA: commit}
			}
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
			finding.Location.LogicalLocation = &ctis.LogicalLocation{
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
	// correlationGuid, baselineState and kind are set rules of the
	// mapping (prep).
	finding.Suppression, finding.Status = sarifSuppression(result.Suppressions)
	var ruleProps map[string]any
	if rule != nil {
		ruleProps = rule.Properties
	}
	finding.Tags = sarifTags(result.Properties, ruleProps)
	if ex, ok := httpExchange(result.WebRequest, result.WebResponse); ok {
		finding.EvidenceItems = []ctis.EvidenceItem{ex}
	}
	finding.DataFlow = sarifDataFlow(result.CodeFlows, roots)
	if prep != nil {
		prep(&finding)
	}
	if finding.Type == ctis.FindingTypeSecret || isSecretTool(strings.ToLower(toolName)) {
		redactSecretFinding(&finding)
	}
	return finding
}

// redactSecretFinding keeps a secret scanner's raw match out of the CTIS
// report. Secret scanners put the matched secret in the SARIF region snippet
// (gitleaks and betterleaks do unless run with --redact), and Import copied
// it into location.snippet, so the live credential travelled in the report and
// was stored wherever the report was. The snippet is masked, and the raw value
// and every secret-looking word of it are masked in every other field
// (redactSecrets), so a message that repeats the bare secret does not carry
// it into the title.
//
// The masked value is not written to secret.masked_value: receivers fingerprint
// secret findings by it (spec section 5.2), and setting it would change the
// identity of every finding already ingested from a SARIF secret scan.
func redactSecretFinding(f *ctis.Finding) {
	ctis.RedactSecretFindingWith(f, true, isRedacted)
}

// isRedacted reports whether a scanner already fully redacted the snippet:
// gitleaks --redact writes "REDACTED", other tools mask with asterisks. A
// partial redaction (gitleaks --redact=N keeps part of the secret followed by
// "...") is masked again.
func isRedacted(s string) bool {
	t := strings.TrimSpace(s)
	return strings.EqualFold(t, ctis.RedactedSecret) || strings.Trim(t, "*•") == ""
}

// Bounds on the tags Import carries, so a hostile or broken SARIF log
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
func sarifSuppression(sups []Suppression) (*ctis.Suppression, ctis.FindingStatus) {
	if len(sups) == 0 {
		return nil, ""
	}
	rank := map[string]int{"rejected": 3, "under_review": 2, "accepted": 1}
	var pick *Suppression
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
	sup := &ctis.Suppression{
		Kind:          sarifSuppressionKind(pick.Kind),
		Status:        pickStatus,
		Justification: truncateUTF8(cleanSuppressionText(pick.Justification), maxSuppressionJustification),
	}
	if pickStatus == "accepted" {
		return sup, ctis.FindingStatusSuppressed
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

// sarifSeverity applies the precedence documented on Import.
func sarifSeverity(result *Result, rule *Rule) ctis.Severity {
	if score, ok := securitySeverity(result.Properties); ok {
		return ctis.Severity(severity.FromCVSS(score))
	}
	if rule != nil {
		if score, ok := securitySeverity(rule.Properties); ok {
			return ctis.Severity(severity.FromCVSS(score))
		}
	}
	level := result.Level
	if level == "" && rule != nil && rule.DefaultConfiguration != nil {
		level = rule.DefaultConfiguration.Level
	}
	sev, _ := imp.Lookup("level_severity", level)
	return ctis.Severity(sev)
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

// detectResultType works out one result's finding type, in the order
// documented on Import.
func detectResultType(rule *Rule, ruleID, toolName, toolType string) ctis.FindingType {
	switch toolType {
	case "secret":
		return ctis.FindingTypeSecret
	case "iac":
		return ctis.FindingTypeMisconfiguration
	case "web3", "sast":
		if cveIDPattern.MatchString(ruleID) || ghsaIDPattern.MatchString(ruleID) {
			return ctis.FindingTypeVulnerability
		}
		return ctis.FindingTypeWeakness
	case "sca":
		return ctis.FindingTypeVulnerability
	}
	if rule != nil {
		for _, tag := range stringOrStrings(rule.Properties["tags"]) {
			switch strings.ToLower(strings.TrimSpace(tag)) {
			case "vulnerability":
				return ctis.FindingTypeVulnerability
			case "weakness":
				return ctis.FindingTypeWeakness
			case "misconfiguration":
				return ctis.FindingTypeMisconfiguration
			case "secret":
				return ctis.FindingTypeSecret
			}
		}
	}
	if cveIDPattern.MatchString(ruleID) || ghsaIDPattern.MatchString(ruleID) {
		return ctis.FindingTypeVulnerability
	}
	return detectFindingType(toolName, toolType)
}

// detectFindingType determines finding type based on tool name.
func detectFindingType(toolName string, toolType string) ctis.FindingType {
	name := strings.ToLower(toolName)

	// Explicit tool type
	switch toolType {
	case "secret":
		return ctis.FindingTypeSecret
	case "iac":
		return ctis.FindingTypeMisconfiguration
	case "web3", "sast":
		return ctis.FindingTypeWeakness
	case "sca":
		return ctis.FindingTypeVulnerability
	}

	if isSecretTool(name) {
		return ctis.FindingTypeSecret
	}

	// Web3 scanners
	web3Tools := []string{"slither", "mythril", "securify", "manticore", "echidna", "aderyn"}
	for _, t := range web3Tools {
		if strings.Contains(name, t) {
			return ctis.FindingTypeWeakness
		}
	}

	// IaC scanners
	iacTools := []string{"trivy", "checkov", "tfsec", "terrascan", "kics"}
	for _, t := range iacTools {
		if strings.Contains(name, t) {
			return ctis.FindingTypeMisconfiguration
		}
	}

	// Static analysers report code weaknesses (a CVE or GHSA rule id was
	// recognised before this point).
	for _, t := range sastToolNames {
		if strings.Contains(name, t) {
			return ctis.FindingTypeWeakness
		}
	}

	return ctis.FindingTypeVulnerability
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
	"semgrep", "opengrep", "codeql", "gosec", "bandit", "sonarqube", "sonarcloud",
	"eslint", "brakeman", "spotbugs", "njsscan", "horusec", "bearer",
	"psalm", "phpstan", "flawfinder", "cppcheck",
}

// detectTechniques determines the detection techniques of a SARIF tool.
func detectTechniques(toolName string, toolType string) []ctis.Technique {
	name := strings.ToLower(toolName)

	switch toolType {
	case "secret":
		return []ctis.Technique{ctis.TechniqueSecret}
	case "iac":
		return []ctis.Technique{ctis.TechniqueIaC}
	case "sca":
		return []ctis.Technique{ctis.TechniqueSCA}
	case "sast", "web3":
		return []ctis.Technique{ctis.TechniqueSAST}
	}

	if isSecretTool(name) {
		return []ctis.Technique{ctis.TechniqueSecret}
	}
	if strings.Contains(name, "slither") || strings.Contains(name, "mythril") {
		return []ctis.Technique{ctis.TechniqueSAST}
	}
	if strings.Contains(name, "trivy") || strings.Contains(name, "checkov") {
		return []ctis.Technique{ctis.TechniqueSCA, ctis.TechniqueIaC}
	}
	for _, t := range sastToolNames {
		if strings.Contains(name, t) {
			return []ctis.Technique{ctis.TechniqueSAST}
		}
	}
	return nil
}

// httpExchange builds an http_exchange evidence item from a result's
// webRequest and webResponse (ctis.HTTPExchange caps and marks it).
func httpExchange(req *WebRequest, resp *WebResponse) (ctis.EvidenceItem, bool) {
	var rq, rs *ctis.HTTPMessageParts
	if req != nil {
		rq = &ctis.HTTPMessageParts{
			Method:      req.Method,
			Target:      req.Target,
			HTTPVersion: httpProtocol(req.Protocol, req.Version),
			Headers:     req.Headers,
			Body:        contentText(req.Body),
		}
	}
	if resp != nil && !resp.NoResponseReceived {
		rs = &ctis.HTTPMessageParts{
			Status:      resp.StatusCode,
			Reason:      resp.ReasonPhrase,
			HTTPVersion: httpProtocol(resp.Protocol, resp.Version),
			Headers:     resp.Headers,
			Body:        contentText(resp.Body),
		}
	}
	return ctis.HTTPExchange(rq, rs)
}

func httpProtocol(protocol, version string) string {
	if protocol == "" || version == "" {
		return ""
	}
	return strings.ToUpper(protocol) + "/" + version
}

// contentText is the body of an artifactContent: its text, else its base64
// binary decoded. A content object without either is an empty body.
func contentText(c *Content) *string {
	if c == nil {
		return nil
	}
	s := c.Text
	if s == "" {
		if raw, err := base64.StdEncoding.DecodeString(c.Binary); err == nil {
			s = string(raw)
		}
	}
	return &s
}
