package ctis

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/openctemio/ctis/severity"
)

// CTIS to SARIF 2.1.0.
//
// One report is one run. Mapping (FromSARIF reads every member back):
//   - tool -> run.tool.driver (name, version, informationUri); the rules
//     catalog run.tool.driver.rules[] is built from the findings: one rule
//     per rule_id, its members taken from the first finding of that rule,
//     sorted by id; every result names its rule by ruleId and ruleIndex.
//   - severity -> result.level and properties["security-severity"] (the
//     finding's CVSS score when it bands to the same severity, else a
//     representative score of the band); the rule carries the same as
//     defaultConfiguration.level and security-severity.
//   - title -> message.text; description -> rule.shortDescription;
//     rule_name -> rule.name; references[0] -> rule.helpUri;
//     remediation.recommendation -> rule.help.
//   - cwe_ids, owasp_ids -> rule properties "cwe", "owasp"; confidence ->
//     rule properties "precision"; type -> a rule tag when the rule id and
//     tool name would not give it back.
//   - location -> locations[0] (physical and logical location, region and
//     snippet); metadata.branch -> run.versionControlProvenance.
//   - fingerprint -> fingerprints["ctis/v1"]; partial_fingerprints ->
//     partialFingerprints; correlation_id -> correlationGuid;
//     baseline_state, kind, suppression -> the SARIF members of that name.
//   - tags -> properties.tags; data_flow -> codeFlows[0].threadFlows[0];
//     the first http_exchange evidence item -> webRequest/webResponse.

const (
	sarifVersion   = "2.1.0"
	sarifSchemaURI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	// sarifFingerprintKey names the CTIS fingerprint in result.fingerprints.
	sarifFingerprintKey = "ctis/v1"
	// sarifDefaultDriver names the driver of a report without a tool.
	sarifDefaultDriver = "ctis"
)

type sarifOutLog struct {
	Schema  string        `json:"$schema"`
	Version string        `json:"version"`
	Runs    []sarifOutRun `json:"runs"`
}

type sarifOutRun struct {
	Tool                     SARIFTool     `json:"tool"`
	VersionControlProvenance []sarifOutVCS `json:"versionControlProvenance,omitempty"`
	Results                  []SARIFResult `json:"results"`
}

type sarifOutVCS struct {
	RepositoryURI string `json:"repositoryUri"`
	RevisionID    string `json:"revisionId,omitempty"`
	Branch        string `json:"branch,omitempty"`
}

type sarifOutCodeFlow struct {
	ThreadFlows []sarifOutThreadFlow `json:"threadFlows"`
}

type sarifOutThreadFlow struct {
	Locations []sarifOutThreadFlowLocation `json:"locations"`
}

type sarifOutThreadFlowLocation struct {
	Location sarifFlowLocation `json:"location"`
	Kinds    []string          `json:"kinds,omitempty"`
}

// ToSARIF converts a report to a SARIF 2.1.0 log (JSON). See the mapping
// above and docs/exporters.md for what SARIF cannot carry.
func ToSARIF(r *Report) ([]byte, error) {
	if r == nil {
		return nil, errNilReport
	}
	driver := SARIFDriver{Name: sarifDefaultDriver}
	if r.Tool != nil {
		if r.Tool.Name != "" {
			driver.Name = r.Tool.Name
		}
		driver.Version = r.Tool.Version
		driver.InformationURI = r.Tool.InfoURL
	}

	// Findings grouped into runs by the tool FromSARIF recorded for a
	// multi-run log (properties["sarif_tool"]), in first-seen order.
	var order []string
	byTool := map[string][]Finding{}
	for i := range r.Findings {
		c, err := exportFinding(&r.Findings[i])
		if err != nil {
			return nil, err
		}
		tool := driver.Name
		if s := propString(c.Properties, "sarif_tool"); s != "" {
			tool = s
		}
		if _, ok := byTool[tool]; !ok {
			order = append(order, tool)
		}
		byTool[tool] = append(byTool[tool], c)
	}
	if len(order) == 0 {
		order = []string{driver.Name}
	}
	log := sarifOutLog{Schema: sarifSchemaURI, Version: sarifVersion}
	for i, tool := range order {
		d := SARIFDriver{Name: tool}
		if tool == driver.Name {
			d = driver
		}
		run, err := sarifRunOf(d, byTool[tool])
		if err != nil {
			return nil, err
		}
		if b := r.Metadata.Branch; i == 0 && b != nil && b.RepositoryURL != "" {
			run.VersionControlProvenance = []sarifOutVCS{{RepositoryURI: b.RepositoryURL, RevisionID: b.CommitSHA, Branch: b.Name}}
		}
		log.Runs = append(log.Runs, run)
	}
	return marshalExport(log)
}

// sarifRunOf writes one run: the rules catalog built from the findings (the
// first finding of each rule id defines the rule, rules sorted by id) and
// one result per finding, in order.
func sarifRunOf(driver SARIFDriver, findings []Finding) (sarifOutRun, error) {
	rules := map[string]SARIFRule{}
	for i := range findings {
		id := sarifRuleID(&findings[i])
		if _, ok := rules[id]; !ok {
			rules[id] = sarifRuleOf(&findings[i], id, driver.Name)
		}
	}
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	index := make(map[string]int, len(ids))
	for i, id := range ids {
		driver.Rules = append(driver.Rules, rules[id])
		index[id] = i
	}
	run := sarifOutRun{Tool: SARIFTool{Driver: driver}, Results: []SARIFResult{}}
	for i := range findings {
		f := &findings[i]
		id := sarifRuleID(f)
		idx := index[id]
		res, err := sarifResultOf(f, id)
		if err != nil {
			return sarifOutRun{}, err
		}
		res.RuleIndex = &idx
		run.Results = append(run.Results, res)
	}
	return run, nil
}

// sarifRuleID is the rule a finding is reported under: its rule_id, else
// one per finding type.
func sarifRuleID(f *Finding) string {
	if f.RuleID != "" {
		return f.RuleID
	}
	t := string(f.Type)
	if t == "" {
		t = "finding"
	}
	return "ctis/" + t
}

// sarifLevel maps a severity to a SARIF level.
func sarifLevel(s Severity) string {
	switch s {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityLow, SeverityInfo:
		return "note"
	default:
		return "warning"
	}
}

// sarifSecuritySeverity is the security-severity score of a finding: its
// CVSS score when that bands to its severity, else the middle of the band.
// An unknown severity has none.
func sarifSecuritySeverity(f *Finding) (string, bool) {
	if !f.Severity.IsValid() {
		return "", false
	}
	if v := f.Vulnerability; v != nil && v.CVSSScore > 0 && v.CVSSScore <= 10 &&
		Severity(severity.FromCVSS(v.CVSSScore)) == f.Severity {
		return formatScore(v.CVSSScore), true
	}
	switch f.Severity {
	case SeverityCritical:
		return "9.5", true
	case SeverityHigh:
		return "8.0", true
	case SeverityMedium:
		return "5.5", true
	case SeverityLow:
		return "2.0", true
	default:
		return "0.0", true
	}
}

// sarifPrecision is the rule precision FromSARIF maps back to the
// confidence, or "" for a confidence it has no precision for.
func sarifPrecision(confidence int) string {
	switch confidence {
	case 95:
		return "very-high"
	case 85:
		return "high"
	case 70:
		return "medium"
	case 50:
		return "low"
	}
	return ""
}

func sarifRuleOf(f *Finding, id, toolName string) SARIFRule {
	rule := SARIFRule{ID: id, Name: f.RuleName}
	if f.Description != "" {
		rule.ShortDescription = &SARIFMessage{Text: f.Description}
	}
	if len(f.References) > 0 {
		rule.HelpURI = f.References[0]
	}
	if f.Remediation != nil && f.Remediation.Recommendation != "" {
		rule.Help = &SARIFMessage{Text: f.Remediation.Recommendation}
	}
	if f.Severity.IsValid() {
		rule.DefaultConfiguration = &SARIFRuleConfig{Level: sarifLevel(f.Severity)}
	}
	props := map[string]any{}
	if s, ok := sarifSecuritySeverity(f); ok {
		props["security-severity"] = s
	}
	if p := sarifPrecision(f.Confidence); p != "" {
		props["precision"] = p
	}
	if v := f.Vulnerability; v != nil {
		cwes := v.CWEIDs
		if len(cwes) == 0 && v.CWEID != "" {
			cwes = []string{v.CWEID}
		}
		if len(cwes) > 0 {
			props["cwe"] = append([]string(nil), cwes...)
		}
		if len(v.OWASPIDs) > 0 {
			props["owasp"] = append([]string(nil), v.OWASPIDs...)
		}
	}
	// The type comes back from the rule id or tool name; only when it would
	// not is it written as the rule tag FromSARIF reads.
	if detectResultType(nil, id, toolName, "") != f.Type {
		switch f.Type {
		case FindingTypeVulnerability, FindingTypeMisconfiguration, FindingTypeSecret:
			props["tags"] = []string{string(f.Type)}
		}
	}
	if len(props) > 0 {
		rule.Properties = props
	}
	return rule
}

func sarifResultOf(f *Finding, ruleID string) (SARIFResult, error) {
	title := f.Title
	if title == "" {
		title = f.Message
	}
	res := SARIFResult{
		RuleID:          ruleID,
		Level:           sarifLevel(f.Severity),
		Message:         SARIFMessage{Text: title},
		CorrelationGUID: f.CorrelationID,
		BaselineState:   f.BaselineState,
		Kind:            sarifKindOut(f.Kind),
	}
	props := map[string]any{}
	if s, ok := sarifSecuritySeverity(f); ok {
		props["security-severity"] = s
	}
	if len(f.Tags) > 0 {
		props["tags"] = append([]string(nil), f.Tags...)
	}
	if len(props) > 0 {
		res.Properties = props
	}
	if loc := sarifLocationOf(f.Location); loc != nil {
		res.Locations = []SARIFLocation{*loc}
	}
	if f.Fingerprint != "" {
		res.Fingerprints = map[string]string{sarifFingerprintKey: f.Fingerprint}
	}
	if len(f.PartialFingerprints) > 0 {
		res.PartialFingerprints = make(map[string]string, len(f.PartialFingerprints))
		for k, v := range f.PartialFingerprints {
			res.PartialFingerprints[k] = v
		}
	}
	res.Suppressions = sarifSuppressionsOf(f)
	if df := f.DataFlow; df != nil {
		if cf := sarifCodeFlowOf(df); cf != nil {
			b, err := json.Marshal([]sarifOutCodeFlow{*cf})
			if err != nil {
				return SARIFResult{}, err
			}
			res.CodeFlows = b
		}
	}
	res.WebRequest, res.WebResponse = sarifWebOf(f.EvidenceItems)
	return res, nil
}

// sarifKindOut maps finding.kind to SARIF's spelling.
func sarifKindOut(kind string) string {
	if kind == "not_applicable" {
		return "notApplicable"
	}
	return kind
}

func sarifLocationOf(l *FindingLocation) *SARIFLocation {
	if l == nil {
		return nil
	}
	loc := &SARIFLocation{}
	region := &SARIFRegion{StartLine: l.StartLine, EndLine: l.EndLine, StartColumn: l.StartColumn, EndColumn: l.EndColumn}
	if l.Snippet != "" {
		region.Snippet = &SARIFSnippet{Text: l.Snippet}
	}
	hasRegion := region.StartLine > 0 || region.EndLine > 0 || region.StartColumn > 0 || region.EndColumn > 0 || region.Snippet != nil
	if l.Path != "" || hasRegion {
		pl := &SARIFPhysicalLocation{}
		if l.Path != "" {
			pl.ArtifactLocation = &SARIFArtifactLocation{URI: l.Path}
		}
		if hasRegion {
			pl.Region = region
		}
		loc.PhysicalLocation = pl
	}
	if ll := l.LogicalLocation; ll != nil && (ll.Name != "" || ll.FullyQualifiedName != "" || ll.Kind != "") {
		loc.LogicalLocations = []SARIFLogicalLocation{{Name: ll.Name, FullyQualifiedName: ll.FullyQualifiedName, Kind: ll.Kind}}
	}
	if loc.PhysicalLocation == nil && loc.LogicalLocations == nil {
		return nil
	}
	return loc
}

// sarifSuppressionsOf writes finding.suppression, or, for a finding
// suppressed, a false positive or an accepted risk without one, an external
// accepted suppression naming the status.
func sarifSuppressionsOf(f *Finding) []SARIFSuppression {
	if s := f.Suppression; s != nil {
		out := SARIFSuppression{Kind: "external", Justification: s.Justification}
		if s.Kind == "in_source" {
			out.Kind = "inSource"
		}
		switch s.Status {
		case "under_review":
			out.Status = "underReview"
		case "rejected":
			out.Status = "rejected"
		case "accepted":
			out.Status = "accepted"
		}
		if out.Justification == "" {
			out.Justification = s.Reason
		}
		return []SARIFSuppression{out}
	}
	switch f.Status {
	case FindingStatusSuppressed, FindingStatusFalsePositive, FindingStatusAcceptedRisk:
		return []SARIFSuppression{{Kind: "external", Status: "accepted", Justification: string(f.Status)}}
	}
	return nil
}

// sarifCodeFlowOf writes the data flow as one thread flow, steps in index
// order, each marked with its role.
func sarifCodeFlowOf(df *DataFlow) *sarifOutCodeFlow {
	steps := make([]DataFlowLocation, 0, len(df.Sources)+len(df.Intermediates)+len(df.Sanitizers)+len(df.Sinks))
	steps = append(steps, df.Sources...)
	steps = append(steps, df.Intermediates...)
	steps = append(steps, df.Sanitizers...)
	steps = append(steps, df.Sinks...)
	if len(steps) == 0 {
		return nil
	}
	sort.SliceStable(steps, func(i, j int) bool { return steps[i].Index < steps[j].Index })
	tf := sarifOutThreadFlow{}
	for _, s := range steps {
		fl := sarifFlowLocation{}
		region := &SARIFRegion{StartLine: s.Line, EndLine: s.EndLine, StartColumn: s.Column, EndColumn: s.EndColumn}
		if s.Content != "" {
			region.Snippet = &SARIFSnippet{Text: s.Content}
		}
		pl := &SARIFPhysicalLocation{}
		if s.Path != "" {
			pl.ArtifactLocation = &SARIFArtifactLocation{URI: s.Path}
		}
		if region.StartLine > 0 || region.EndLine > 0 || region.StartColumn > 0 || region.EndColumn > 0 || region.Snippet != nil {
			pl.Region = region
		}
		if pl.ArtifactLocation != nil || pl.Region != nil {
			fl.PhysicalLocation = pl
		}
		if s.Function != "" {
			fl.LogicalLocations = []SARIFLogicalLocation{{FullyQualifiedName: s.Function}}
		}
		if s.Label != "" {
			fl.Message = &SARIFMessage{Text: s.Label}
		}
		tfl := sarifOutThreadFlowLocation{Location: fl}
		switch s.Type {
		case DataFlowLocationSource:
			tfl.Kinds = []string{"source"}
		case DataFlowLocationSink:
			tfl.Kinds = []string{"sink"}
		case DataFlowLocationSanitizer:
			tfl.Kinds = []string{"sanitizer"}
		}
		tf.Locations = append(tf.Locations, tfl)
	}
	return &sarifOutCodeFlow{ThreadFlows: []sarifOutThreadFlow{tf}}
}

// sarifWebOf writes the first http_exchange evidence item as a webRequest
// and webResponse; values the item marks sensitive are masked.
func sarifWebOf(items []EvidenceItem) (*SARIFWebRequest, *SARIFWebResponse) {
	for i := range items {
		it := &items[i]
		if it.Kind != EvidenceKindHTTPExchange || it.HTTP == nil {
			continue
		}
		var req *SARIFWebRequest
		var resp *SARIFWebResponse
		if r := it.HTTP.Request; r != nil {
			req = &SARIFWebRequest{
				Method: r.Method,
				Target: maskSensitiveSpans(r.URL, "/http/request/url", it.Sensitive),
			}
			req.Protocol, req.Version = sarifProtocolOut(r.HTTPVersion)
			req.Headers = sarifHeadersOut(r.Headers, "/http/request/headers/", it.Sensitive)
			req.Body = sarifBodyOut(maskSensitiveSpans(r.Body, "/http/request/body", it.Sensitive), r.BodyEncoding)
		}
		if r := it.HTTP.Response; r != nil {
			resp = &SARIFWebResponse{StatusCode: r.Status, ReasonPhrase: r.Reason}
			resp.Protocol, resp.Version = sarifProtocolOut(r.HTTPVersion)
			resp.Headers = sarifHeadersOut(r.Headers, "/http/response/headers/", it.Sensitive)
			resp.Body = sarifBodyOut(maskSensitiveSpans(r.Body, "/http/response/body", it.Sensitive), r.BodyEncoding)
		}
		return req, resp
	}
	return nil, nil
}

// sarifProtocolOut splits "HTTP/1.1" into protocol and version.
func sarifProtocolOut(v string) (string, string) {
	p, ver, ok := strings.Cut(v, "/")
	if !ok || p == "" || ver == "" {
		return "", ""
	}
	return strings.ToLower(p), ver
}

// sarifHeadersOut writes headers as SARIF's name-to-value map: a header
// sent twice is joined with ", "; sensitive headers are masked.
func sarifHeadersOut(hs []EvidenceHeader, ptr string, spans []SensitiveSpan) map[string]string {
	if len(hs) == 0 {
		return nil
	}
	out := make(map[string]string, len(hs))
	for k, h := range hs {
		v := maskSensitiveSpans(h.Value, ptr+itoa(k)+"/value", spans)
		if IsSensitiveHeader(h.Name) && v != "" {
			v = redactedSecret
		}
		if prev, ok := out[h.Name]; ok {
			v = prev + ", " + v
		}
		out[h.Name] = v
	}
	return out
}

func sarifBodyOut(body, encoding string) *SARIFContent {
	if body == "" {
		return nil
	}
	if encoding == BodyEncodingBase64 {
		return &SARIFContent{Binary: body}
	}
	return &SARIFContent{Text: body}
}
