package sarif

import (
	"fmt"
	"strconv"

	"github.com/openctemio/ctis/v2/internal/exportkit"
	"github.com/openctemio/ctis/v2/interop/engine"

	"github.com/openctemio/ctis/v2"

	"encoding/json"
	"sort"
	"strings"

	"github.com/openctemio/ctis/v2/severity"
)

// CTIS to SARIF 2.1.0.
//
// One report is one run. Mapping (Import reads every member back):
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
//   - fingerprint -> fingerprints["ctis/v2"]; partial_fingerprints ->
//     partialFingerprints; correlation_id -> correlationGuid;
//     baseline_state, kind, suppression -> the SARIF members of that name.
//   - tags -> properties.tags; data_flow -> codeFlows[0].threadFlows[0];
//     the first http_exchange evidence item -> webRequest/webResponse.

const (
	sarifVersion   = "2.1.0"
	sarifSchemaURI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	// sarifFingerprintKey names the CTIS fingerprint in result.fingerprints.
	sarifFingerprintKey = "ctis/v2"
	// sarifDefaultDriver names the driver of a report without a tool.
	sarifDefaultDriver = "ctis"
)

type sarifOutLog struct {
	Schema  string        `json:"$schema"`
	Version string        `json:"version"`
	Runs    []sarifOutRun `json:"runs"`
}

type sarifOutRun struct {
	Tool                     Tool          `json:"tool"`
	VersionControlProvenance []sarifOutVCS `json:"versionControlProvenance,omitempty"`
	Results                  []Result      `json:"results"`
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

// ExportOptions configure Export. The zero value (or nil) is valid.
type ExportOptions struct {
	// NoPassthrough leaves out the SARIF members an import kept under
	// extensions["org.ctis.interop.sarif"]; by default they are written back
	// where the exporter writes nothing.
	NoPassthrough bool
}

// ErrTooLarge is returned when the encoded output would exceed MaxBytes.
var ErrTooLarge = exportkit.ErrTooLarge

// MaxBytes is the largest output Export returns.
const MaxBytes = exportkit.MaxBytes

// Export converts a report to a SARIF 2.1.0 log (JSON). See the mapping
// above, 2.1.0/export.json and docs/exporters.md for what SARIF cannot
// carry.
func Export(r *ctis.Report, opts *ExportOptions) ([]byte, error) {
	if opts == nil {
		opts = &ExportOptions{}
	}
	if r == nil {
		return nil, exportkit.ErrNilReport
	}
	driver := Driver{Name: sarifDefaultDriver}
	if r.Tool != nil {
		if r.Tool.Name != "" {
			driver.Name = r.Tool.Name
		}
		driver.Version = r.Tool.Version
		driver.InformationURI = r.Tool.InfoURL
	}

	// Findings grouped into runs by their own tool (finding.tool, which
	// Import records for a multi-run log), in first-seen order.
	var order []string
	byTool := map[string][]ctis.Finding{}
	toolVersion := map[string]string{}
	for i := range r.Findings {
		c, err := exportkit.Finding(&r.Findings[i])
		if err != nil {
			return nil, err
		}
		tool := driver.Name
		if c.Tool != nil && c.Tool.Name != "" {
			tool = c.Tool.Name
			if _, ok := toolVersion[tool]; !ok {
				toolVersion[tool] = c.Tool.Version
			}
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
		d := Driver{Name: tool, Version: toolVersion[tool]}
		if tool == driver.Name {
			d = driver
		}
		run, err := sarifRunOf(d, byTool[tool], r.Rules, len(order) == 1)
		if err != nil {
			return nil, err
		}
		if b := r.Metadata.Branch; i == 0 && b != nil && b.RepositoryURL != "" {
			run.VersionControlProvenance = []sarifOutVCS{{RepositoryURI: b.RepositoryURL, RevisionID: b.CommitSHA, Branch: b.Name}}
		}
		log.Runs = append(log.Runs, run)
	}
	out, err := exportkit.Marshal(log)
	if err != nil || opts.NoPassthrough {
		return out, err
	}
	// Members an import kept: the document's, then each result's. A
	// document member under a run is placed only when there is one run, so
	// it cannot land on another tool's run.
	var entries []engine.Entry
	if _, kept, ok := exp.Kept(r.Extensions); ok {
		for _, e := range kept {
			if strings.HasPrefix(e.Pointer, "/runs/") && (len(log.Runs) != 1 || !strings.HasPrefix(e.Pointer, "/runs/0/")) {
				continue
			}
			entries = append(entries, e)
		}
	}
	for i, tool := range order {
		for k := range byTool[tool] {
			if _, kept, ok := exp.Kept(byTool[tool][k].Extensions); ok {
				base := fmt.Sprintf("/runs/%d/results/%d", i, k)
				for _, e := range kept {
					entries = append(entries, engine.Entry{Pointer: base + e.Pointer, Value: e.Value})
				}
			}
		}
	}
	out, _, err = exp.Reemit(out, entries, "  ")
	if err != nil {
		return nil, err
	}
	if len(out) > exportkit.MaxBytes {
		return nil, exportkit.ErrTooLarge
	}
	return out, nil
}

// sarifRunOf writes one run: the rules catalog and one result per finding,
// in order. The catalog rules come first (all of them when all is set, else
// the ones the findings name), in catalog order; a finding without a catalog
// rule gets a rule built from it (the first finding of each rule id defines
// it), after them, sorted by id (rules.go).
func sarifRunOf(driver Driver, findings []ctis.Finding, cat []ctis.Rule, all bool) (sarifOutRun, error) {
	byRef := make(map[string]int, len(cat))
	byRuleID := make(map[string]int, len(cat))
	for k := range cat {
		if _, ok := byRef[cat[k].ID]; !ok {
			byRef[cat[k].ID] = k
		}
		if _, ok := byRuleID[cat[k].RuleID]; !ok {
			byRuleID[cat[k].RuleID] = k
		}
	}
	use := make([]int, len(findings))
	first := map[int]*ctis.Finding{}
	for i := range findings {
		f := &findings[i]
		k := -1
		if j, ok := byRef[f.RuleRef]; ok && f.RuleRef != "" {
			k = j
		} else if j, ok := byRuleID[f.RuleID]; ok && f.RuleID != "" {
			k = j
		}
		use[i] = k
		if _, ok := first[k]; k >= 0 && !ok {
			first[k] = f
		}
	}
	catIndex := map[int]int{}
	for k := range cat {
		if _, used := first[k]; !all && !used {
			continue
		}
		catIndex[k] = len(driver.Rules)
		driver.Rules = append(driver.Rules, sarifRuleOfCatalog(&cat[k], first[k], driver.Name))
	}
	rules := map[string]Rule{}
	for i := range findings {
		if use[i] >= 0 {
			continue
		}
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
	for _, id := range ids {
		index[id] = len(driver.Rules)
		driver.Rules = append(driver.Rules, rules[id])
	}
	run := sarifOutRun{Tool: Tool{Driver: driver}, Results: []Result{}}
	for i := range findings {
		f := &findings[i]
		id := sarifRuleID(f)
		idx := index[id]
		if k := use[i]; k >= 0 {
			id, idx = cat[k].RuleID, catIndex[k]
		}
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
func sarifRuleID(f *ctis.Finding) string {
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
func sarifLevel(s ctis.Severity) string {
	l, _ := exp.Lookup("severity_level", string(s))
	return l
}

// sarifSecuritySeverity is the security-severity score of a finding: its
// CVSS score when that bands to its severity, else the middle of the band.
// An unknown severity has none.
func sarifSecuritySeverity(f *ctis.Finding) (string, bool) {
	if !f.Severity.IsValid() || f.Severity == ctis.SeverityUnknown {
		return "", false
	}
	if c, ok := ctis.PrimaryCVSS(f); ok && c.Value != nil && *c.Value > 0 && *c.Value <= 10 &&
		ctis.Severity(severity.FromCVSS(*c.Value)) == f.Severity {
		return exportkit.FormatScore(*c.Value), true
	}
	return exp.Lookup("severity_score", string(f.Severity))
}

// sarifPrecision is the rule precision Import maps back to the
// confidence, or "" for a confidence it has no precision for.
func sarifPrecision(confidence int) string {
	p, _ := exp.Lookup("confidence_precision", strconv.Itoa(confidence))
	return p
}

func sarifRuleOf(f *ctis.Finding, id, toolName string) Rule {
	rule := Rule{ID: id, Name: f.RuleName}
	if f.Description != "" {
		rule.ShortDescription = &Message{Text: f.Description}
	}
	if len(f.References) > 0 {
		rule.HelpURI = f.References[0]
	}
	if f.Remediation != nil && f.Remediation.Recommendation != "" {
		rule.Help = &Message{Text: f.Remediation.Recommendation}
	}
	if f.Severity.IsValid() {
		rule.DefaultConfiguration = &RuleConfig{Level: sarifLevel(f.Severity)}
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
		if len(cwes) > 0 {
			props["cwe"] = append([]string(nil), cwes...)
		}
		if len(v.OWASPIDs) > 0 {
			props["owasp"] = append([]string(nil), v.OWASPIDs...)
		}
	}
	// The type comes back from the rule id or tool name; only when it would
	// not is it written as the rule tag Import reads.
	if detectResultType(nil, id, toolName, "") != f.Type {
		switch f.Type {
		case ctis.FindingTypeVulnerability, ctis.FindingTypeWeakness, ctis.FindingTypeMisconfiguration, ctis.FindingTypeSecret:
			props["tags"] = []string{string(f.Type)}
		}
	}
	if len(props) > 0 {
		rule.Properties = props
	}
	return rule
}

func sarifResultOf(f *ctis.Finding, ruleID string) (Result, error) {
	title := f.Title
	if title == "" {
		title = f.Message
	}
	res := Result{
		RuleID:          ruleID,
		Level:           sarifLevel(f.Severity),
		Message:         Message{Text: title},
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
		res.Locations = []Location{*loc}
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
				return Result{}, err
			}
			res.CodeFlows = b
		}
	}
	res.WebRequest, res.WebResponse = sarifWebOf(f.EvidenceItems)
	return res, nil
}

// sarifKindOut maps finding.kind to SARIF's spelling.
func sarifKindOut(kind string) string {
	if k, ok := exp.Lookup("kind_out", kind); ok {
		return k
	}
	return kind
}

func sarifLocationOf(l *ctis.FindingLocation) *Location {
	if l == nil {
		return nil
	}
	loc := &Location{}
	region := &Region{StartLine: l.StartLine, EndLine: l.EndLine, StartColumn: l.StartColumn, EndColumn: l.EndColumn}
	if l.Snippet != "" {
		region.Snippet = &Snippet{Text: l.Snippet}
	}
	hasRegion := region.StartLine > 0 || region.EndLine > 0 || region.StartColumn > 0 || region.EndColumn > 0 || region.Snippet != nil
	if l.Path != "" || hasRegion {
		pl := &PhysicalLocation{}
		if l.Path != "" {
			pl.ArtifactLocation = &ArtifactLocation{URI: l.Path}
		}
		if hasRegion {
			pl.Region = region
		}
		loc.PhysicalLocation = pl
	}
	if ll := l.LogicalLocation; ll != nil && (ll.Name != "" || ll.FullyQualifiedName != "" || ll.Kind != "") {
		loc.LogicalLocations = []LogicalLocation{{Name: ll.Name, FullyQualifiedName: ll.FullyQualifiedName, Kind: ll.Kind}}
	}
	if loc.PhysicalLocation == nil && loc.LogicalLocations == nil {
		return nil
	}
	return loc
}

// sarifSuppressionsOf writes finding.suppression, or, for a finding
// suppressed, a false positive or an accepted risk without one, an external
// accepted suppression naming the status.
func sarifSuppressionsOf(f *ctis.Finding) []Suppression {
	if s := f.Suppression; s != nil {
		out := Suppression{Kind: "external", Justification: s.Justification}
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
		return []Suppression{out}
	}
	switch f.Status {
	case ctis.FindingStatusSuppressed, ctis.FindingStatusFalsePositive, ctis.FindingStatusAcceptedRisk:
		return []Suppression{{Kind: "external", Status: "accepted", Justification: string(f.Status)}}
	}
	return nil
}

// sarifCodeFlowOf writes the data flow as one thread flow, steps in index
// order, each marked with its role.
func sarifCodeFlowOf(df *ctis.DataFlow) *sarifOutCodeFlow {
	// Built by appending: the input is bounded by Validate, and a summed
	// capacity would be computed from untrusted lengths.
	steps := append([]ctis.DataFlowLocation(nil), df.Sources...)
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
		region := &Region{StartLine: s.Line, EndLine: s.EndLine, StartColumn: s.Column, EndColumn: s.EndColumn}
		if s.Content != "" {
			region.Snippet = &Snippet{Text: s.Content}
		}
		pl := &PhysicalLocation{}
		if s.Path != "" {
			pl.ArtifactLocation = &ArtifactLocation{URI: s.Path}
		}
		if region.StartLine > 0 || region.EndLine > 0 || region.StartColumn > 0 || region.EndColumn > 0 || region.Snippet != nil {
			pl.Region = region
		}
		if pl.ArtifactLocation != nil || pl.Region != nil {
			fl.PhysicalLocation = pl
		}
		if s.Function != "" {
			fl.LogicalLocations = []LogicalLocation{{FullyQualifiedName: s.Function}}
		}
		if s.Label != "" {
			fl.Message = &Message{Text: s.Label}
		}
		tfl := sarifOutThreadFlowLocation{Location: fl}
		switch s.Type {
		case ctis.DataFlowLocationSource:
			tfl.Kinds = []string{"source"}
		case ctis.DataFlowLocationSink:
			tfl.Kinds = []string{"sink"}
		case ctis.DataFlowLocationSanitizer:
			tfl.Kinds = []string{"sanitizer"}
		}
		tf.Locations = append(tf.Locations, tfl)
	}
	return &sarifOutCodeFlow{ThreadFlows: []sarifOutThreadFlow{tf}}
}

// sarifWebOf writes the first http_exchange evidence item as a webRequest
// and webResponse; values the item marks sensitive are masked.
func sarifWebOf(items []ctis.EvidenceItem) (*WebRequest, *WebResponse) {
	for i := range items {
		it := &items[i]
		if it.Kind != ctis.EvidenceKindHTTPExchange || it.HTTP == nil {
			continue
		}
		var req *WebRequest
		var resp *WebResponse
		if r := it.HTTP.Request; r != nil {
			req = &WebRequest{
				Method: r.Method,
				Target: exportkit.MaskSensitiveSpans(r.URL, "/http/request/url", it.Sensitive),
			}
			req.Protocol, req.Version = sarifProtocolOut(r.HTTPVersion)
			req.Headers = sarifHeadersOut(r.Headers, "/http/request/headers/", it.Sensitive)
			req.Body = sarifBodyOut(exportkit.MaskSensitiveSpans(r.Body, "/http/request/body", it.Sensitive), r.BodyEncoding)
		}
		if r := it.HTTP.Response; r != nil {
			resp = &WebResponse{StatusCode: r.Status, ReasonPhrase: r.Reason}
			resp.Protocol, resp.Version = sarifProtocolOut(r.HTTPVersion)
			resp.Headers = sarifHeadersOut(r.Headers, "/http/response/headers/", it.Sensitive)
			resp.Body = sarifBodyOut(exportkit.MaskSensitiveSpans(r.Body, "/http/response/body", it.Sensitive), r.BodyEncoding)
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
func sarifHeadersOut(hs []ctis.EvidenceHeader, ptr string, spans []ctis.SensitiveSpan) map[string]string {
	if len(hs) == 0 {
		return nil
	}
	out := make(map[string]string, len(hs))
	for k, h := range hs {
		v := exportkit.MaskSensitiveSpans(h.Value, ptr+strconv.Itoa(k)+"/value", spans)
		if ctis.IsSensitiveHeader(h.Name) && v != "" {
			v = ctis.RedactedSecret
		}
		if prev, ok := out[h.Name]; ok {
			v = prev + ", " + v
		}
		out[h.Name] = v
	}
	return out
}

func sarifBodyOut(body, encoding string) *Content {
	if body == "" {
		return nil
	}
	if encoding == ctis.BodyEncodingBase64 {
		return &Content{Binary: body}
	}
	return &Content{Text: body}
}
