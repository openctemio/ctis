package importer

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/fingerprint"
)

// semgrep JSON output (semgrep --json). The mapping is spec_semgrep.go.

func init() {
	parsers[FormatSemgrep] = parseSemgrep
	tools[FormatSemgrep] = ctis.Tool{Name: "semgrep", Vendor: "Semgrep, Inc.", Capabilities: []string{"sast"}}
}

type sgPos struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type sgMetadata struct {
	CWE                json.RawMessage `json:"cwe"`
	OWASP              json.RawMessage `json:"owasp"`
	Confidence         flexStr         `json:"confidence"`
	Impact             flexStr         `json:"impact"`
	Likelihood         flexStr         `json:"likelihood"`
	Category           flexStr         `json:"category"`
	Subcategory        json.RawMessage `json:"subcategory"`
	Technology         json.RawMessage `json:"technology"`
	References         json.RawMessage `json:"references"`
	Source             flexStr         `json:"source"`
	SourceRuleURL      flexStr         `json:"source-rule-url"`
	VulnerabilityClass json.RawMessage `json:"vulnerability_class"`
	Shortlink          flexStr         `json:"shortlink"`
	License            flexStr         `json:"license"`
}

type sgFixRegex struct {
	Regex       string `json:"regex"`
	Replacement string `json:"replacement"`
	Count       int    `json:"count"`
}

type sgExtra struct {
	Message         string          `json:"message"`
	Severity        string          `json:"severity"`
	Metadata        sgMetadata      `json:"metadata"`
	Lines           string          `json:"lines"`
	IsIgnored       bool            `json:"is_ignored"`
	Fingerprint     string          `json:"fingerprint"`
	Fix             string          `json:"fix"`
	FixRegex        *sgFixRegex     `json:"fix_regex"`
	Dataflow        *sgTrace        `json:"dataflow_trace"`
	ValidationState string          `json:"validation_state"`
	EngineKind      string          `json:"engine_kind"`
	Metavars        json.RawMessage `json:"metavars"`
}

type sgResult struct {
	CheckID string  `json:"check_id"`
	Path    string  `json:"path"`
	Start   sgPos   `json:"start"`
	End     sgPos   `json:"end"`
	Extra   sgExtra `json:"extra"`
}

type sgError struct {
	Code    int             `json:"code"`
	Level   string          `json:"level"`
	Type    json.RawMessage `json:"type"`
	Message string          `json:"message"`
	Path    string          `json:"path"`
}

type sgOutput struct {
	Version string            `json:"version"`
	Results []json.RawMessage `json:"results"`
	Errors  []sgError         `json:"errors"`
}

// sgTrace is a taint trace. semgrep writes each part either as a list of
// {location, content} objects or as its tagged form ["CliLoc", [location,
// content]]; both are read, other tags (calls) are skipped.
type sgTrace struct {
	Source        []sgTraceLoc
	Intermediates []sgTraceLoc
	Sink          []sgTraceLoc
}

type sgTraceLoc struct {
	Path    string
	Line    int
	Col     int
	Content string
}

func (t *sgTrace) UnmarshalJSON(b []byte) error {
	var raw struct {
		Source        json.RawMessage `json:"taint_source"`
		Intermediates json.RawMessage `json:"intermediate_vars"`
		Sink          json.RawMessage `json:"taint_sink"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	t.Source = sgTraceLocs(raw.Source)
	t.Intermediates = sgTraceLocs(raw.Intermediates)
	t.Sink = sgTraceLocs(raw.Sink)
	return nil
}

type sgLoc struct {
	Path  string `json:"path"`
	Start sgPos  `json:"start"`
}

// sgTraceLocs reads one part of a trace in either form; anything else is
// empty (a trace is context, never a reason to drop a finding).
func sgTraceLocs(raw json.RawMessage) []sgTraceLoc {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '[' {
		return nil
	}
	var objs []struct {
		Location sgLoc  `json:"location"`
		Content  string `json:"content"`
	}
	if json.Unmarshal(raw, &objs) == nil {
		out := make([]sgTraceLoc, 0, len(objs))
		for _, o := range objs {
			out = append(out, sgTraceLoc{o.Location.Path, o.Location.Start.Line, o.Location.Start.Col, o.Content})
		}
		return out
	}
	var tagged []json.RawMessage
	if json.Unmarshal(raw, &tagged) != nil || len(tagged) != 2 {
		return nil
	}
	var tag string
	if json.Unmarshal(tagged[0], &tag) != nil || tag != "CliLoc" {
		return nil
	}
	var pair []json.RawMessage
	if json.Unmarshal(tagged[1], &pair) != nil || len(pair) != 2 {
		return nil
	}
	var loc sgLoc
	var content string
	if json.Unmarshal(pair[0], &loc) != nil {
		return nil
	}
	_ = json.Unmarshal(pair[1], &content)
	return []sgTraceLoc{{loc.Path, loc.Start.Line, loc.Start.Col, content}}
}

// sgPlaceholder is what semgrep writes in fingerprint and lines when the
// run is not logged in; it is no value.
const sgPlaceholder = "requires login"

func parseSemgrep(b *builder, r io.Reader) error {
	data, err := readAll(r, FormatSemgrep, b.lim)
	if err != nil {
		return err
	}
	doc, err := scanJSON(data, FormatSemgrep, b.lim, b.obs, "/results[]")
	if err != nil {
		return err
	}
	var out sgOutput
	if err := doc.decode(&out); err != nil {
		return err
	}
	if out.Results == nil {
		return &ParseError{Format: FormatSemgrep, Msg: "no results array", Err: ErrMalformed}
	}
	if v := line(out.Version, 64); v != "" {
		b.res.Report.Tool.Version = v
	}
	for _, e := range out.Errors {
		if len(b.res.Issues) >= b.lim.MaxIssues {
			break
		}
		b.issue(Issue{Path: line(e.Path, 1024), Message: "semgrep reported: " + line(sgErrorKind(e.Type)+" "+e.Message, 512)})
	}
	for i, raw := range out.Results {
		b.res.Stats.Records++
		if err := b.tick(); err != nil {
			return err
		}
		ptr := "/results/" + strconv.Itoa(i)
		var res sgResult
		if err := json.Unmarshal(raw, &res); err != nil {
			b.issue(doc.issueAt("/results[]", i, ptr, "skipped: "+jsonErrText(err)))
			b.res.Stats.Skipped++
			continue
		}
		f, ok := sgFinding(&res)
		if !ok {
			b.issue(doc.issueAt("/results[]", i, ptr, "result without check_id or path: skipped"))
			b.res.Stats.Skipped++
			continue
		}
		f.Native.RawRef = ptr
		if err := b.finding(f); err != nil {
			return err
		}
	}
	if len(b.res.Report.Findings) == 0 && b.opts.Repository == "" {
		return nil
	}
	return b.bindAll(b.codeAsset(nil))
}

func sgErrorKind(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil && len(arr) > 0 && json.Unmarshal(arr[0], &s) == nil {
		return s
	}
	return ""
}

func sgFinding(r *sgResult) (ctis.Finding, bool) {
	rule := line(r.CheckID, capShort)
	path := line(r.Path, 1024)
	if rule == "" || path == "" {
		return ctis.Finding{}, false
	}
	msg := text(r.Extra.Message, 8<<10)
	title := line(msg, capTitle)
	if title == "" {
		title = rule
	}
	f := ctis.Finding{
		Type:       ctis.FindingTypeVulnerability,
		Title:      title,
		Message:    msg,
		Severity:   sgSeverity(r.Extra.Severity),
		RuleID:     rule,
		RuleName:   line(sgRuleName(r.CheckID), capTitle),
		Confidence: sgConfidence(r.Extra.Metadata.Confidence.String()),
		Location: &ctis.FindingLocation{
			Path:        path,
			StartLine:   nonNeg(r.Start.Line),
			EndLine:     nonNeg(r.End.Line),
			StartColumn: nonNeg(r.Start.Col),
			EndColumn:   nonNeg(r.End.Col),
		},
		Native: &ctis.NativeIdentity{Scheme: ctis.NativeSchemeOther, VulnID: line(r.CheckID, ctis.MaxNativeIDLen), Severity: line(r.Extra.Severity, ctis.MaxNativeValueLen)},
	}
	if l := r.Extra.Lines; l != "" && l != sgPlaceholder {
		f.Location.Snippet = text(l, 16<<10)
	}
	md := &r.Extra.Metadata
	vuln := &ctis.VulnerabilityDetails{}
	for _, c := range stringList(md.CWE) {
		if id := cweID(c); id != "" {
			vuln.CWEIDs = appendUnique(vuln.CWEIDs, id)
		}
	}
	if len(vuln.CWEIDs) > 0 {
		vuln.CWEID = vuln.CWEIDs[0]
	}
	for _, o := range stringList(md.OWASP) {
		vuln.OWASPIDs = appendUnique(vuln.OWASPIDs, line(o, 128))
	}
	if len(vuln.CWEIDs) > 0 || len(vuln.OWASPIDs) > 0 {
		f.Vulnerability = vuln
	}
	for _, v := range stringList(md.VulnerabilityClass) {
		if len(f.VulnerabilityClass) < 50 {
			f.VulnerabilityClass = append(f.VulnerabilityClass, line(v, 200))
		}
	}
	for _, v := range stringList(md.Subcategory) {
		if len(f.Subcategory) < 50 {
			f.Subcategory = append(f.Subcategory, line(v, 200))
		}
	}
	f.Category = line(md.Category.String(), capCategory)
	f.Impact = sgLevel(md.Impact.String())
	f.Likelihood = sgLevel(md.Likelihood.String())
	f.References = addRefs(f.References, stringList(md.References)...)
	f.References = addRefs(f.References, md.SourceRuleURL.String(), md.Shortlink.String())
	f.Tags = addTags(f.Tags, stringList(md.Technology)...)
	f.Tags = addTags(f.Tags, "semgrep")
	if r.Extra.Fix != "" || r.Extra.FixRegex != nil {
		f.Remediation = &ctis.Remediation{Recommendation: "Apply the suggested fix code.", FixAvailable: true, FixCode: text(r.Extra.Fix, capRemediation)}
		if fr := r.Extra.FixRegex; fr != nil {
			f.Remediation.FixRegex = &ctis.FixRegex{Regex: line(fr.Regex, 2048), Replacement: line(fr.Replacement, 2048), Count: nonNeg(fr.Count)}
		}
	}
	if fp := line(r.Extra.Fingerprint, 512); fp != "" && fp != sgPlaceholder {
		f.Fingerprint = fp
	} else {
		f.Fingerprint = fingerprint.GenerateSAST(r.Path, r.CheckID, r.Start.Line, 0)
	}
	if t := r.Extra.Dataflow; t != nil {
		f.DataFlow = sgDataFlow(t)
	}
	if r.Extra.IsIgnored {
		f.Suppression = &ctis.Suppression{Kind: "in_source", Status: "accepted", Justification: "nosemgrep"}
	}
	extras(&f, "validation_state", r.Extra.ValidationState, "engine_kind", r.Extra.EngineKind,
		"rule_source", md.Source.String(), "rule_license", md.License.String())
	return f, true
}

func sgDataFlow(t *sgTrace) *ctis.DataFlow {
	df := &ctis.DataFlow{}
	idx := 0
	add := func(dst *[]ctis.DataFlowLocation, locs []sgTraceLoc, typ ctis.DataFlowLocationType) {
		for _, l := range locs {
			if idx >= 100 {
				return
			}
			*dst = append(*dst, ctis.DataFlowLocation{Path: line(l.Path, 1024), Line: nonNeg(l.Line), Column: nonNeg(l.Col), Content: text(l.Content, 2048), Index: idx, Type: typ})
			idx++
		}
	}
	add(&df.Sources, t.Source, ctis.DataFlowLocationSource)
	add(&df.Intermediates, t.Intermediates, ctis.DataFlowLocationPropagator)
	add(&df.Sinks, t.Sink, ctis.DataFlowLocationSink)
	if idx == 0 {
		return nil
	}
	df.Tainted = len(df.Sources) > 0 && len(df.Sinks) > 0
	return df
}

// stringList reads a JSON string or a list of strings.
func stringList(raw json.RawMessage) []string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if s = strings.TrimSpace(s); s != "" {
			return []string{s}
		}
		return nil
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	var out []string
	for _, item := range list {
		if json.Unmarshal(item, &s) == nil && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

// cweID reads "CWE-89", "CWE-89: SQL Injection" or "89" as "CWE-89".
func cweID(s string) string {
	s = strings.TrimSpace(strings.ToUpper(s))
	s = strings.TrimPrefix(s, "CWE-")
	n := 0
	for n < len(s) && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	if n == 0 || n > 6 {
		return ""
	}
	return "CWE-" + s[:n]
}

func sgSeverity(s string) ctis.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ERROR", "HIGH", "CRITICAL":
		return ctis.SeverityHigh
	case "WARNING", "MEDIUM":
		return ctis.SeverityMedium
	case "INFO", "LOW":
		return ctis.SeverityLow
	case "INVENTORY", "EXPERIMENT":
		return ctis.SeverityInfo
	}
	return ctis.SeverityMedium
}

func sgConfidence(c string) int {
	switch strings.ToUpper(strings.TrimSpace(c)) {
	case "HIGH":
		return 90
	case "LOW":
		return 50
	}
	return 70
}

// sgLevel keeps the CTIS impact and likelihood words (critical, high,
// medium, low) and drops anything else.
func sgLevel(s string) string {
	switch l := strings.ToLower(strings.TrimSpace(s)); l {
	case "critical", "high", "medium", "low":
		return l
	}
	return ""
}

// sgRuleName turns the last part of a check id into words:
// "python.lang.security.sql-injection" -> "Sql Injection".
func sgRuleName(checkID string) string {
	parts := strings.Split(checkID, ".")
	words := strings.Split(parts[len(parts)-1], "-")
	for i, w := range words {
		if w != "" {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}
