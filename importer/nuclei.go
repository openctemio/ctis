package importer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/fingerprint"
	"github.com/openctemio/ctis/weburl"
)

// nuclei results: JSON lines (nuclei -jsonl), or a JSON array (nuclei
// -json-export). The mapping is spec_nuclei.go.

func init() {
	parsers[FormatNuclei] = parseNuclei
	tools[FormatNuclei] = ctis.Tool{Name: "nuclei", Vendor: "ProjectDiscovery", InfoURL: "https://github.com/projectdiscovery/nuclei", Capabilities: []string{"dast"}}
}

type nucleiClass struct {
	CVEID       json.RawMessage `json:"cve-id"`
	CWEID       json.RawMessage `json:"cwe-id"`
	CVSSMetrics string          `json:"cvss-metrics"`
	CVSSScore   float64         `json:"cvss-score"`
	EPSSScore   float64         `json:"epss-score"`
	EPSSPerc    float64         `json:"epss-percentile"`
	CPE         string          `json:"cpe"`
}

type nucleiInfo struct {
	Name           string                     `json:"name"`
	Severity       string                     `json:"severity"`
	Description    string                     `json:"description"`
	Author         json.RawMessage            `json:"author"`
	Tags           json.RawMessage            `json:"tags"`
	Reference      json.RawMessage            `json:"reference"`
	Classification *nucleiClass               `json:"classification"`
	Remediation    string                     `json:"remediation"`
	Impact         string                     `json:"impact"`
	Metadata       map[string]json.RawMessage `json:"metadata"`
}

type nucleiResult struct {
	TemplateID    string          `json:"template-id"`
	TemplatePath  string          `json:"template-path"`
	Template      string          `json:"template"`
	TemplateURL   string          `json:"template-url"`
	Info          nucleiInfo      `json:"info"`
	Type          string          `json:"type"`
	Host          string          `json:"host"`
	Port          flexStr         `json:"port"`
	Scheme        string          `json:"scheme"`
	URL           string          `json:"url"`
	Path          string          `json:"path"`
	MatchedAt     string          `json:"matched-at"`
	IP            string          `json:"ip"`
	Timestamp     string          `json:"timestamp"`
	MatcherName   string          `json:"matcher-name"`
	MatcherStatus bool            `json:"matcher-status"`
	ExtractorName string          `json:"extractor-name"`
	Request       string          `json:"request"`
	Response      string          `json:"response"`
	CurlCommand   string          `json:"curl-command"`
	Extracted     json.RawMessage `json:"extracted-results"`

	// DAST (fuzzing) results.
	FuzzingMethod    string `json:"fuzzing_method"`
	FuzzingParameter string `json:"fuzzing_parameter"`
	FuzzingPosition  string `json:"fuzzing_position"`
}

func parseNuclei(b *builder, r io.Reader) error {
	data, err := readAll(r, FormatNuclei, b.lim)
	if err != nil {
		return err
	}
	lines := &lines{data: data}
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '[' {
		// An array: the outer scan bounds it, each element is scanned
		// again for its field paths.
		doc, err := scanJSON(data, FormatNuclei, b.lim, nil, "/[]")
		if err != nil {
			return err
		}
		var records []json.RawMessage
		if err := doc.decode(&records); err != nil {
			return err
		}
		for i, raw := range records {
			ln, _ := doc.lines.pos(offsetAt(doc, i))
			if err := b.nucleiRecord(raw, ln, "/"+strconv.Itoa(i)); err != nil {
				return err
			}
		}
		return nil
	}
	// JSON lines: each line is one bounded document.
	n := 0
	for start := 0; start < len(data); {
		end := bytes.IndexByte(data[start:], '\n')
		if end < 0 {
			end = len(data)
		} else {
			end += start
		}
		rec := bytes.TrimSpace(data[start:end])
		ln, _ := lines.pos(int64(start))
		start = end + 1
		if len(rec) == 0 {
			continue
		}
		n++
		if n > b.lim.MaxFindings {
			return b.tooMany("records", b.lim.MaxFindings)
		}
		if err := b.nucleiRecord(rec, ln, fmt.Sprintf("line %d", ln)); err != nil {
			return err
		}
	}
	if n == 0 {
		return &ParseError{Format: FormatNuclei, Msg: "no result", Err: ErrMalformed}
	}
	return nil
}

func offsetAt(doc *jsonDoc, i int) int64 {
	if offs := doc.offsets["/[]"]; i < len(offs) {
		return offs[i]
	}
	return -1
}

// nucleiRecord reads one result. A record that is not valid JSON, not an
// object of results, or over a limit is skipped with an issue at its line;
// a hostile line cannot stop the others.
func (b *builder) nucleiRecord(raw []byte, ln int, ref string) error {
	b.res.Stats.Records++
	if err := b.tick(); err != nil {
		return err
	}
	skip := func(msg string) error {
		b.res.Stats.Skipped++
		b.issue(Issue{Line: ln, Path: ref, Message: msg})
		return nil
	}
	if _, err := scanJSON(raw, FormatNuclei, b.lim, b.obs); err != nil {
		var pe *ParseError
		if errors.As(err, &pe) {
			return skip("skipped: " + pe.Msg)
		}
		return skip("skipped: not valid JSON")
	}
	var res nucleiResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return skip("skipped: " + jsonErrText(err))
	}
	if strings.TrimSpace(res.TemplateID) == "" {
		return skip("result without template-id: skipped")
	}
	t, v := hostAsset(firstNonEmpty(res.Host, res.MatchedAt, res.IP))
	if v == "" {
		return skip("result names no host: skipped")
	}
	id := b.nucleiHostID(t, v, res.IP)
	f := nucleiFinding(&res, v)
	f.AssetRef = id
	f.Native.RawRef = ref
	return b.finding(f)
}

// nucleiHostID returns the asset of a host, adding it on first use (ids
// asset-1, asset-2, ... in order of first appearance).
func (b *builder) nucleiHostID(t ctis.AssetType, v, ip string) string {
	for i := range b.res.Report.Assets {
		if a := &b.res.Report.Assets[i]; a.Type == t && a.Value == v {
			return a.ID
		}
	}
	id := "asset-" + strconv.Itoa(len(b.res.Report.Assets)+1)
	a := ctis.Asset{ID: id, Type: t, Value: v, Name: v}
	if p := net.ParseIP(strings.TrimSpace(ip)); p != nil && t != ctis.AssetTypeIPAddress {
		a.Properties = ctis.Properties{"ip_address": p.String()}
	}
	if _, err := b.asset(a); err != nil {
		return ""
	}
	return id
}

// hostAsset names the host of a target (a host, host:port, an IP or a URL)
// as a domain or ip_address asset value.
func hostAsset(target string) (ctis.AssetType, string) {
	s := strings.TrimSpace(target)
	if s == "" {
		return "", ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			s = u.Hostname()
		}
	} else {
		if i := strings.IndexAny(s, "/?#"); i >= 0 {
			s = s[:i]
		}
		if h, _, err := net.SplitHostPort(s); err == nil {
			s = h
		}
	}
	s = strings.TrimSuffix(strings.Trim(s, "[]"), ".")
	if s == "" || len(s) > 253 || strings.ContainsAny(s, " \t\r\n@") {
		return "", ""
	}
	if ip := net.ParseIP(s); ip != nil {
		return ctis.AssetTypeIPAddress, ip.String()
	}
	return ctis.AssetTypeDomain, strings.ToLower(s)
}

func nucleiSeverity(s string) ctis.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return ctis.SeverityCritical
	case "high":
		return ctis.SeverityHigh
	case "medium":
		return ctis.SeverityMedium
	case "low":
		return ctis.SeverityLow
	case "info", "unknown":
		return ctis.SeverityInfo
	}
	return ctis.SeverityMedium
}

func nucleiFinding(r *nucleiResult, host string) ctis.Finding {
	name := line(r.Info.Name, capTitle)
	if name == "" {
		name = line(r.TemplateID, capTitle)
	}
	f := ctis.Finding{
		Type:        ctis.FindingTypeVulnerability,
		Title:       name,
		Description: text(r.Info.Description, capDescription),
		Severity:    nucleiSeverity(r.Info.Severity),
		RuleID:      line(r.TemplateID, capShort),
		Native:      &ctis.NativeIdentity{Scheme: ctis.NativeSchemeOther, VulnID: line(r.TemplateID, ctis.MaxNativeIDLen), Severity: line(r.Info.Severity, ctis.MaxNativeValueLen)},
		Confidence:  70,
	}
	if r.MatcherStatus {
		f.Confidence = 90
	}
	// matched-at is a URL for http templates and host:port for network
	// ones. It is never a file: the URL goes to finding.web, redacted (no
	// query value, user info or fragment), and only names the place in the
	// message.
	matched := line(weburl.RedactURL(r.MatchedAt), 2048)
	if matched != "" {
		f.Message = line(name+" at "+matched, 8<<10)
	} else {
		f.Message = name
	}
	f.Web = nucleiWeb(r)
	f.EvidenceItems = nucleiEvidence(r)
	if c := r.Info.Classification; c != nil {
		vd := &ctis.VulnerabilityDetails{}
		for _, id := range stringList(c.CVEID) {
			addVulnID(vd, id)
		}
		for _, cw := range stringList(c.CWEID) {
			if id := cweID(cw); id != "" {
				vd.CWEIDs = appendUnique(vd.CWEIDs, id)
			}
		}
		if len(vd.CWEIDs) > 0 {
			vd.CWEID = vd.CWEIDs[0]
		}
		if c.CVSSScore > 0 && c.CVSSScore <= 10 {
			ver := ctis.CVSSVersionOfVector(c.CVSSMetrics)
			if ver == "" {
				ver = "3.1"
			}
			vd.CVSSScore, vd.CVSSVector, vd.CVSSVersion = c.CVSSScore, line(c.CVSSMetrics, ctis.MaxScoreVectorLen), ver
			val := c.CVSSScore
			addScore(&f, ctis.Score{System: ctis.ScoreSystemCVSS, Version: ver, Vector: vd.CVSSVector, Value: &val, Source: "nuclei-templates"})
		}
		if c.EPSSScore > 0 && c.EPSSScore <= 1 {
			vd.EPSSScore = c.EPSSScore
			val := c.EPSSScore
			addScore(&f, ctis.Score{System: ctis.ScoreSystemEPSS, Value: &val, Source: "first"})
		}
		if c.EPSSPerc > 0 && c.EPSSPerc <= 1 {
			vd.EPSSPercentile = c.EPSSPerc
		}
		vd.CPE = line(c.CPE, capShort)
		f.Vulnerability = vd
	}
	f.References = addRefs(f.References, stringList(r.Info.Reference)...)
	f.References = addRefs(f.References, r.TemplateURL)
	f.Tags = addTags(f.Tags, stringList(r.Info.Tags)...)
	f.Tags = addTags(f.Tags, "nuclei", r.Type)
	if rem := text(r.Info.Remediation, capRemediation); rem != "" {
		f.Remediation = &ctis.Remediation{Recommendation: rem}
	}
	port, _ := strconv.Atoi(r.Port.String())
	if port > 0 && port <= 65535 {
		f.Network = &ctis.NetworkLocation{Host: host, Port: port, Protocol: "tcp", Service: line(r.Scheme, 32)}
	}
	f.Fingerprint = fingerprint.GenerateSAST(fingerprintHost(r.Host), r.TemplateID, 0, 0)
	var meta []string
	for _, k := range sortedKeysOf(r.Info.Metadata) {
		meta = append(meta, line(k, 64)+"="+line(string(r.Info.Metadata[k]), 256))
	}
	extras(&f, "impact", r.Info.Impact, "matcher_name", r.MatcherName, "extractor_name", r.ExtractorName,
		"template_path", firstNonEmpty(r.TemplatePath, r.Template), "timestamp", r.Timestamp,
		"template_metadata", strings.Join(meta, "\n"), "authors", strings.Join(stringList(r.Info.Author), ", "))
	return f
}

// fingerprintHost is the host a finding is fingerprinted by: as given, or,
// when it carries user info, a query or a fragment, redacted. Fingerprints
// of hosts without credentials are unchanged.
func fingerprintHost(h string) string {
	if strings.ContainsAny(h, "@?#") {
		return weburl.RedactURL(h)
	}
	return h
}

// nucleiWeb is the web location of an http result: the redacted matched
// URL, the method (the fuzzing method, else the request line's) and, for a
// DAST result, the fuzzed parameter.
func nucleiWeb(r *nucleiResult) *ctis.WebLocation {
	u, err := weburl.Parse(weburl.RedactURL(strings.TrimSpace(r.MatchedAt)))
	if err != nil {
		return nil
	}
	w := &ctis.WebLocation{URL: redactedWebURL(u)}
	method := r.FuzzingMethod
	if method == "" {
		if sp := strings.IndexByte(r.Request, ' '); sp > 0 {
			method = r.Request[:sp]
		}
	}
	if m, ok := weburl.NormalizeMethod(method); ok && method != "" {
		w.Method = m
	}
	if loc, ok := nucleiParamLocation(r.FuzzingPosition); ok {
		if n := strings.TrimSpace(r.FuzzingParameter); n != "" && len(n) <= ctis.MaxParamNameLen && !hasControl(n) {
			w.Parameter = &ctis.WebParameter{Location: loc, Name: n}
		}
	}
	return w
}

// nucleiEvidence is the evidence of an http result: the request and the
// response as one http_exchange (with the extracted values, located in the
// response body when they occur there) and the curl command. Sensitive
// values (credentials, sessions, tokens, extracted secrets) are marked for
// the receiver to mask, never masked here.
func nucleiEvidence(r *nucleiResult) []ctis.EvidenceItem {
	var items []ctis.EvidenceItem
	ex, ok := ctis.HTTPExchangeFromRaw(r.Request, r.Response, r.MatchedAt)
	if ok {
		ex.Label = line(r.TemplateID, ctis.MaxEvidenceLabelLen)
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(r.Timestamp)); err == nil {
			t = t.UTC()
			ex.CapturedAt = &t
		}
		var body string
		if resp := ex.HTTP.Response; resp != nil && resp.BodyEncoding == ctis.BodyEncodingText {
			body = resp.Body
		}
		matcher := line(r.MatcherName, 128)
		for _, v := range stringList(r.Extracted) {
			if len(ex.Extracted) == ctis.MaxEvidenceExtracted {
				break
			}
			v = cutBytes(v, ctis.MaxEvidenceExtractLen)
			if v == "" {
				continue
			}
			k := len(ex.Extracted)
			ex.Extracted = append(ex.Extracted, v)
			if looksSecretValue(v) {
				ex.Sensitive = append(ex.Sensitive, ctis.SensitiveSpan{Pointer: "/extracted/" + strconv.Itoa(k), Kind: "extracted"})
			}
			if i := strings.Index(body, v); i >= 0 && len(ex.Match) < ctis.MaxEvidenceMatches {
				start, end := i, i+len(v)
				ex.Match = append(ex.Match, ctis.EvidenceMatch{Location: ctis.MatchLocationResponse, Part: ctis.MatchPartBody, Start: &start, End: &end, Matcher: matcher})
			}
		}
		if matcher != "" && len(ex.Match) == 0 {
			ex.Label = line(ex.Label+" ("+matcher+")", ctis.MaxEvidenceLabelLen)
		}
		items = append(items, ex)
	}
	if curl, ok := ctis.CurlEvidence(r.CurlCommand); ok {
		items = append(items, curl)
	}
	ptrs := make([]*ctis.EvidenceItem, len(items))
	for i := range items {
		ptrs[i] = &items[i]
	}
	ctis.MarkSensitive(ptrs...)
	return items
}

// looksSecretValue reports whether an extracted value looks like a
// credential: a long run of letters and digits, or a known key prefix.
func looksSecretValue(v string) bool {
	for _, w := range strings.FieldsFunc(v, func(r rune) bool { return unicode.IsSpace(r) || strings.ContainsRune("\"'=:;,", r) }) {
		if len(w) >= 16 && strings.IndexFunc(w, unicode.IsDigit) >= 0 && strings.IndexFunc(w, unicode.IsLetter) >= 0 {
			return true
		}
	}
	return false
}

// cutBytes cuts s to at most n bytes on a rune boundary.
func cutBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// redactedWebURL is the normalised URL with its query parameter names and
// no values: https://h/p?a=&b=.
func redactedWebURL(u *weburl.URL) string {
	s := u.String()
	for i, n := range u.Params {
		sep := "&"
		if i == 0 {
			sep = "?"
		}
		s += sep + url.QueryEscape(n) + "="
	}
	return s
}

// nucleiParamLocation maps a nuclei fuzzing position to a parameter
// location.
func nucleiParamLocation(pos string) (ctis.ParamLocation, bool) {
	switch strings.ToLower(strings.TrimSpace(pos)) {
	case "query":
		return ctis.ParamLocationQuery, true
	case "path":
		return ctis.ParamLocationPath, true
	case "header":
		return ctis.ParamLocationHeader, true
	case "cookie":
		return ctis.ParamLocationCookie, true
	case "body", "form":
		return ctis.ParamLocationForm, true
	case "json":
		return ctis.ParamLocationJSON, true
	case "multipart":
		return ctis.ParamLocationMultipart, true
	}
	return "", false
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// stripUserinfo removes credentials from a URL (https://user:pass@host/).
func stripUserinfo(s string) string {
	if !strings.Contains(s, "@") || !strings.Contains(s, "://") {
		return s
	}
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		return s
	}
	u.User = nil
	return u.String()
}
