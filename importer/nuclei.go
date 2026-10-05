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

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/fingerprint"
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
	TemplateID    string     `json:"template-id"`
	TemplatePath  string     `json:"template-path"`
	Template      string     `json:"template"`
	TemplateURL   string     `json:"template-url"`
	Info          nucleiInfo `json:"info"`
	Type          string     `json:"type"`
	Host          string     `json:"host"`
	Port          flexStr    `json:"port"`
	Scheme        string     `json:"scheme"`
	URL           string     `json:"url"`
	Path          string     `json:"path"`
	MatchedAt     string     `json:"matched-at"`
	IP            string     `json:"ip"`
	Timestamp     string     `json:"timestamp"`
	MatcherName   string     `json:"matcher-name"`
	MatcherStatus bool       `json:"matcher-status"`
	ExtractorName string     `json:"extractor-name"`
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
	matched := line(stripUserinfo(r.MatchedAt), 2048)
	if matched != "" {
		f.Message = line(name+" at "+matched, 8<<10)
		f.Location = &ctis.FindingLocation{Path: matched}
	} else {
		f.Message = name
	}
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
	f.Fingerprint = fingerprint.GenerateSAST(r.Host, r.TemplateID, 0, 0)
	var meta []string
	for _, k := range sortedKeysOf(r.Info.Metadata) {
		meta = append(meta, line(k, 64)+"="+line(string(r.Info.Metadata[k]), 256))
	}
	extras(&f, "impact", r.Info.Impact, "matcher_name", r.MatcherName, "extractor_name", r.ExtractorName,
		"template_path", firstNonEmpty(r.TemplatePath, r.Template), "timestamp", r.Timestamp,
		"template_metadata", strings.Join(meta, "\n"), "authors", strings.Join(stringList(r.Info.Author), ", "))
	return f
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
