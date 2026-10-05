package importer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/openctemio/ctis"
)

// ZAP traditional report, JSON (`{"@programName": "ZAP", "site": [...]}`) or
// XML (`<OWASPZAPReport>`). The mapping is spec_zap.go.
//
// Instance request and response headers and bodies hold cookies,
// authorization headers and session tokens; they are never read.

func init() {
	parsers[FormatZAP] = parseZAP
	tools[FormatZAP] = ctis.Tool{Name: "zap", Capabilities: []string{"dast"}}
}

// zapMaxInstances is how many instances of an alert are written into the
// finding's evidence; the rest are counted.
const zapMaxInstances = 20

type zapInstance struct {
	URI       flexStr `json:"uri" xml:"uri"`
	Method    flexStr `json:"method" xml:"method"`
	Param     flexStr `json:"param" xml:"param"`
	Attack    flexStr `json:"attack" xml:"attack"`
	Evidence  flexStr `json:"evidence" xml:"evidence"`
	OtherInfo flexStr `json:"otherinfo" xml:"otherinfo"`
}

type zapTag struct {
	Name string `xml:"tag"`
	Link string `xml:"link"`
}

type zapAlert struct {
	PluginID   flexStr       `json:"pluginid" xml:"pluginid"`
	AlertRef   flexStr       `json:"alertRef" xml:"alertRef"`
	Alert      flexStr       `json:"alert" xml:"alert"`
	Name       flexStr       `json:"name" xml:"name"`
	RiskCode   flexStr       `json:"riskcode" xml:"riskcode"`
	Confidence flexStr       `json:"confidence" xml:"confidence"`
	Desc       flexStr       `json:"desc" xml:"desc"`
	Instances  []zapInstance `json:"instances" xml:"instances>instance"`
	Count      flexStr       `json:"count" xml:"count"`
	Systemic   flexStr       `json:"systemic" xml:"systemic"`
	Solution   flexStr       `json:"solution" xml:"solution"`
	OtherInfo  flexStr       `json:"otherinfo" xml:"otherinfo"`
	Reference  flexStr       `json:"reference" xml:"reference"`
	CWEID      flexStr       `json:"cweid" xml:"cweid"`
	WASCID     flexStr       `json:"wascid" xml:"wascid"`
	SourceID   flexStr       `json:"sourceid" xml:"sourceid"`
	// JSON: {"NAME": "link"}; XML: <tags><tag><tag>NAME</tag><link/></tag></tags>.
	TagsJSON map[string]string `json:"tags" xml:"-"`
	TagsXML  []zapTag          `json:"-" xml:"tags>tag"`
}

// UnmarshalXML reads flexStr element text in the XML form.
func (f *flexStr) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var s string
	if err := d.DecodeElement(&s, &start); err != nil {
		return err
	}
	*f = flexStr(s)
	return nil
}

type zapSite struct {
	Name   string     `json:"@name" xml:"name,attr"`
	Host   string     `json:"@host" xml:"host,attr"`
	Port   flexStr    `json:"@port" xml:"port,attr"`
	SSL    flexStr    `json:"@ssl" xml:"ssl,attr"`
	Alerts []zapAlert `json:"alerts" xml:"alerts>alertitem"`
}

func (f *flexStr) UnmarshalXMLAttr(a xml.Attr) error {
	*f = flexStr(a.Value)
	return nil
}

func parseZAP(b *builder, r io.Reader) error {
	br := bufio.NewReader(r)
	for {
		c, err := br.Peek(1)
		if err != nil {
			return &ParseError{Format: FormatZAP, Msg: "empty input", Err: ErrMalformed}
		}
		if c[0] == 0xEF || c[0] == ' ' || c[0] == '\t' || c[0] == '\r' || c[0] == '\n' {
			if c[0] == 0xEF {
				if bom, _ := br.Peek(3); bytes.Equal(bom, utf8BOM) {
					_, _ = br.Discard(3)
					continue
				}
				break
			}
			_, _ = br.Discard(1)
			continue
		}
		break
	}
	if c, _ := br.Peek(1); len(c) == 1 && c[0] == '<' {
		return b.zapXML(br)
	}
	return b.zapJSON(br)
}

const zapSiteJ = "/site[]"

func (b *builder) zapJSON(r io.Reader) error {
	data, err := readAll(r, FormatZAP, b.lim)
	if err != nil {
		return err
	}
	doc, err := scanJSON(data, FormatZAP, b.lim, b.obs, zapSiteJ)
	if err != nil {
		return err
	}
	var top struct {
		Program string          `json:"@programName"`
		Version string          `json:"@version"`
		Created string          `json:"created"`
		Gen     string          `json:"@generated"`
		Site    json.RawMessage `json:"site"`
	}
	if err := doc.decode(&top); err != nil {
		return err
	}
	b.zapMeta(top.Version, firstNonEmpty(top.Created, top.Gen))
	var sites []json.RawMessage
	raw := bytes.TrimSpace(top.Site)
	switch {
	case len(raw) == 0 || bytes.Equal(raw, []byte("null")):
		return &ParseError{Format: FormatZAP, Msg: "no site member", Err: ErrMalformed}
	case raw[0] == '{':
		sites = []json.RawMessage{raw}
	default:
		if err := json.Unmarshal(raw, &sites); err != nil {
			return &ParseError{Format: FormatZAP, Msg: "site is not a list of sites", Err: ErrMalformed}
		}
	}
	for i, s := range sites {
		var site zapSite
		ptr := "/site/" + strconv.Itoa(i)
		if err := json.Unmarshal(s, &site); err != nil {
			b.issue(doc.issueAt(zapSiteJ, i, ptr, "site skipped: "+jsonErrText(err)))
			continue
		}
		is := doc.issueAt(zapSiteJ, i, ptr, "")
		if err := b.zapSite(&site, is.Line, ptr); err != nil {
			return err
		}
	}
	return nil
}

func (b *builder) zapXML(r io.Reader) error {
	xr := newXMLReader(r, FormatZAP, b.lim, nil, b.obs)
	dec := xml.NewTokenDecoder(xr)
	sawRoot := false
	n := 0
	for {
		if err := b.tick(); err != nil {
			return err
		}
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return asParseError(err, FormatZAP)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "OWASPZAPReport":
			sawRoot = true
			b.zapMeta(attrValue(se, "version"), attrValue(se, "generated"))
		case "site":
			if !sawRoot {
				return &ParseError{Format: FormatZAP, Msg: "not an OWASPZAPReport document", Err: ErrMalformed}
			}
			lineNo, _ := xr.d.InputPos()
			var site zapSite
			if err := dec.DecodeElement(&site, &se); err != nil {
				return asParseError(err, FormatZAP)
			}
			if err := b.zapSite(&site, lineNo, fmt.Sprintf("/OWASPZAPReport/site[%d]", n)); err != nil {
				return err
			}
			n++
		default:
			if !sawRoot {
				return &ParseError{Format: FormatZAP, Msg: fmt.Sprintf("root element is <%s>, want <OWASPZAPReport>", se.Name.Local), Err: ErrMalformed}
			}
		}
	}
	if !sawRoot {
		return &ParseError{Format: FormatZAP, Msg: "no OWASPZAPReport element", Err: ErrMalformed}
	}
	return nil
}

func (b *builder) zapMeta(version, generated string) {
	if v := line(version, 64); v != "" && b.res.Report.Tool != nil {
		b.res.Report.Tool.Version = v
	}
	if g := line(generated, 64); g != "" {
		if b.res.Report.Metadata.Properties == nil {
			b.res.Report.Metadata.Properties = ctis.Properties{}
		}
		b.res.Report.Metadata.Properties["generated"] = g
	}
}

// zapSiteAsset names a site by its origin (scheme, host and port), without
// path, query or user info.
func zapSiteAsset(s *zapSite) (ctis.Asset, string, int, bool) {
	host := strings.ToLower(strings.TrimSuffix(line(s.Host, capShort), "."))
	port, _ := strconv.Atoi(s.Port.String())
	scheme := "http"
	if s.SSL.Bool() {
		scheme = "https"
	}
	if u, err := url.Parse(strings.TrimSpace(s.Name)); err == nil && u.Host != "" {
		if host == "" {
			host = strings.ToLower(u.Hostname())
		}
		if u.Scheme == "https" || u.Scheme == "http" {
			scheme = u.Scheme
		}
		if port == 0 {
			port, _ = strconv.Atoi(u.Port())
		}
	}
	if host == "" {
		return ctis.Asset{}, "", 0, false
	}
	if port <= 0 || port > 65535 {
		port = map[string]int{"http": 80, "https": 443}[scheme]
	}
	origin := scheme + "://" + host
	if (scheme != "http" || port != 80) && (scheme != "https" || port != 443) {
		origin = scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port))
	}
	a := ctis.Asset{ID: "site-" + origin, Type: ctis.AssetTypeWebsite, Value: origin, Name: origin,
		Properties: ctis.Properties{"host": host, "port": strconv.Itoa(port), "scheme": scheme}}
	return a, host, port, true
}

func (b *builder) zapSite(s *zapSite, lineNo int, ptr string) error {
	asset, host, port, ok := zapSiteAsset(s)
	if !ok {
		b.issue(Issue{Line: lineNo, Path: ptr, Message: "site without a host: skipped"})
		b.res.Stats.Records += len(s.Alerts)
		b.res.Stats.Skipped += len(s.Alerts)
		return nil
	}
	assetID, err := b.asset(asset)
	if err != nil {
		return err
	}
	for i := range s.Alerts {
		b.res.Stats.Records++
		if err := b.tick(); err != nil {
			return err
		}
		f, ok := b.zapFinding(&s.Alerts[i], assetID, host, port, lineNo, fmt.Sprintf("%s/alerts/%d", ptr, i))
		if !ok {
			b.res.Stats.Skipped++
			continue
		}
		if err := b.finding(f); err != nil {
			return err
		}
	}
	return nil
}

func (b *builder) zapFinding(a *zapAlert, assetID, host string, port, lineNo int, ptr string) (ctis.Finding, bool) {
	title := line(firstNonEmpty(a.Alert.String(), a.Name.String()), capTitle)
	plugin := line(a.PluginID.String(), capShort)
	if title == "" || plugin == "" {
		b.issue(Issue{Line: lineNo, Path: ptr, Message: "alert without a name or a plugin id: skipped"})
		return ctis.Finding{}, false
	}
	risk := a.RiskCode.String()
	sev := map[string]ctis.Severity{"0": ctis.SeverityInfo, "1": ctis.SeverityLow, "2": ctis.SeverityMedium, "3": ctis.SeverityHigh}[risk]
	if sev == "" {
		b.issue(Issue{Line: lineNo, Path: ptr, Message: fmt.Sprintf("alert %s: unknown riskcode %q, kept as medium", plugin, line(risk, 16))})
		sev = ctis.SeverityMedium
	}
	f := ctis.Finding{
		Type:        ctis.FindingTypeVulnerability,
		Title:       title,
		Severity:    sev,
		RuleID:      plugin,
		RuleName:    title,
		AssetRef:    assetID,
		Description: text(qualysHTML(a.Desc.String()), capDescription),
		Network:     &ctis.NetworkLocation{Host: host, Port: port, Protocol: "tcp", Service: "http"},
		Native: &ctis.NativeIdentity{
			Scheme:     ctis.NativeSchemeOther,
			VulnID:     plugin,
			InstanceID: line(a.AlertRef.String(), ctis.MaxNativeIDLen),
			Severity:   line(risk, ctis.MaxNativeValueLen),
			RawRef:     line(ptr, ctis.MaxRawRefLen),
		},
	}
	switch a.Confidence.String() {
	case "0":
		// A person marked the alert a false positive in ZAP.
		f.Status = ctis.FindingStatusFalsePositive
		f.Native.Status = "false_positive"
	case "1":
		f.Confidence = 30
	case "2":
		f.Confidence = 60
	case "3":
		f.Confidence = 90
	case "4":
		f.Confidence = 100
		f.Native.DetectionType = ctis.DetectionTypeConfirmed
	}
	if sev == ctis.SeverityInfo {
		f.Native.DetectionType = ctis.DetectionTypeInfo
	}
	if c, err := strconv.Atoi(a.CWEID.String()); err == nil && c > 0 {
		f.Vulnerability = &ctis.VulnerabilityDetails{CWEID: "CWE-" + strconv.Itoa(c), CWEIDs: []string{"CWE-" + strconv.Itoa(c)}}
	}
	if sol := text(qualysHTML(a.Solution.String()), capRemediation); sol != "" {
		f.Remediation = &ctis.Remediation{Recommendation: sol}
	}
	for _, w := range strings.Fields(qualysHTML(a.Reference.String())) {
		if validURL(w) {
			f.References = addRefs(f.References, w)
		}
	}
	for _, name := range sortedTagNames(a.TagsJSON) {
		f.Tags = addTags(f.Tags, name)
		if validURL(a.TagsJSON[name]) {
			f.References = addRefs(f.References, a.TagsJSON[name])
		}
	}
	for _, t := range a.TagsXML {
		f.Tags = addTags(f.Tags, t.Name)
		if validURL(t.Link) {
			f.References = addRefs(f.References, t.Link)
		}
	}
	if n, err := strconv.Atoi(a.Count.String()); err == nil && n > 0 {
		f.OccurrenceCount = n
	} else if len(a.Instances) > 0 {
		f.OccurrenceCount = len(a.Instances)
	}
	var ev []string
	for i, in := range a.Instances {
		if i == zapMaxInstances {
			ev = append(ev, fmt.Sprintf("... %d more instances", len(a.Instances)-zapMaxInstances))
			break
		}
		parts := []string{line(in.Method.String(), 16), line(zapURI(in.URI.String()), 2048)}
		for _, kv := range [][2]string{{"param", in.Param.String()}, {"attack", in.Attack.String()}, {"evidence", in.Evidence.String()}, {"otherinfo", in.OtherInfo.String()}} {
			if v := line(kv[1], 1024); v != "" {
				parts = append(parts, kv[0]+"="+v)
			}
		}
		ev = append(ev, strings.TrimSpace(strings.Join(parts, " ")))
	}
	if len(ev) > 0 {
		f.Evidence = text(strings.Join(ev, "\n"), capEvidence)
	}
	extras(&f, "otherinfo", qualysHTML(a.OtherInfo.String()), "wascid", a.WASCID.String(),
		"sourceid", a.SourceID.String(), "systemic", a.Systemic.String(), "confidence", a.Confidence.String())
	return f, true
}

// zapURI drops the user info of an instance URI (credentials typed into a
// URL never reach the report).
func zapURI(s string) string {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.User == nil {
		return s
	}
	u.User = nil
	return u.String()
}

func sortedTagNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
