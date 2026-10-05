package importer

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/ctis"
)

// Nessus v2 XML (.nessus): NessusClientData_v2 > Report > ReportHost >
// (HostProperties > tag, ReportItem). The mapping is spec_nessus.go.

func init() {
	parsers[FormatNessus] = parseNessus
	tools[FormatNessus] = ctis.Tool{Name: "nessus", Vendor: "Tenable", Capabilities: []string{"va"}}
}

// xmlField is any child element of a ReportItem, by local name, so the
// compliance members in the cm namespace are read like the others.
type xmlField struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

type nessusTag struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

type nessusItem struct {
	Port         string     `xml:"port,attr"`
	SvcName      string     `xml:"svc_name,attr"`
	Protocol     string     `xml:"protocol,attr"`
	Severity     string     `xml:"severity,attr"`
	PluginID     string     `xml:"pluginID,attr"`
	PluginName   string     `xml:"pluginName,attr"`
	PluginFamily string     `xml:"pluginFamily,attr"`
	Fields       []xmlField `xml:",any"`
}

type nessusHost struct {
	Name  string       `xml:"name,attr"`
	Tags  []nessusTag  `xml:"HostProperties>tag"`
	Items []nessusItem `xml:"ReportItem"`
}

// values groups the item's children by local name, keeping repeats in order.
func (it *nessusItem) values() map[string][]string {
	out := make(map[string][]string, len(it.Fields))
	for _, f := range it.Fields {
		out[f.XMLName.Local] = append(out[f.XMLName.Local], f.Value)
	}
	return out
}

func parseNessus(b *builder, r io.Reader) error {
	xr := newXMLReader(r, FormatNessus, b.lim, map[string]string{"tag": "name"}, b.obs)
	dec := xml.NewTokenDecoder(xr)
	sawRoot := false
	for {
		if err := b.tick(); err != nil {
			return err
		}
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return asParseError(err, FormatNessus)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "NessusClientData_v2":
			sawRoot = true
		case "Policy":
			// The scan policy: server and plugin preferences, which hold
			// the scan's credentials (masked or not) and account names.
			// Nothing of it is read.
			if err := dec.Skip(); err != nil {
				return asParseError(err, FormatNessus)
			}
		case "Report":
			if name := line(attrValue(se, "name"), capShort); name != "" {
				if b.res.Report.Metadata.Properties == nil {
					b.res.Report.Metadata.Properties = ctis.Properties{}
				}
				b.res.Report.Metadata.Properties["scan_name"] = name
			}
		case "ReportHost":
			if !sawRoot {
				return &ParseError{Format: FormatNessus, Msg: "not a NessusClientData_v2 document", Err: ErrMalformed}
			}
			lineNo, _ := xr.d.InputPos()
			var h nessusHost
			if err := dec.DecodeElement(&h, &se); err != nil {
				return asParseError(err, FormatNessus)
			}
			if err := b.nessusHost(&h, lineNo); err != nil {
				return err
			}
		default:
			if !sawRoot {
				return &ParseError{Format: FormatNessus, Msg: fmt.Sprintf("root element is <%s>, want <NessusClientData_v2>", se.Name.Local), Err: ErrMalformed}
			}
		}
	}
	if !sawRoot {
		return &ParseError{Format: FormatNessus, Msg: "no NessusClientData_v2 element", Err: ErrMalformed}
	}
	return nil
}

// asParseError keeps a ParseError and wraps anything else.
func asParseError(err error, f Format) error {
	var pe *ParseError
	if errors.As(err, &pe) {
		return pe
	}
	var se *xml.SyntaxError
	if errors.As(err, &se) {
		return &ParseError{Format: f, Line: se.Line, Msg: se.Msg, Err: ErrMalformed}
	}
	return &ParseError{Format: f, Msg: err.Error(), Err: ErrMalformed}
}

// nessusHostProps are the HostProperties tags, by name (the first value of a
// repeated name wins).
type nessusHostProps map[string]string

func (p nessusHostProps) get(name string) string { return strings.TrimSpace(p[name]) }

func (b *builder) nessusHost(h *nessusHost, lineNo int) error {
	props := nessusHostProps{}
	for _, t := range h.Tags {
		if _, ok := props[t.Name]; !ok {
			props[t.Name] = t.Value
		}
	}
	ip := props.get("host-ip")
	fqdn := strings.ToLower(strings.TrimSuffix(props.get("host-fqdn"), "."))
	value := fqdn
	if value == "" {
		value = ip
	}
	if value == "" {
		value = strings.TrimSpace(h.Name)
	}
	value = line(value, capShort)
	if value == "" {
		b.issue(Issue{Line: lineNo, Path: "/NessusClientData_v2/Report/ReportHost", Message: "host without name, host-ip or host-fqdn: skipped"})
		b.res.Stats.Records += len(h.Items)
		b.res.Stats.Skipped += len(h.Items)
		return nil
	}

	asset := ctis.Asset{ID: "host-" + value, Type: ctis.AssetTypeHost, Value: value, Name: value}
	if net.ParseIP(value) != nil {
		asset.Type = ctis.AssetTypeIPAddress
	}
	ap := ctis.Properties{}
	setProp := func(k, v string) {
		if v = line(v, capShort); v != "" {
			ap[k] = v
		}
	}
	setProp("ip_address", ip)
	setProp("fqdn", fqdn)
	setProp("os", firstLine(props.get("operating-system")))
	setProp("mac_address", props.get("mac-address"))
	setProp("host_rdns", props.get("host-rdns"))
	setProp("system_type", props.get("system-type"))
	setProp("os_confidence", props.get("operating-system-conf"))
	setProp("os_method", props.get("operating-system-method"))
	setProp("bios_uuid", props.get("bios-uuid"))
	setProp("scan_started_at", nessusTime(props.get("HOST_START_TIMESTAMP"), props.get("HOST_START")))
	setProp("scan_ended_at", nessusTime(props.get("HOST_END_TIMESTAMP"), props.get("HOST_END")))
	setProp("local_checks_protocol", props.get("local-checks-proto"))
	if len(ap) > 0 {
		asset.Properties = ap
	}

	hints := &ctis.IdentityHints{
		FQDN:        line(fqdn, ctis.MaxIdentityHintLen),
		NetBIOSName: line(props.get("netbios-name"), ctis.MaxIdentityHintLen),
		OSCPE:       nessusOSCPE(props),
	}
	for _, mac := range strings.Fields(props.get("mac-address")) {
		if len(hints.MACAddresses) < ctis.MaxIdentityHintMACs && len(mac) <= ctis.MaxIdentityHintLen {
			hints.MACAddresses = append(hints.MACAddresses, strings.ToLower(mac))
		}
	}
	for _, k := range []string{"aws-instance-instanceId", "azure-instance-id", "gcp-instance-id"} {
		if v := line(props.get(k), ctis.MaxIdentityHintLen); v != "" {
			hints.CloudResourceID = v
			break
		}
	}
	for _, k := range []string{"nessus-agent-uuid", "tenable-agent-uuid", "agent-uuid"} {
		if v := line(props.get(k), ctis.MaxIdentityHintLen); v != "" {
			hints.ScannerAgentID = v
			break
		}
	}
	if hints.FQDN != "" || hints.NetBIOSName != "" || hints.OSCPE != "" || hints.CloudResourceID != "" || hints.ScannerAgentID != "" || len(hints.MACAddresses) > 0 {
		asset.IdentityHints = hints
	}
	assetID, err := b.asset(asset)
	if err != nil {
		return err
	}

	var credentialed *bool
	switch strings.ToLower(props.get("Credentialed_Scan")) {
	case "true", "yes":
		t := true
		credentialed = &t
	case "false", "no":
		f := false
		credentialed = &f
	}

	for i := range h.Items {
		b.res.Stats.Records++
		if err := b.tick(); err != nil {
			return err
		}
		f, ok := b.nessusFinding(&h.Items[i], assetID, value, credentialed, lineNo)
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

// firstLine returns the first line of a multi-line value (Nessus lists
// several OS guesses, one per line).
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// nessusOSCPE returns the operating system CPE among the cpe tags ("cpe-0"
// is "cpe:/o:vendor:product -> Name").
func nessusOSCPE(p nessusHostProps) string {
	for _, k := range []string{"cpe", "cpe-0", "cpe-1", "cpe-2", "cpe-3"} {
		v := p.get(k)
		if v == "" {
			continue
		}
		if i := strings.Index(v, " -> "); i >= 0 {
			v = v[:i]
		}
		v = strings.TrimSpace(v)
		if strings.HasPrefix(v, "cpe:/o:") || strings.HasPrefix(v, "cpe:2.3:o:") {
			return line(v, ctis.MaxIdentityHintLen)
		}
	}
	return ""
}

// nessusTime returns a host scan time as RFC 3339: from the Unix timestamp
// tag when present, else from the ctime string ("Mon Jan  2 15:04:05 2006").
func nessusTime(unix, ctime string) string {
	if n, err := strconv.ParseInt(strings.TrimSpace(unix), 10, 64); err == nil && n > 0 {
		return time.Unix(n, 0).UTC().Format(time.RFC3339)
	}
	if t, err := time.Parse(time.ANSIC, strings.Join(strings.Fields(ctime), " ")); err == nil {
		return t.UTC().Format(time.RFC3339)
	}
	if t, err := time.Parse("Mon Jan 2 15:04:05 2006", strings.Join(strings.Fields(ctime), " ")); err == nil {
		return t.UTC().Format(time.RFC3339)
	}
	return ""
}

// nessusDate reads the item dates ("2024/03/29").
func nessusDate(s string) *time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"2006/01/02", "2006-01-02", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}

func first(v map[string][]string, k string) string {
	if s := v[k]; len(s) > 0 {
		return strings.TrimSpace(s[0])
	}
	return ""
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "yes", "1", "y":
		return true
	}
	return false
}

func parseScore(s string, max float64) (float64, bool) {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || v < 0 || v > max || v != v {
		return 0, false
	}
	return v, true
}

// nessusExtra are item members kept in source_extra under their own name.
var nessusExtra = []string{
	"risk_factor", "plugin_type", "plugin_publication_date", "plugin_modification_date",
	"exploitability_ease", "exploit_framework_metasploit", "exploit_framework_canvas",
	"exploit_framework_core", "exploit_framework_d2_elliot", "exploit_framework_exploithub",
	"metasploit_name", "canvas_package", "d2_elliot_name", "exploited_by_malware",
	"exploited_by_nessus", "in_the_news", "unsupported_by_vendor", "default_account",
	"stig_severity", "age_of_vuln", "threat_intensity_last_28", "threat_recency",
	"threat_sources_last_28", "product_coverage", "cvss_temporal_score", "cvss_temporal_vector",
	"cvss3_temporal_score", "cvss3_temporal_vector", "cvss3_impact_score", "cvssV3_impact_score",
	"cvss4_threat_score", "cvss4_threat_vector", "cvss_score_source", "cvss3_score_source",
	"vendor_severity", "vendor_unpatched", "cisa-known-exploited", "cisa_known_exploited",
	"exploit_code_maturity", "patch_publication_date", "vuln_publication_date", "epss_score",
	"vpr_score", "rhsa", "usn", "dsa", "glsa", "fedora", "suse", "osvdb", "edb-id",
}

func (b *builder) nessusFinding(it *nessusItem, assetID, assetValue string, credentialed *bool, lineNo int) (ctis.Finding, bool) {
	v := it.values()
	pluginID := strings.TrimSpace(it.PluginID)
	itemPath := "/NessusClientData_v2/Report/ReportHost/ReportItem"
	if pluginID == "" {
		b.issue(Issue{Line: lineNo, Path: itemPath, Message: fmt.Sprintf("ReportItem on %s without pluginID: skipped", assetValue)})
		return ctis.Finding{}, false
	}
	nativeSev := strings.TrimSpace(it.Severity)
	sev, ok := ctis.NormalizeNativeSeverity(ctis.NativeSchemeNessus, nativeSev)
	if !ok {
		if s, ok2 := ctis.NormalizeNativeSeverity(ctis.NativeSchemeNessus, first(v, "risk_factor")); ok2 {
			sev = s
		} else {
			b.issue(Issue{Line: lineNo, Path: itemPath, Message: fmt.Sprintf("plugin %s on %s: unknown severity %q, kept as medium", pluginID, assetValue, nativeSev)})
			sev = ctis.SeverityMedium
		}
	}

	title := line(it.PluginName, capTitle)
	if title == "" {
		title = line(first(v, "plugin_name"), capTitle)
	}
	if title == "" {
		title = "Nessus plugin " + pluginID
	}

	f := ctis.Finding{
		Type:     ctis.FindingTypeVulnerability,
		Title:    title,
		Severity: sev,
		RuleID:   pluginID,
		RuleName: title,
		Category: line(it.PluginFamily, capCategory),
		AssetRef: assetID,
		Native: &ctis.NativeIdentity{
			Scheme:       ctis.NativeSchemeNessus,
			VulnID:       line(pluginID, ctis.MaxNativeIDLen),
			Family:       line(it.PluginFamily, ctis.MaxNativeIDLen),
			Severity:     line(nativeSev, ctis.MaxNativeValueLen),
			Credentialed: credentialed,
			RawRef:       line(fmt.Sprintf("ReportHost[%s]/ReportItem[pluginID=%s,port=%s,protocol=%s]", assetValue, pluginID, it.Port, it.Protocol), ctis.MaxRawRefLen),
		},
	}
	if sev == ctis.SeverityInfo {
		f.Native.DetectionType = ctis.DetectionTypeInfo
	}

	synopsis := text(first(v, "synopsis"), capDescription)
	desc := text(first(v, "description"), capDescription)
	switch {
	case synopsis != "" && desc != "" && synopsis != desc:
		f.Description = text(synopsis+"\n\n"+desc, capDescription)
	case desc != "":
		f.Description = desc
	default:
		f.Description = synopsis
	}
	f.Message = line(synopsis, 8<<10)
	if out := redactCredentials(first(v, "plugin_output")); out != "" {
		f.Evidence = text(out, capEvidence)
	}

	port, _ := strconv.Atoi(strings.TrimSpace(it.Port))
	svc := line(it.SvcName, capShort)
	if port > 0 && port <= 65535 {
		f.Network = &ctis.NetworkLocation{Host: assetValue, Port: port, Protocol: strings.ToLower(line(it.Protocol, 16)), Service: svc}
	} else if svc != "" && svc != "general" {
		f.Network = &ctis.NetworkLocation{Host: assetValue, Protocol: strings.ToLower(line(it.Protocol, 16)), Service: svc}
	}

	// Compliance audit results (cm: members).
	if check := first(v, "compliance-check-name"); check != "" {
		f.Type = ctis.FindingTypeCompliance
		f.Title = line(check, capTitle)
		// One plugin runs every check of an audit, so the check, not the
		// plugin, is the rule: two checks on a host are two findings.
		checkID := firstNonEmpty(first(v, "compliance-check-id"), first(v, "compliance-control-id"))
		if checkID != "" {
			f.RuleID = line(checkID, capShort)
			f.Native.InstanceID = line(checkID, ctis.MaxNativeIDLen)
		} else {
			f.RuleID = line(pluginID+":"+check, capShort)
		}
		f.RuleName = f.Title
		f.Compliance = &ctis.ComplianceDetails{
			Framework:          complianceFramework(first(v, "compliance-benchmark-name")),
			FrameworkVersion:   line(first(v, "compliance-benchmark-version"), capShort),
			ControlID:          line(firstNonEmpty(first(v, "compliance-control-id"), first(v, "compliance-check-id")), capShort),
			ControlName:        line(check, capShort),
			ControlDescription: text(first(v, "compliance-info"), 4<<10),
			Result:             nessusComplianceResult(first(v, "compliance-result")),
		}
		if out := redactCredentials(first(v, "compliance-actual-value")); out != "" {
			f.Evidence = text(out, capEvidence)
		}
		if sol := text(first(v, "compliance-solution"), capRemediation); sol != "" {
			f.Remediation = &ctis.Remediation{Recommendation: sol}
		}
		f.References = addRefs(f.References, splitLines(first(v, "compliance-see-also"))...)
		for _, k := range []string{"compliance-benchmark-name", "compliance-result", "compliance-policy-value", "compliance-audit-file", "compliance-benchmark-profile", "compliance-full-id", "compliance-functional-id", "compliance-reference", "compliance-check-id", "compliance-uname", "compliance-source"} {
			if k == "compliance-uname" {
				continue // the account the check ran as
			}
			extra(&f, k, first(v, k))
		}
	}

	vuln := &ctis.VulnerabilityDetails{}
	for _, c := range v["cve"] {
		addVulnID(vuln, c)
	}
	for _, bid := range v["bid"] {
		addVendorID(vuln, prefixed("BID", bid), "bid")
	}
	for _, x := range v["xref"] {
		kind, id, ok := strings.Cut(strings.TrimSpace(x), ":")
		if !ok {
			continue
		}
		kind, id = strings.TrimSpace(kind), strings.TrimSpace(id)
		switch strings.ToUpper(kind) {
		case "CWE":
			if n, err := strconv.Atoi(id); err == nil && n > 0 {
				vuln.CWEIDs = appendUnique(vuln.CWEIDs, "CWE-"+id)
			}
		case "CVE":
			addVulnID(vuln, id)
		case "MSFT", "MSKB", "IAVA", "IAVB", "CERT", "CISA-KNOWN-EXPLOITED", "CEA-ID", "TRA", "USN", "RHSA", "DSA", "GLSA":
			// Advisories below.
		default:
			addVendorID(vuln, prefixed(kind, id), strings.ToLower(kind))
		}
	}
	for _, x := range v["xref"] {
		kind, id, _ := strings.Cut(strings.TrimSpace(x), ":")
		switch strings.ToUpper(strings.TrimSpace(kind)) {
		case "MSFT", "MSKB", "IAVA", "IAVB", "CERT", "CEA-ID", "TRA", "USN", "RHSA", "DSA", "GLSA":
			kind = strings.TrimSpace(kind)
			id = strings.TrimSpace(id)
			switch strings.ToUpper(kind) {
			case "USN", "RHSA", "DSA", "GLSA":
				id = prefixed(kind, id)
			}
			addAdvisory(&f, id, strings.ToLower(kind))
		}
	}
	for _, k := range []string{"msft", "mskb", "iava", "iavb", "cert", "cea-id", "iavt"} {
		for _, id := range v[k] {
			addAdvisory(&f, id, k)
		}
	}
	if len(vuln.CWEIDs) > 0 {
		vuln.CWEID = vuln.CWEIDs[0]
	}

	// Scores: every CVSS version with its vector, VPR, EPSS.
	type cvss struct{ version, score, vector string }
	var cvsses []cvss
	if s := first(v, "cvss3_base_score"); s != "" {
		vec := first(v, "cvss3_vector")
		ver := ctis.CVSSVersionOfVector(vec)
		if ver == "" {
			ver = "3.0"
		}
		cvsses = append(cvsses, cvss{ver, s, vec})
	}
	if s := first(v, "cvss4_base_score"); s != "" {
		cvsses = append(cvsses, cvss{"4.0", s, firstNonEmpty(first(v, "cvss4_vector"), first(v, "cvss4_base_vector"))})
	}
	if s := first(v, "cvss_base_score"); s != "" {
		vec := strings.TrimPrefix(first(v, "cvss_vector"), "CVSS2#")
		cvsses = append(cvsses, cvss{"2.0", s, vec})
	}
	for _, c := range cvsses {
		val, ok := parseScore(c.score, 10)
		if !ok {
			continue
		}
		if vuln.CVSSVersion == "" {
			vuln.CVSSScore, vuln.CVSSVersion, vuln.CVSSVector, vuln.CVSSSource = val, c.version, line(c.vector, ctis.MaxScoreVectorLen), "vendor"
		}
		vc := val
		addScore(&f, ctis.Score{System: ctis.ScoreSystemCVSS, Version: c.version, Vector: line(c.vector, ctis.MaxScoreVectorLen), Value: &vc, Source: "tenable"})
	}
	if val, ok := parseScore(first(v, "vpr_score"), 10); ok {
		vuln.VPRScore = val
		vc := val
		addScore(&f, ctis.Score{System: ctis.ScoreSystemVPR, Value: &vc, Source: "tenable"})
	}
	if val, ok := parseScore(first(v, "epss_score"), 1); ok {
		vuln.EPSSScore = val
		vc := val
		addScore(&f, ctis.Score{System: ctis.ScoreSystemEPSS, Value: &vc, Source: "tenable"})
	}
	if truthy(first(v, "exploit_available")) {
		vuln.ExploitAvailable = true
	}
	if m := nessusMaturity(first(v, "exploit_code_maturity")); m != "" {
		vuln.ExploitMaturity = m
	}
	if first(v, "cisa-known-exploited") != "" || first(v, "cisa_known_exploited") != "" {
		vuln.InCISAKEV = true
	}
	for _, x := range v["xref"] {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(x)), "CISA-KNOWN-EXPLOITED:") {
			vuln.InCISAKEV = true
		}
	}
	if cpe := firstLine(first(v, "cpe")); cpe != "" {
		vuln.CPE = line(cpe, capShort)
	}
	vuln.PublishedAt = nessusDate(first(v, "vuln_publication_date"))
	if vuln.CVEID != "" || len(vuln.IDs) > 0 || vuln.CVSSScore > 0 || vuln.VPRScore > 0 || vuln.CPE != "" || vuln.ExploitAvailable || vuln.InCISAKEV || len(vuln.CWEIDs) > 0 || vuln.PublishedAt != nil || vuln.EPSSScore > 0 || vuln.ExploitMaturity != "" {
		f.Vulnerability = vuln
	}

	if f.Type != ctis.FindingTypeCompliance {
		sol := text(first(v, "solution"), capRemediation)
		if strings.EqualFold(sol, "n/a") {
			sol = ""
		}
		patch := nessusDate(first(v, "patch_publication_date"))
		if sol != "" || patch != nil || f.Remediation != nil {
			if f.Remediation == nil {
				f.Remediation = &ctis.Remediation{}
			}
			f.Remediation.Recommendation = sol
			f.Remediation.PatchPublishedAt = patch
			if patch != nil {
				f.Remediation.FixAvailable = true
			}
		}
		if truthy(first(v, "unsupported_by_vendor")) {
			if f.Remediation == nil {
				f.Remediation = &ctis.Remediation{}
			}
			f.Remediation.SolutionType = ctis.SolutionTypeUpgrade
		}
	}
	f.References = addRefs(f.References, splitLines(first(v, "see_also"))...)

	// The receiver's established property names for the two CVSS vectors
	// and the patch date.
	fp := ctis.Properties{}
	if s := first(v, "cvss_vector"); s != "" {
		fp["cvss_v2_vector"] = line(s, ctis.MaxScoreVectorLen)
	}
	if s := first(v, "cvss3_vector"); s != "" {
		fp["cvss_v3_vector"] = line(s, ctis.MaxScoreVectorLen)
	}
	if s := first(v, "patch_publication_date"); s != "" {
		fp["patch_publication_date"] = line(s, 32)
	}
	if len(fp) > 0 {
		f.Properties = fp
	}

	for _, k := range nessusExtra {
		if vals := v[k]; len(vals) > 0 {
			extra(&f, k, strings.Join(vals, "\n"))
		}
	}
	if xr := v["xref"]; len(xr) > 0 {
		extra(&f, "xref", strings.Join(xr, "\n"))
	}
	return f, true
}

// prefixed returns id with the upper-case kind as its prefix ("EDB-ID-41891",
// "USN-6560-1"), so a bare number from one namespace never equals a bare
// number from another.
func prefixed(kind, id string) string {
	kind = strings.ToUpper(strings.TrimSpace(kind))
	id = strings.TrimSpace(id)
	if id == "" || strings.HasPrefix(strings.ToUpper(id), kind) {
		return id
	}
	return kind + "-" + id
}

func firstNonEmpty(vals ...string) string {
	for _, s := range vals {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return ""
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func appendUnique(dst []string, s string) []string {
	for _, d := range dst {
		if d == s {
			return dst
		}
	}
	return append(dst, s)
}

// addVendorID adds a vendor vulnerability id with its issuer.
func addVendorID(v *ctis.VulnerabilityDetails, id, source string) {
	id = strings.TrimSpace(id)
	n, ok := ctis.NormalizeVulnerabilityID(id)
	if !ok || len(v.IDs) >= ctis.MaxVulnerabilityIDs {
		return
	}
	if n.Type == ctis.VulnerabilityIDVendor {
		n.Source = line(source, 64)
	}
	for _, have := range v.IDs {
		if have.Type == n.Type && strings.EqualFold(have.ID, n.ID) {
			return
		}
	}
	v.IDs = append(v.IDs, n)
	if n.Type == ctis.VulnerabilityIDCVE {
		v.CVEIDs = append(v.CVEIDs, n.ID)
		if v.CVEID == "" {
			v.CVEID = n.ID
		}
	}
}

// addAdvisory adds a vendor advisory to the finding's remediation.
func addAdvisory(f *ctis.Finding, id, source string) {
	id = line(id, ctis.MaxNativeIDLen)
	if id == "" {
		return
	}
	if f.Remediation == nil {
		f.Remediation = &ctis.Remediation{}
	}
	for _, a := range f.Remediation.Advisories {
		if a.ID == id && a.Source == source {
			return
		}
	}
	if len(f.Remediation.Advisories) >= ctis.MaxAdvisories {
		return
	}
	f.Remediation.Advisories = append(f.Remediation.Advisories, ctis.Advisory{ID: id, Source: source})
}

func nessusComplianceResult(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "PASSED":
		return "pass"
	case "FAILED":
		return "fail"
	case "WARNING":
		return "manual"
	case "ERROR", "SKIPPED":
		return "not_applicable"
	}
	return ""
}

// complianceFramework names the framework of a benchmark in the CTIS
// vocabulary (pci-dss, hipaa, soc2, cis, nist, iso27001, gdpr, fedramp), or
// returns "" (the benchmark name is kept in source_extra).
func complianceFramework(benchmark string) string {
	b := strings.ToLower(benchmark)
	switch {
	case strings.HasPrefix(b, "cis"):
		return "cis"
	case strings.Contains(b, "pci"):
		return "pci-dss"
	case strings.Contains(b, "hipaa"):
		return "hipaa"
	case strings.Contains(b, "nist") || strings.Contains(b, "800-53"):
		return "nist"
	case strings.Contains(b, "iso 27001") || strings.Contains(b, "iso27001"):
		return "iso27001"
	case strings.Contains(b, "fedramp"):
		return "fedramp"
	case strings.Contains(b, "soc 2") || strings.Contains(b, "soc2"):
		return "soc2"
	case strings.Contains(b, "gdpr"):
		return "gdpr"
	}
	return ""
}

// nessusMaturity maps exploit_code_maturity to the CTIS exploit maturity
// words.
func nessusMaturity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return "weaponized"
	case "functional":
		return "functional"
	case "poc", "proof-of-concept", "proof of concept":
		return "poc"
	case "unproven":
		return "unproven"
	}
	return ""
}

// Credential redaction. Scanner output names the accounts a scan logged in
// with ("Credentialed checks : yes, as 'root' via ssh", "User: 'admin'")
// and, misconfigured, can echo a password or community string. None of that
// is a property of the finding, so it never leaves the parser.
var (
	reAccountLine = regexp.MustCompile(`(?im)^([ \t]*(?:user ?name|user|login|account|domain\\user|credentials?|community(?: string)?)[ \t]*[:=][ \t]*)\S.*$`)
	reSecretKV    = regexp.MustCompile(`(?i)(\b(?:password|passwd|pwd|passphrase|secret|token|api[_-]?key|community)\b[ \t]*[:=][ \t]*)\S+`)
	reAsAccount   = regexp.MustCompile(`(?i)(\bas[ \t]+)'[^'\n]*'`)
)

const redacted = "[redacted]"

func redactCredentials(s string) string {
	if s == "" {
		return s
	}
	s = reAccountLine.ReplaceAllString(s, "${1}"+redacted)
	s = reSecretKV.ReplaceAllString(s, "${1}"+redacted)
	s = reAsAccount.ReplaceAllString(s, "${1}'"+redacted+"'")
	return s
}
