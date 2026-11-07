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

	"github.com/openctemio/ctis/v2"
)

// Nessus v2 XML (.nessus): NessusClientData_v2 > Report > ReportHost >
// (HostProperties > tag, ReportItem). The mapping is spec_nessus.go.

func init() {
	parsers[FormatNessus] = parseNessus
	tools[FormatNessus] = ctis.Tool{Name: "nessus", Vendor: "Tenable", Techniques: []ctis.Technique{ctis.TechniqueVA}}
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

func parseNessus(b *Builder, r io.Reader) error {
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
			// Only the plugin selection is read (nessusPolicy): which
			// families and plugins ran.
			if err := b.nessusReadPolicy(dec, &se); err != nil {
				return err
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
	b.nessusReport()
	b.nessusFinishCoverage()
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

func (b *Builder) nessusHost(h *nessusHost, lineNo int) error {
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

	asset := ctis.Asset{Type: ctis.AssetTypeHost, Value: value, Name: value}
	if net.ParseIP(value) != nil {
		asset.Type = ctis.AssetTypeIPAddress
	}
	if os := line(firstLine(props.get("operating-system")), capShort); os != "" {
		t := ctis.Technology{Name: os, Categories: []string{"operating-system"}}
		if c := nessusConfidence(props.get("operating-system-conf")); c > 0 {
			t.Confidence = c
		}
		asset.Technologies = []ctis.Technology{t}
	}
	var osTech *ctis.Technology
	if len(asset.Technologies) > 0 {
		osTech = &asset.Technologies[0]
	}
	for _, t := range nessusCPETechnologies(h.Tags, osTech) {
		if len(asset.Technologies) >= ctis.MaxTechnologies {
			b.issue(Issue{Line: lineNo, Path: nsTag, Message: fmt.Sprintf("host %s: more than %d technologies from cpe tags, the rest left out", value, ctis.MaxTechnologies)})
			break
		}
		asset.Technologies = append(asset.Technologies, t)
	}
	if u := line(props.get("bios-uuid"), ctis.MaxIdentityHintLen); u != "" {
		asset.Identifiers = &ctis.AssetIdentifiers{BIOSUUID: u}
	}
	if t := parseTime(nessusTime(props.get("HOST_START_TIMESTAMP"), props.get("HOST_START"))); t != nil {
		asset.FirstSeenAt = t
	}
	if t := parseTime(nessusTime(props.get("HOST_END_TIMESTAMP"), props.get("HOST_END"))); t != nil {
		asset.LastSeenAt = t
	}
	if asset.FirstSeenAt != nil && asset.LastSeenAt != nil && asset.LastSeenAt.Before(*asset.FirstSeenAt) {
		asset.FirstSeenAt = nil
	}
	ap := ctis.Properties{}
	setProp := func(k, v string) {
		if v = line(v, capShort); v != "" {
			ap[k] = v
		}
	}
	setProp("host_rdns", props.get("host-rdns"))
	setProp("system_type", props.get("system-type"))
	setProp("os_method", props.get("operating-system-method"))
	setProp("local_checks_protocol", props.get("local-checks-proto"))
	if keys := nessusSSHFingerprints(props.get("ssh-fingerprint")); len(keys) > 0 {
		// CTIS identity_hints has no SSH host key member: the keys go to
		// properties, for a receiver that matches hosts by them.
		ap["ssh_host_key_fingerprints"] = keys
	}
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
	if assetID == "" {
		b.res.Stats.Records += len(h.Items)
		b.res.Stats.Skipped += len(h.Items)
		return nil
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

	reached := map[string]bool{}
	packages := map[string]bool{}
	osName := props.get("operating-system")
	for i := range h.Items {
		b.res.Stats.Records++
		if err := b.tick(); err != nil {
			return err
		}
		it := &h.Items[i]
		b.nessusDetails.note(it)
		f, ok := b.nessusFinding(it, assetID, value, credentialed, lineNo)
		if !ok {
			b.res.Stats.Skipped++
			continue
		}
		// The finding was observed when its host's scan ran.
		if seen := firstTime(asset.LastSeenAt, asset.FirstSeenAt); seen != nil {
			f.LastSeenAt = seen
		}
		if f.Network != nil && f.Network.Port > 0 && f.Network.Transport != "" {
			b.service(assetID, f.Network.Port, f.Network.Transport, f.Network.AppProtocol)
			reached[fmt.Sprintf("%d/%s", f.Network.Port, f.Network.Transport)] = true
		}
		if kind := nessusInventoryKind(it); kind != "" {
			b.nessusInventory(it, kind, assetID, osName, packages, lineNo)
		}
		if err := b.finding(f); err != nil {
			return err
		}
	}
	b.nessusLocalServices(h.Tags, assetID, reached, lineNo)
	b.nessusHostCoverage(h, assetID, asset.FirstSeenAt, asset.LastSeenAt, credentialed)
	return nil
}

// nessusDetailCount tells a file exported without plugin details: plugin
// results that carry none of the members a full export writes.
type nessusDetailCount struct {
	plugin, detailed int
}

// nessusDetailMembers are the members only an export with plugin details
// writes on a plugin result.
var nessusDetailMembers = map[string]bool{
	"description": true, "synopsis": true, "solution": true, "risk_factor": true,
	"plugin_type": true, "plugin_publication_date": true, "cve": true, "cvss3_base_score": true, "cvss_base_score": true,
}

func (c *nessusDetailCount) note(it *nessusItem) {
	for _, f := range it.Fields {
		if strings.HasPrefix(f.XMLName.Local, "compliance") {
			return // a compliance result carries its own members
		}
	}
	c.plugin++
	for _, f := range it.Fields {
		if nessusDetailMembers[f.XMLName.Local] {
			c.detailed++
			return
		}
	}
}

// NessusNoDetailsMessage is the issue of a file whose plugin results carry
// no plugin details (an export without plugin attributes): no CVE, score or
// description can be imported from it.
const NessusNoDetailsMessage = "export lacks plugin details; re-export with full plugin attributes"

// nessusReport adds the file-level issues once every host is read. The
// issue is kept even when Issues is full: it replaces the last one.
func (b *Builder) nessusReport() {
	c := b.nessusDetails
	if c.plugin == 0 || c.detailed > 0 {
		return
	}
	is := Issue{Path: nsRoot, Message: fmt.Sprintf("%s (%d plugin results without description, solution or scores)", NessusNoDetailsMessage, c.plugin)}
	if n := len(b.res.Issues); n >= b.lim.MaxIssues && n > 0 {
		b.res.Issues[n-1] = is
		return
	}
	b.issue(is)
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

func (b *Builder) nessusFinding(it *nessusItem, assetID, assetValue string, credentialed *bool, lineNo int) (ctis.Finding, bool) {
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
			Scheme:         ctis.NativeSchemeNessus,
			VulnID:         line(pluginID, ctis.MaxNativeIDLen),
			Family:         line(it.PluginFamily, ctis.MaxNativeIDLen),
			Severity:       line(nativeSev, ctis.MaxNativeValueLen),
			IsCredentialed: credentialed,
			RawRef:         line(fmt.Sprintf("ReportHost[%s]/ReportItem[pluginID=%s,port=%s,protocol=%s]", assetValue, pluginID, it.Port, it.Protocol), ctis.MaxRawRefLen),
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
	rawTextEvidence(&f, "plugin_output", redactCredentials(first(v, "plugin_output")), "")

	// Every plugin result is observed on its host, so every finding carries
	// a network location: port 0 is a host-level result (Nessus reports it on
	// the pseudo-service "general"). A receiver then keys a host-level result
	// by (host, plugin) like any other network result, not by its title.
	port, _ := strconv.Atoi(strings.TrimSpace(it.Port))
	if port < 0 || port > 65535 {
		port = 0
	}
	svc := line(it.SvcName, capShort)
	if port == 0 && svc == "general" {
		svc = ""
	}
	f.Network = &ctis.NetworkLocation{Port: port, Transport: transportOf(it.Protocol), AppProtocol: ianaName(svc)}
	if f.Network.Port == 0 {
		// A host-level result: no transport either.
		f.Network.Transport = ""
	} else if f.Network.Transport == "" {
		// icmp and the like carry no port.
		f.Network.Port = 0
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
		}
		f.Kind = nessusComplianceResult(first(v, "compliance-result"))
		rawTextEvidence(&f, "compliance-actual-value", redactCredentials(first(v, "compliance-actual-value")), "")
		if sol := text(first(v, "compliance-solution"), capRemediation); sol != "" {
			f.Remediation = &ctis.Remediation{Recommendation: sol}
		}
		f.References = addWebRefs(f.References, splitLines(first(v, "compliance-see-also"))...)
		for _, k := range []string{"compliance-benchmark-name", "compliance-result", "compliance-policy-value", "compliance-audit-file", "compliance-benchmark-profile", "compliance-full-id", "compliance-functional-id", "compliance-informational-id", "compliance-reference", "compliance-check-id", "compliance-uname", "compliance-source"} {
			if k == "compliance-uname" {
				continue // the account the check ran as
			}
			extra(&f, k, first(v, k))
		}
		if m := nessusComplianceMappings(first(v, "compliance-reference")); m != "" {
			extra(&f, "compliance-mappings", m)
		}
		if e := line(redactCredentials(first(v, "compliance-error")), 4<<10); e != "" {
			// CTIS has no error member on a compliance result: the
			// message is the finding's message and kept in source_extra.
			extra(&f, "compliance-error", e)
			f.Message = e
		}
		if subs := nessusSubChecks(redactCredentials(first(v, "compliance-actual-value"))); len(subs) > 0 {
			nessusSetSubChecks(&f, subs)
		}
		// The description of a compliance result repeats the reference,
		// policy value and actual value that have their own members: only
		// the prose before them is kept as the description, the original
		// text in source_extra.
		if d, cut := nessusComplianceDescription(f.Description); cut {
			extra(&f, "compliance-description-original", redactCredentials(f.Description))
			f.Description = d
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
		vc := val
		addScore(&f, ctis.Score{System: ctis.ScoreSystemCVSS, Version: c.version, Vector: line(c.vector, ctis.MaxScoreVectorLen), Value: &vc, Source: "tenable"})
	}
	if val, ok := parseScore(first(v, "vpr_score"), 10); ok {
		vc := val
		addScore(&f, ctis.Score{System: ctis.ScoreSystemVendor, Value: &vc, Source: "tenable"})
	}
	if val, ok := parseScore(first(v, "epss_score"), 1); ok {
		vc := val
		addScore(&f, ctis.Score{System: ctis.ScoreSystemEPSS, Value: &vc, Source: "tenable"})
	}
	if truthy(first(v, "exploit_available")) {
		addSignal(vuln, ctis.ThreatSignalPublicExploit, "tenable", nil)
	}
	switch nessusMaturity(first(v, "exploit_code_maturity")) {
	case "weaponized":
		addSignal(vuln, ctis.ThreatSignalWeaponized, "tenable", nil)
	case "functional", "poc":
		addSignal(vuln, ctis.ThreatSignalPublicExploit, "tenable", nil)
	}
	if truthy(first(v, "exploited_by_malware")) {
		addSignal(vuln, ctis.ThreatSignalExploitedInWild, "tenable", nil)
	}
	kevDue, kev := "", false
	for _, k := range []string{"cisa-known-exploited", "cisa_known_exploited"} {
		if x := first(v, k); x != "" {
			kev = true
			if d := nessusDate(x); d != nil {
				kevDue = d.Format(time.DateOnly)
			}
		}
	}
	for _, x := range v["xref"] {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(x), "CISA-KNOWN-EXPLOITED:"); ok {
			kev = true
			if d := nessusDate(rest); d != nil && kevDue == "" {
				kevDue = d.Format(time.DateOnly)
			}
		}
	}
	if kev {
		addSignal(vuln, ctis.ThreatSignalKEV, "cisa", nil)
		for i := range vuln.ThreatSignals {
			if vuln.ThreatSignals[i].Type == ctis.ThreatSignalKEV {
				vuln.ThreatSignals[i].DueOn = kevDue
			}
		}
	}
	if cpe := firstLine(first(v, "cpe")); cpe != "" {
		vuln.CPE = line(cpe, capShort)
	}
	vuln.PublishedAt = nessusDate(first(v, "vuln_publication_date"))
	if len(vuln.IDs) > 0 || vuln.CPE != "" || len(vuln.ThreatSignals) > 0 || len(vuln.CWEIDs) > 0 || vuln.PublishedAt != nil {
		f.Vulnerability = vuln
	}

	if f.Type != ctis.FindingTypeCompliance {
		sol := text(first(v, "solution"), capRemediation)
		if strings.EqualFold(sol, "n/a") {
			sol = ""
		}
		patch := nessusDate(first(v, "patch_publication_date"))
		if sol != "" || patch != nil || f.Remediation != nil {
			rem := ensureRemediation(&f)
			rem.Recommendation = sol
			rem.PatchPublishedAt = patch
			if patch != nil {
				rem.IsFixAvailable = ctis.Bool(true)
			}
		}
		if truthy(first(v, "unsupported_by_vendor")) {
			ensureRemediation(&f).SolutionType = ctis.SolutionTypeUpgrade
		}
	}
	f.References = addWebRefs(f.References, splitLines(first(v, "see_also"))...)
	f.SourceRefs = []ctis.SourceRef{sourceRef("nessus", pluginID)}

	for _, k := range nessusExtra {
		if vals := v[k]; len(vals) > 0 {
			extra(&f, k, strings.Join(vals, "\n"))
		}
	}
	if xr := v["xref"]; len(xr) > 0 {
		extra(&f, "xref", strings.Join(xr, "\n"))
	}
	// A password or community string the plugin output echoed is masked
	// wherever else the item repeats it.
	ctis.RedactSecretFinding(&f, append(credentialValues(first(v, "plugin_output")), credentialValues(first(v, "compliance-actual-value"))...)...)
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

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// addAdvisory adds a vendor advisory to the finding's remediation.
func addAdvisory(f *ctis.Finding, id, source string) {
	id = line(id, ctis.MaxVulnerabilityIDLen)
	if id == "" {
		return
	}
	ensureRemediation(f)
	for _, a := range f.Remediation.Advisories {
		if a.ID == id && a.Source == source {
			return
		}
	}
	if len(f.Remediation.Advisories) >= ctis.MaxAdvisories {
		return
	}
	f.Remediation.Advisories = append(f.Remediation.Advisories, ctis.Advisory{ID: id, Source: line(source, ctis.MaxScoreSourceLen)})
}

func nessusComplianceResult(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "PASSED":
		return "pass"
	case "FAILED":
		return "fail"
	case "WARNING":
		return "review"
	case "ERROR", "SKIPPED":
		return "not_applicable"
	}
	return ""
}

// complianceFramework names the framework of a benchmark in the CTIS
// registry (pci_dss, hipaa, soc2, cis, nist_800_53, iso27001, gdpr, fedramp), or
// returns "" (the benchmark name is kept in source_extra).
func complianceFramework(benchmark string) ctis.ComplianceFramework {
	b := strings.ToLower(benchmark)
	switch {
	case strings.HasPrefix(b, "cis"):
		return ctis.FrameworkCIS
	case strings.Contains(b, "pci"):
		return ctis.FrameworkPCIDSS
	case strings.Contains(b, "hipaa"):
		return ctis.FrameworkHIPAA
	case strings.Contains(b, "800-53"):
		return ctis.FrameworkNIST80053
	case strings.Contains(b, "nist") && strings.Contains(b, "csf"):
		return ctis.FrameworkNISTCSF
	case strings.Contains(b, "nist"):
		return "nist"
	case strings.Contains(b, "iso 27001") || strings.Contains(b, "iso27001"):
		return ctis.FrameworkISO27001
	case strings.Contains(b, "fedramp"):
		return ctis.FrameworkFedRAMP
	case strings.Contains(b, "soc 2") || strings.Contains(b, "soc2"):
		return ctis.FrameworkSOC2
	case strings.Contains(b, "gdpr"):
		return ctis.FrameworkGDPR
	}
	return ""
}

// nessusConfidence reads the operating-system-conf tag (0 to 100).
func nessusConfidence(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 || n > 100 {
		return 0
	}
	return n
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
		return "none"
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
	// An account label inside a line ("missing; user: svc-scan"): the value
	// up to the next separator.
	reAccountInline = regexp.MustCompile(`(?i)(\b(?:user ?name|user|login|account)[ \t]*[:=][ \t]*)[^\s;,'"\[]+`)
)

const redacted = "[redacted]"

func redactCredentials(s string) string {
	if s == "" {
		return s
	}
	s = reAccountLine.ReplaceAllString(s, "${1}"+redacted)
	s = reSecretKV.ReplaceAllString(s, "${1}"+redacted)
	s = reAsAccount.ReplaceAllString(s, "${1}'"+redacted+"'")
	s = reAccountInline.ReplaceAllString(s, "${1}"+redacted)
	return s
}

// credentialValues returns the passwords, tokens and community strings that
// redactCredentials hides in s (not the account names), so the finding can
// mask them wherever else they appear.
func credentialValues(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, m := range reSecretKV.FindAllStringSubmatchIndex(s, -1) {
		out = append(out, strings.Trim(s[m[3]:m[1]], `'"`))
	}
	for _, m := range reAccountLine.FindAllStringSubmatchIndex(s, -1) {
		if label := strings.ToLower(s[m[2]:m[3]]); strings.Contains(label, "community") || strings.Contains(label, "credential") {
			out = append(out, strings.Trim(s[m[3]:m[1]], "'\" \t"))
		}
	}
	return out
}
