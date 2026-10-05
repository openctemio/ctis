package importer

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/openctemio/ctis"
)

// Qualys VM host list detection XML (HOST_LIST_VM_DETECTION_OUTPUT), joined
// on QID with the KnowledgeBase XML (KNOWLEDGE_BASE_VULN_LIST_OUTPUT) when
// one is given. The mapping is spec_qualys.go and spec_qualys_kb.go.
//
// The detection file is read first, one HOST at a time; the KnowledgeBase is
// then streamed and only the QIDs the detections name are decoded, so a full
// KnowledgeBase export does not have to fit in memory.

func init() {
	parsers[FormatQualys] = parseQualys
	tools[FormatQualys] = ctis.Tool{Name: "qualys", Vendor: "Qualys", Capabilities: []string{"va"}}
}

type qText struct {
	Value string `xml:",chardata"`
}

type qTag struct {
	ID   string `xml:"TAG_ID"`
	Name string `xml:"NAME"`
}

type qQDS struct {
	Severity string `xml:"severity,attr"`
	Value    string `xml:",chardata"`
}

type qQDSFactor struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

type qDetection struct {
	UniqueVulnID          string       `xml:"UNIQUE_VULN_ID"`
	QID                   string       `xml:"QID"`
	Type                  string       `xml:"TYPE"`
	Severity              string       `xml:"SEVERITY"`
	Port                  string       `xml:"PORT"`
	Protocol              string       `xml:"PROTOCOL"`
	FQDN                  string       `xml:"FQDN"`
	SSL                   string       `xml:"SSL"`
	Instance              string       `xml:"INSTANCE"`
	Results               string       `xml:"RESULTS"`
	Status                string       `xml:"STATUS"`
	FirstFound            string       `xml:"FIRST_FOUND_DATETIME"`
	LastFound             string       `xml:"LAST_FOUND_DATETIME"`
	TimesFound            string       `xml:"TIMES_FOUND"`
	LastTest              string       `xml:"LAST_TEST_DATETIME"`
	LastUpdate            string       `xml:"LAST_UPDATE_DATETIME"`
	LastFixed             string       `xml:"LAST_FIXED_DATETIME"`
	FirstReopened         string       `xml:"FIRST_REOPENED_DATETIME"`
	LastReopened          string       `xml:"LAST_REOPENED_DATETIME"`
	TimesReopened         string       `xml:"TIMES_REOPENED"`
	Service               string       `xml:"SERVICE"`
	IsIgnored             string       `xml:"IS_IGNORED"`
	IsDisabled            string       `xml:"IS_DISABLED"`
	AffectRunningKernel   string       `xml:"AFFECT_RUNNING_KERNEL"`
	AffectRunningService  string       `xml:"AFFECT_RUNNING_SERVICE"`
	AffectExploitableConf string       `xml:"AFFECT_EXPLOITABLE_CONFIG"`
	LastProcessed         string       `xml:"LAST_PROCESSED_DATETIME"`
	QDS                   *qQDS        `xml:"QDS"`
	QDSFactors            []qQDSFactor `xml:"QDS_FACTORS>QDS_FACTOR"`
}

type qHost struct {
	ID                 string       `xml:"ID"`
	AssetID            string       `xml:"ASSET_ID"`
	IP                 string       `xml:"IP"`
	IPv6               string       `xml:"IPV6"`
	TrackingMethod     string       `xml:"TRACKING_METHOD"`
	NetworkID          string       `xml:"NETWORK_ID"`
	OS                 string       `xml:"OS"`
	OSCPE              string       `xml:"OS_CPE"`
	DNS                string       `xml:"DNS"`
	DNSHostname        string       `xml:"DNS_DATA>HOSTNAME"`
	DNSDomain          string       `xml:"DNS_DATA>DOMAIN"`
	DNSFQDN            string       `xml:"DNS_DATA>FQDN"`
	CloudProvider      string       `xml:"CLOUD_PROVIDER"`
	CloudService       string       `xml:"CLOUD_SERVICE"`
	CloudResourceID    string       `xml:"CLOUD_RESOURCE_ID"`
	EC2InstanceID      string       `xml:"EC2_INSTANCE_ID"`
	NetBIOS            string       `xml:"NETBIOS"`
	QGHostID           string       `xml:"QG_HOSTID"`
	LastScan           string       `xml:"LAST_SCAN_DATETIME"`
	LastVMScanned      string       `xml:"LAST_VM_SCANNED_DATE"`
	LastVMAuthScanned  string       `xml:"LAST_VM_AUTH_SCANNED_DATE"`
	LastPCScanned      string       `xml:"LAST_PC_SCANNED_DATE"`
	AssetRiskScore     string       `xml:"ASSET_RISK_SCORE"`
	TruRiskScore       string       `xml:"TRURISK_SCORE"`
	AssetCriticality   string       `xml:"ASSET_CRITICALITY_SCORE"`
	Tags               []qTag       `xml:"TAGS>TAG"`
	Detections         []qDetection `xml:"DETECTION_LIST>DETECTION"`
	LastVMScanDuration string       `xml:"LAST_VM_SCANNED_DURATION"`
}

func parseQualys(b *builder, r io.Reader) error {
	xr := newXMLReader(r, FormatQualys, b.lim, map[string]string{"QDS_FACTOR": "name"}, b.obs)
	dec := xml.NewTokenDecoder(xr)
	sawRoot := false
	// Findings by QID, for the KnowledgeBase join.
	byQID := map[string][]int{}
	for {
		if err := b.tick(); err != nil {
			return err
		}
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return asParseError(err, FormatQualys)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "HOST_LIST_VM_DETECTION_OUTPUT":
			sawRoot = true
		case "DATETIME":
			var t qText
			if err := dec.DecodeElement(&t, &se); err != nil {
				return asParseError(err, FormatQualys)
			}
			if ts := parseTime(t.Value); ts != nil {
				if b.res.Report.Metadata.Properties == nil {
					b.res.Report.Metadata.Properties = ctis.Properties{}
				}
				b.res.Report.Metadata.Properties["generated_at"] = ts.Format("2006-01-02T15:04:05Z07:00")
			}
		case "WARNING":
			// Pagination notice (CODE, TEXT, URL of the next page).
			if err := dec.Skip(); err != nil {
				return asParseError(err, FormatQualys)
			}
			b.issue(Issue{Path: "/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/WARNING", Message: "the export is one page of a longer list; import the other pages too"})
		case "HOST":
			if !sawRoot {
				return &ParseError{Format: FormatQualys, Msg: "not a HOST_LIST_VM_DETECTION_OUTPUT document", Err: ErrMalformed}
			}
			lineNo, _ := xr.d.InputPos()
			var h qHost
			if err := dec.DecodeElement(&h, &se); err != nil {
				return asParseError(err, FormatQualys)
			}
			if err := b.qualysHost(&h, lineNo, byQID); err != nil {
				return err
			}
		default:
			if !sawRoot {
				return &ParseError{Format: FormatQualys, Msg: fmt.Sprintf("root element is <%s>, want <HOST_LIST_VM_DETECTION_OUTPUT>", se.Name.Local), Err: ErrMalformed}
			}
		}
	}
	if !sawRoot {
		return &ParseError{Format: FormatQualys, Msg: "no HOST_LIST_VM_DETECTION_OUTPUT element", Err: ErrMalformed}
	}
	if b.opts.QualysKnowledgeBase != nil {
		if err := b.qualysKnowledgeBase(b.opts.QualysKnowledgeBase, byQID); err != nil {
			return err
		}
	} else if len(byQID) > 0 {
		b.issue(Issue{Message: "no KnowledgeBase given: findings carry the QID but no title, description, CVEs or CVSS; export the KnowledgeBase for these QIDs and import it with the detections"})
	}
	return nil
}

func qualysTime(s string) string {
	if t := parseTime(s); t != nil {
		return t.Format("2006-01-02T15:04:05Z07:00")
	}
	return ""
}

func (b *builder) qualysHost(h *qHost, lineNo int, byQID map[string][]int) error {
	fqdn := strings.ToLower(strings.TrimSuffix(firstNonEmpty(h.DNSFQDN, h.DNS), "."))
	value := line(firstNonEmpty(fqdn, h.IP, h.IPv6, h.NetBIOS), capShort)
	if value == "" {
		b.issue(Issue{Line: lineNo, Path: "/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST", Message: fmt.Sprintf("host %s without DNS, IP or NetBIOS name: skipped", line(h.ID, 32))})
		b.res.Stats.Records += len(h.Detections)
		b.res.Stats.Skipped += len(h.Detections)
		return nil
	}
	asset := ctis.Asset{ID: "host-" + value, Type: ctis.AssetTypeHost, Value: value, Name: value}
	if net.ParseIP(value) != nil {
		asset.Type = ctis.AssetTypeIPAddress
	}
	ap := ctis.Properties{}
	set := func(k, v string) {
		if v = line(v, capShort); v != "" {
			ap[k] = v
		}
	}
	set("ip_address", h.IP)
	set("ipv6_address", h.IPv6)
	set("fqdn", fqdn)
	set("os", h.OS)
	set("qualys_host_id", h.ID)
	set("qualys_asset_id", h.AssetID)
	set("tracking_method", h.TrackingMethod)
	set("network_id", h.NetworkID)
	set("cloud_provider", h.CloudProvider)
	set("cloud_service", h.CloudService)
	set("last_scan_at", qualysTime(h.LastScan))
	set("last_vm_scanned_at", qualysTime(h.LastVMScanned))
	set("last_vm_scan_duration_s", h.LastVMScanDuration)
	set("last_vm_auth_scanned_at", qualysTime(h.LastVMAuthScanned))
	set("last_pc_scanned_at", qualysTime(h.LastPCScanned))
	set("qualys_asset_risk_score", h.AssetRiskScore)
	set("qualys_trurisk_score", h.TruRiskScore)
	set("qualys_asset_criticality_score", h.AssetCriticality)
	set("dns_hostname", h.DNSHostname)
	set("dns_domain", h.DNSDomain)
	if len(ap) > 0 {
		asset.Properties = ap
	}
	for _, t := range h.Tags {
		asset.Tags = addTags(asset.Tags, t.Name)
	}
	hints := &ctis.IdentityHints{
		FQDN:            line(fqdn, ctis.MaxIdentityHintLen),
		NetBIOSName:     line(h.NetBIOS, ctis.MaxIdentityHintLen),
		OSCPE:           line(h.OSCPE, ctis.MaxIdentityHintLen),
		CloudResourceID: line(firstNonEmpty(h.CloudResourceID, h.EC2InstanceID), ctis.MaxIdentityHintLen),
		ScannerAgentID:  line(h.QGHostID, ctis.MaxIdentityHintLen),
	}
	if hints.FQDN != "" || hints.NetBIOSName != "" || hints.OSCPE != "" || hints.CloudResourceID != "" || hints.ScannerAgentID != "" {
		asset.IdentityHints = hints
	}
	assetID, err := b.asset(asset)
	if err != nil {
		return err
	}
	for i := range h.Detections {
		b.res.Stats.Records++
		if err := b.tick(); err != nil {
			return err
		}
		d := &h.Detections[i]
		f, ok := b.qualysFinding(d, assetID, value, lineNo)
		if !ok {
			b.res.Stats.Skipped++
			continue
		}
		n := len(b.res.Report.Findings)
		if err := b.finding(f); err != nil {
			return err
		}
		if len(b.res.Report.Findings) > n {
			byQID[f.Native.VulnID] = append(byQID[f.Native.VulnID], n)
		}
	}
	return nil
}

func (b *builder) qualysFinding(d *qDetection, assetID, assetValue string, lineNo int) (ctis.Finding, bool) {
	const p = "/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION"
	qid := strings.TrimSpace(d.QID)
	if _, err := strconv.ParseUint(qid, 10, 32); err != nil {
		b.issue(Issue{Line: lineNo, Path: p, Message: fmt.Sprintf("detection on %s with QID %q: skipped", assetValue, line(qid, 32))})
		return ctis.Finding{}, false
	}
	nativeSev := strings.TrimSpace(d.Severity)
	sev, ok := ctis.NormalizeNativeSeverity(ctis.NativeSchemeQualys, nativeSev)
	if !ok {
		b.issue(Issue{Line: lineNo, Path: p, Message: fmt.Sprintf("QID %s on %s: unknown severity %q, kept as medium", qid, assetValue, line(nativeSev, 16))})
		sev = ctis.SeverityMedium
	}
	f := ctis.Finding{
		Type:     ctis.FindingTypeVulnerability,
		Title:    "Qualys QID " + qid,
		Severity: sev,
		RuleID:   qid,
		AssetRef: assetID,
		Native: &ctis.NativeIdentity{
			Scheme:     ctis.NativeSchemeQualys,
			VulnID:     qid,
			InstanceID: line(d.UniqueVulnID, ctis.MaxNativeIDLen),
			Severity:   line(nativeSev, ctis.MaxNativeValueLen),
			Status:     line(d.Status, ctis.MaxNativeValueLen),
			RawRef:     line(fmt.Sprintf("HOST[%s]/DETECTION[QID=%s,port=%s,protocol=%s]", assetValue, qid, d.Port, d.Protocol), ctis.MaxRawRefLen),
		},
	}
	if dt, ok := ctis.NormalizeDetectionType(d.Type); ok {
		f.Native.DetectionType = dt
		if dt == ctis.DetectionTypePotential {
			f.Confidence = 50
		}
	}
	if status, state, ok := ctis.NormalizeNativeStatus(ctis.NativeSchemeQualys, d.Status); ok {
		f.Status = status
		lc := &ctis.SourceLifecycle{
			FirstFound: parseTime(d.FirstFound),
			LastFound:  parseTime(d.LastFound),
			LastFixed:  parseTime(d.LastFixed),
			State:      state,
		}
		if n, err := strconv.Atoi(strings.TrimSpace(d.TimesFound)); err == nil && n > 0 && n <= ctis.MaxTimesFound {
			lc.TimesFound = n
		}
		f.SourceLifecycle = lc
	} else {
		f.SourceLifecycle = &ctis.SourceLifecycle{FirstFound: parseTime(d.FirstFound), LastFound: parseTime(d.LastFound), LastFixed: parseTime(d.LastFixed)}
		if n, err := strconv.Atoi(strings.TrimSpace(d.TimesFound)); err == nil && n > 0 && n <= ctis.MaxTimesFound {
			f.SourceLifecycle.TimesFound = n
		}
	}
	f.FirstSeenAt = f.SourceLifecycle.FirstFound
	f.LastSeenAt = f.SourceLifecycle.LastFound

	host := assetValue
	if fq := line(d.FQDN, capShort); fq != "" {
		host = strings.ToLower(fq)
	}
	port, _ := strconv.Atoi(strings.TrimSpace(d.Port))
	if port > 0 && port <= 65535 {
		f.Network = &ctis.NetworkLocation{Host: host, Port: port, Protocol: strings.ToLower(line(d.Protocol, 16)), Service: line(d.Service, capShort)}
	}
	if out := redactCredentials(d.Results); strings.TrimSpace(out) != "" {
		f.Evidence = text(out, capEvidence)
	}
	if d.QDS != nil {
		if v, err := strconv.ParseFloat(strings.TrimSpace(d.QDS.Value), 64); err == nil && v >= 0 && v <= 100 {
			vc := v
			addScore(&f, ctis.Score{System: ctis.ScoreSystemVendor, Value: &vc, Label: line(strings.ToLower(d.QDS.Severity), ctis.MaxScoreLabelLen), Source: "qualys"})
		}
	}
	if len(d.QDSFactors) > 0 {
		var parts []string
		for _, q := range d.QDSFactors {
			parts = append(parts, line(q.Name, 64)+"="+line(q.Value, 512))
		}
		extra(&f, "qds_factors", strings.Join(parts, "\n"))
	}
	extras(&f,
		"type", d.Type, "ssl", d.SSL, "instance", d.Instance, "last_test_datetime", d.LastTest,
		"last_update_datetime", d.LastUpdate, "first_reopened_datetime", d.FirstReopened,
		"last_reopened_datetime", d.LastReopened, "times_reopened", d.TimesReopened,
		"is_ignored", d.IsIgnored, "is_disabled", d.IsDisabled,
		"affect_running_kernel", d.AffectRunningKernel, "affect_running_service", d.AffectRunningService,
		"affect_exploitable_config", d.AffectExploitableConf, "last_processed_datetime", d.LastProcessed,
	)
	return f, true
}

// The KnowledgeBase.

type qIDURL struct {
	ID  string `xml:"ID"`
	URL string `xml:"URL"`
}

type qCVSS struct {
	Base     qScore `xml:"BASE"`
	Temporal string `xml:"TEMPORAL"`
	Vector   string `xml:"VECTOR_STRING"`
	Version  string `xml:"CVSS3_VERSION"`
}

type qScore struct {
	Source string `xml:"source,attr"`
	Value  string `xml:",chardata"`
}

type qThreat struct {
	ID    string `xml:"id,attr"`
	Value string `xml:",chardata"`
}

type qExploit struct {
	Ref  string `xml:"REF"`
	Desc string `xml:"DESC"`
	Link string `xml:"LINK"`
}

type qExploitSource struct {
	Name     string     `xml:"SRC_NAME"`
	Exploits []qExploit `xml:"EXPLT_LIST>EXPLT"`
}

type qMalware struct {
	ID       string `xml:"MW_ID"`
	Type     string `xml:"MW_TYPE"`
	Platform string `xml:"MW_PLATFORM"`
	Alias    string `xml:"MW_ALIAS"`
	Rating   string `xml:"MW_RATING"`
	Link     string `xml:"MW_LINK"`
}

type qMalwareSource struct {
	Name    string     `xml:"SRC_NAME"`
	Malware []qMalware `xml:"MW_LIST>MW_INFO"`
}

type qSoftware struct {
	Product string `xml:"PRODUCT"`
	Vendor  string `xml:"VENDOR"`
}

type qCompliance struct {
	Type        string `xml:"TYPE"`
	Section     string `xml:"SECTION"`
	Description string `xml:"DESCRIPTION"`
}

type qVuln struct {
	QID                 string           `xml:"QID"`
	VulnType            string           `xml:"VULN_TYPE"`
	Title               string           `xml:"TITLE"`
	Category            string           `xml:"CATEGORY"`
	Technology          string           `xml:"TECHNOLOGY"`
	DetectionInfo       string           `xml:"DETECTION_INFO"`
	Published           string           `xml:"PUBLISHED_DATETIME"`
	ServiceModified     string           `xml:"LAST_SERVICE_MODIFICATION_DATETIME"`
	CodeModified        string           `xml:"CODE_MODIFIED_DATETIME"`
	Bugtraq             []qIDURL         `xml:"BUGTRAQ_LIST>BUGTRAQ"`
	Patchable           string           `xml:"PATCHABLE"`
	PatchPublished      string           `xml:"PATCH_PUBLISHED_DATE"`
	Software            []qSoftware      `xml:"SOFTWARE_LIST>SOFTWARE"`
	VendorRefs          []qIDURL         `xml:"VENDOR_REFERENCE_LIST>VENDOR_REFERENCE"`
	CVEs                []qIDURL         `xml:"CVE_LIST>CVE"`
	Diagnosis           string           `xml:"DIAGNOSIS"`
	DiagnosisComment    string           `xml:"DIAGNOSIS_COMMENT"`
	Consequence         string           `xml:"CONSEQUENCE"`
	ConsequenceComment  string           `xml:"CONSEQUENCE_COMMENT"`
	Solution            string           `xml:"SOLUTION"`
	SolutionComment     string           `xml:"SOLUTION_COMMENT"`
	Compliance          []qCompliance    `xml:"COMPLIANCE_LIST>COMPLIANCE"`
	ExploitSources      []qExploitSource `xml:"CORRELATION>EXPLOITS>EXPLT_SRC"`
	MalwareSources      []qMalwareSource `xml:"CORRELATION>MALWARE>MW_SRC"`
	CVSS                *qCVSS           `xml:"CVSS"`
	CVSSv3              *qCVSS           `xml:"CVSS_V3"`
	PCIFlag             string           `xml:"PCI_FLAG"`
	PCIReasons          []string         `xml:"PCI_REASONS>PCI_REASON"`
	ThreatIntel         []qThreat        `xml:"THREAT_INTELLIGENCE>THREAT_INTEL"`
	DiscoveryRemote     string           `xml:"DISCOVERY>REMOTE"`
	DiscoveryAuthTypes  []string         `xml:"DISCOVERY>AUTH_TYPE_LIST>AUTH_TYPE"`
	DiscoveryAdditional string           `xml:"DISCOVERY>ADDITIONAL_INFO"`
}

// qualysKnowledgeBase streams the KnowledgeBase and enriches the findings of
// every QID the detections named.
func (b *builder) qualysKnowledgeBase(r io.Reader, byQID map[string][]int) error {
	xr := newXMLReader(r, FormatQualysKB, b.lim, map[string]string{"THREAT_INTEL": "id"}, b.obs)
	dec := xml.NewTokenDecoder(xr)
	sawRoot := false
	seen := map[string]bool{}
	for {
		if err := b.tick(); err != nil {
			return err
		}
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return asParseError(err, FormatQualysKB)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "KNOWLEDGE_BASE_VULN_LIST_OUTPUT":
			sawRoot = true
		case "VULN":
			if !sawRoot {
				return &ParseError{Format: FormatQualysKB, Msg: "the KnowledgeBase is not a KNOWLEDGE_BASE_VULN_LIST_OUTPUT document", Err: ErrMalformed}
			}
			var v qVuln
			if err := dec.DecodeElement(&v, &se); err != nil {
				return asParseError(err, FormatQualysKB)
			}
			qid := strings.TrimSpace(v.QID)
			idx, ok := byQID[qid]
			if !ok {
				continue
			}
			seen[qid] = true
			for _, i := range idx {
				b.qualysEnrich(&b.res.Report.Findings[i], &v)
			}
		default:
			if !sawRoot {
				return &ParseError{Format: FormatQualysKB, Msg: fmt.Sprintf("the KnowledgeBase root element is <%s>, want <KNOWLEDGE_BASE_VULN_LIST_OUTPUT>", se.Name.Local), Err: ErrMalformed}
			}
		}
	}
	if !sawRoot {
		return &ParseError{Format: FormatQualysKB, Msg: "no KNOWLEDGE_BASE_VULN_LIST_OUTPUT element", Err: ErrMalformed}
	}
	var missing []string
	for qid := range byQID {
		if !seen[qid] {
			missing = append(missing, qid)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		if len(missing) > 20 {
			missing = append(missing[:20], "...")
		}
		b.issue(Issue{Message: "the KnowledgeBase has no entry for QID " + strings.Join(missing, ", ") + "; those findings keep only the detection data"})
	}
	return nil
}

// qualysThreatExploit are THREAT_INTELLIGENCE values that mean exploit code
// exists.
var qualysThreatExploit = map[string]bool{
	"exploit_public": true, "easy_exploit": true, "active_attacks": true, "malware": true,
	"exploit_kit": true, "wormable": true, "predicted_high_risk": false, "cisa_known_exploited_vulns": true,
	"ransomware": true,
}

func (b *builder) qualysEnrich(f *ctis.Finding, v *qVuln) {
	if t := line(v.Title, capTitle); t != "" {
		f.Title = t
		f.RuleName = t
	}
	if c := line(v.Category, capCategory); c != "" {
		f.Category = c
		f.Native.Family = line(v.Category, ctis.MaxNativeIDLen)
	}
	if f.Native.DetectionType == "" {
		if dt, ok := ctis.NormalizeDetectionType(qualysVulnType(v.VulnType)); ok {
			f.Native.DetectionType = dt
		}
	}
	f.Description = text(qualysHTML(v.Diagnosis), capDescription)
	extra(f, "consequence", qualysHTML(v.Consequence))
	vuln := f.Vulnerability
	if vuln == nil {
		vuln = &ctis.VulnerabilityDetails{}
	}
	for _, c := range v.CVEs {
		addVulnID(vuln, c.ID)
		f.References = addRefs(f.References, c.URL)
	}
	for _, bt := range v.Bugtraq {
		addVendorID(vuln, prefixed("BID", bt.ID), "bid")
		f.References = addRefs(f.References, bt.URL)
	}
	for _, vr := range v.VendorRefs {
		addAdvisory(f, vr.ID, "vendor")
		if n := len(f.Remediation.Advisories); n > 0 && f.Remediation.Advisories[n-1].ID == line(vr.ID, ctis.MaxNativeIDLen) && validURL(vr.URL) {
			f.Remediation.Advisories[n-1].URL = line(vr.URL, ctis.MaxAdvisoryURLLen)
		}
	}
	vuln.PublishedAt = parseTime(v.Published)
	vuln.ModifiedAt = parseTime(v.ServiceModified)
	type cv struct {
		c       *qCVSS
		version string
	}
	for _, c := range []cv{{v.CVSSv3, "3.1"}, {v.CVSS, "2.0"}} {
		if c.c == nil {
			continue
		}
		val, ok := parseScore(c.c.Base.Value, 10)
		if !ok {
			continue
		}
		vec := strings.TrimSpace(c.c.Vector)
		ver := ctis.CVSSVersionOfVector(vec)
		if ver == "" {
			ver = c.version
			if c.version == "3.1" && strings.TrimSpace(c.c.Version) != "" {
				ver = strings.TrimSpace(c.c.Version)
			}
		}
		if ver == "2.0" {
			vec = cvss2Base(strings.TrimPrefix(vec, "CVSS:2.0/"))
		}
		if vuln.CVSSVersion == "" {
			vuln.CVSSScore, vuln.CVSSVersion, vuln.CVSSVector, vuln.CVSSSource = val, ver, line(vec, ctis.MaxScoreVectorLen), "vendor"
		}
		vc := val
		addScore(f, ctis.Score{System: ctis.ScoreSystemCVSS, Version: ver, Vector: line(vec, ctis.MaxScoreVectorLen), Value: &vc, Source: firstNonEmpty(strings.ToLower(c.c.Base.Source), "qualys")})
		if tmp := strings.TrimSpace(c.c.Temporal); tmp != "" {
			extra(f, "cvss"+strings.Split(ver, ".")[0]+"_temporal", tmp)
		}
	}
	for _, ti := range v.ThreatIntel {
		name := strings.ToLower(strings.TrimSpace(ti.Value))
		f.Tags = addTags(f.Tags, name)
		if qualysThreatExploit[name] {
			vuln.ExploitAvailable = true
		}
		if name == "cisa_known_exploited_vulns" {
			vuln.InCISAKEV = true
		}
	}
	var exploits []string
	for _, src := range v.ExploitSources {
		for _, e := range src.Exploits {
			vuln.ExploitAvailable = true
			exploits = append(exploits, line(src.Name, 64)+": "+line(firstNonEmpty(e.Ref, e.Desc), 256))
			if validURL(e.Link) {
				f.References = addRefs(f.References, e.Link)
			}
		}
	}
	if len(exploits) > 0 {
		extra(f, "exploits", strings.Join(exploits, "\n"))
	}
	var malware []string
	for _, src := range v.MalwareSources {
		for _, m := range src.Malware {
			malware = append(malware, line(src.Name, 64)+": "+line(m.ID, 128)+" ("+line(m.Type, 64)+", "+line(m.Rating, 32)+")")
		}
	}
	if len(malware) > 0 {
		extra(f, "malware", strings.Join(malware, "\n"))
	}
	if vuln.CVEID != "" || len(vuln.IDs) > 0 || vuln.CVSSScore > 0 || vuln.PublishedAt != nil || vuln.ExploitAvailable {
		f.Vulnerability = vuln
	}

	sol := text(qualysHTML(v.Solution), capRemediation)
	patch := parseTime(v.PatchPublished)
	if sol != "" || patch != nil || truthy(v.Patchable) || f.Remediation != nil {
		if f.Remediation == nil {
			f.Remediation = &ctis.Remediation{}
		}
		f.Remediation.Recommendation = sol
		f.Remediation.PatchPublishedAt = patch
		if truthy(v.Patchable) {
			f.Remediation.FixAvailable = true
			f.Remediation.SolutionType = ctis.SolutionTypePatch
		}
	}
	if truthy(v.PCIFlag) {
		f.Tags = addTags(f.Tags, "pci")
	}
	var sw []string
	for _, s := range v.Software {
		sw = append(sw, line(s.Vendor, 128)+" "+line(s.Product, 128))
	}
	var comp []string
	for _, c := range v.Compliance {
		comp = append(comp, line(c.Type, 64)+" "+line(c.Section, 128)+": "+line(c.Description, 512))
	}
	extras(f,
		"vuln_type", v.VulnType, "technology", v.Technology, "detection_info", qualysHTML(v.DetectionInfo),
		"code_modified_datetime", v.CodeModified, "diagnosis_comment", qualysHTML(v.DiagnosisComment),
		"consequence_comment", qualysHTML(v.ConsequenceComment), "solution_comment", qualysHTML(v.SolutionComment),
		"pci_flag", v.PCIFlag, "pci_reasons", strings.Join(v.PCIReasons, "\n"), "affected_software", strings.Join(sw, "\n"),
		"compliance", strings.Join(comp, "\n"), "discovery_remote", v.DiscoveryRemote,
		"discovery_auth_types", strings.Join(v.DiscoveryAuthTypes, ", "), "discovery_additional_info", v.DiscoveryAdditional,
		"patchable", v.Patchable,
	)
}

// cvss2Base keeps the six base metrics of a CVSS v2 vector; the KnowledgeBase
// appends the temporal ones, which the temporal score already carries.
func cvss2Base(vec string) string {
	var keep []string
	for _, part := range strings.Split(vec, "/") {
		k, _, _ := strings.Cut(part, ":")
		switch k {
		case "AV", "AC", "Au", "C", "I", "A":
			keep = append(keep, part)
		}
	}
	return strings.Join(keep, "/")
}

// qualysVulnType maps the KnowledgeBase VULN_TYPE words to the detection
// type words.
func qualysVulnType(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "vulnerability":
		return "confirmed"
	case "potential vulnerability", "vulnerability or potential vulnerability":
		return "potential"
	case "information gathered":
		return "info"
	}
	return ""
}

// qualysHTML turns the light HTML of KnowledgeBase texts into plain text:
// line breaks and paragraphs become newlines, every other tag is dropped.
// The result is text, never markup; a receiver renders it escaped.
func qualysHTML(s string) string {
	if !strings.Contains(s, "<") {
		return s
	}
	var out strings.Builder
	for len(s) > 0 {
		i := strings.IndexByte(s, '<')
		if i < 0 {
			out.WriteString(s)
			break
		}
		out.WriteString(s[:i])
		j := strings.IndexByte(s[i:], '>')
		if j < 0 {
			out.WriteString(s[i:])
			break
		}
		tag := strings.ToLower(strings.Trim(s[i+1:i+j], "/ "))
		if f := strings.Fields(tag); len(f) > 0 {
			tag = f[0]
		}
		switch tag {
		case "br", "p", "li", "div", "tr":
			out.WriteByte('\n')
		}
		s = s[i+j+1:]
	}
	return out.String()
}

func validURL(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://")
}
