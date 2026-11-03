package ctis

import (
	"path"
	"strings"
	"time"
)

// CTIS to OCSF 1.3.0 findings.
//
// Every finding becomes one event of the Findings category (category_uid 2):
//   - vulnerability, secret and web3 findings: Vulnerability Finding
//     (class_uid 2002);
//   - compliance and misconfiguration findings: Compliance Finding
//     (class_uid 2003).
//
// Mapping:
//   - fingerprint (else the finding id) -> finding_info.uid; title, description
//     -> finding_info.title, desc; rule_id, rule_name ->
//     finding_info.analytic (type Rule); first/last_seen_at ->
//     finding_info.first/last_seen_time (epoch milliseconds).
//   - severity -> severity_id and severity; status -> status_id and status
//     (false_positive and accepted_risk are status_id 99 with their name);
//     resolved -> activity_id 3 (Close), else 1 (Create).
//   - the finding's asset -> resources[0] (uid = asset id, name = value,
//     type = asset type).
//   - cve_ids / ids -> vulnerabilities[].cve.uid (one vulnerability object
//     per CVE, the first carrying everything else); cwe_ids ->
//     vulnerabilities[].cwe.uid; CVSS scores -> cve.cvss[]; EPSS ->
//     cve.epss; package, version, purl, fixed version ->
//     affected_packages[]; location -> affected_code[]; references ->
//     references; remediation.recommendation -> remediation.desc;
//     exploit_available -> is_exploit_available.
//   - compliance: framework -> compliance.standards, control_id -> control,
//     result -> status_id (pass 1, fail 3, else 99 with the result);
//     misconfiguration: policy_id -> control, provider -> standards.
//   - time: last_seen_at, else first_seen_at, else OCSFOptions.Time, else
//     report.metadata.timestamp.
//   - the CTIS finding type -> unmapped["ctis_type"]; the compliance
//     framework version -> unmapped["compliance_framework_version"]; a
//     secret's type, service and masked value -> unmapped (masked, never
//     the raw match).

// OCSFVersion is the OCSF schema version ToOCSF writes.
const OCSFVersion = "1.3.0"

// OCSF class, category and activity ids used by ToOCSF.
const (
	OCSFCategoryFindings          = 2
	OCSFClassVulnerabilityFinding = 2002
	OCSFClassComplianceFinding    = 2003
	OCSFActivityCreate            = 1
	OCSFActivityClose             = 3
)

// OCSFOptions configure ToOCSF. The zero value is valid.
type OCSFOptions struct {
	// Time of an event whose finding has no seen time. Zero:
	// report.metadata.timestamp.
	Time time.Time
}

// OCSFEvent is one OCSF Vulnerability Finding or Compliance Finding event.
type OCSFEvent struct {
	ActivityID      int                 `json:"activity_id"`
	ActivityName    string              `json:"activity_name"`
	CategoryUID     int                 `json:"category_uid"`
	CategoryName    string              `json:"category_name"`
	ClassUID        int                 `json:"class_uid"`
	ClassName       string              `json:"class_name"`
	TypeUID         int                 `json:"type_uid"`
	TypeName        string              `json:"type_name"`
	SeverityID      int                 `json:"severity_id"`
	Severity        string              `json:"severity"`
	StatusID        int                 `json:"status_id,omitempty"`
	Status          string              `json:"status,omitempty"`
	Time            int64               `json:"time"`
	ConfidenceScore int                 `json:"confidence_score,omitempty"`
	Message         string              `json:"message,omitempty"`
	Metadata        OCSFMetadata        `json:"metadata"`
	FindingInfo     OCSFFindingInfo     `json:"finding_info"`
	Vulnerabilities []OCSFVulnerability `json:"vulnerabilities,omitempty"`
	Compliance      *OCSFCompliance     `json:"compliance,omitempty"`
	Remediation     *OCSFRemediation    `json:"remediation,omitempty"`
	Resources       []OCSFResource      `json:"resources,omitempty"`
	Unmapped        map[string]string   `json:"unmapped,omitempty"`
}

// OCSFMetadata is the event's metadata object.
type OCSFMetadata struct {
	Version string      `json:"version"`
	Product OCSFProduct `json:"product"`
}

// OCSFProduct is the product that reported the finding.
type OCSFProduct struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name,omitempty"`
	Version    string `json:"version,omitempty"`
	URL        string `json:"url_string,omitempty"`
}

// OCSFFindingInfo is the finding_info object.
type OCSFFindingInfo struct {
	UID           string        `json:"uid"`
	Title         string        `json:"title"`
	Desc          string        `json:"desc,omitempty"`
	Types         []string      `json:"types,omitempty"`
	FirstSeenTime int64         `json:"first_seen_time,omitempty"`
	LastSeenTime  int64         `json:"last_seen_time,omitempty"`
	Analytic      *OCSFAnalytic `json:"analytic,omitempty"`
}

// OCSFAnalytic is the rule that produced the finding.
type OCSFAnalytic struct {
	UID    string `json:"uid,omitempty"`
	Name   string `json:"name,omitempty"`
	TypeID int    `json:"type_id"`
	Type   string `json:"type"`
}

// OCSFVulnerability is one entry of vulnerabilities[].
type OCSFVulnerability struct {
	Title              string             `json:"title,omitempty"`
	Desc               string             `json:"desc,omitempty"`
	Severity           string             `json:"severity,omitempty"`
	CVE                *OCSFCVE           `json:"cve,omitempty"`
	CWE                *OCSFCWE           `json:"cwe,omitempty"`
	AffectedPackages   []OCSFPackage      `json:"affected_packages,omitempty"`
	AffectedCode       []OCSFAffectedCode `json:"affected_code,omitempty"`
	References         []string           `json:"references,omitempty"`
	IsExploitAvailable bool               `json:"is_exploit_available,omitempty"`
	Remediation        *OCSFRemediation   `json:"remediation,omitempty"`
}

// OCSFCVE is a CVE with its scores.
type OCSFCVE struct {
	UID  string     `json:"uid"`
	CVSS []OCSFCVSS `json:"cvss,omitempty"`
	EPSS *OCSFEPSS  `json:"epss,omitempty"`
}

// OCSFCVSS is one CVSS score.
type OCSFCVSS struct {
	Version      string   `json:"version"`
	BaseScore    *float64 `json:"base_score,omitempty"`
	VectorString string   `json:"vector_string,omitempty"`
}

// OCSFEPSS is an EPSS score.
type OCSFEPSS struct {
	Score      string   `json:"score"`
	Percentile *float64 `json:"percentile,omitempty"`
}

// OCSFCWE is a CWE.
type OCSFCWE struct {
	UID string `json:"uid"`
}

// OCSFPackage is an affected package.
type OCSFPackage struct {
	Name           string `json:"name"`
	Version        string `json:"version,omitempty"`
	PURL           string `json:"purl,omitempty"`
	FixedInVersion string `json:"fixed_in_version,omitempty"`
}

// OCSFAffectedCode is a code location of the finding.
type OCSFAffectedCode struct {
	File      OCSFFile `json:"file"`
	StartLine int      `json:"start_line,omitempty"`
	EndLine   int      `json:"end_line,omitempty"`
}

// OCSFFile is a file.
type OCSFFile struct {
	Name string `json:"name"`
	Path string `json:"path,omitempty"`
}

// OCSFRemediation is how to fix the finding.
type OCSFRemediation struct {
	Desc       string   `json:"desc"`
	References []string `json:"references,omitempty"`
}

// OCSFCompliance is the compliance object of a Compliance Finding.
type OCSFCompliance struct {
	Standards []string `json:"standards"`
	Control   string   `json:"control,omitempty"`
	StatusID  int      `json:"status_id,omitempty"`
	Status    string   `json:"status,omitempty"`
}

// OCSFResource is an affected resource.
type OCSFResource struct {
	UID  string `json:"uid,omitempty"`
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}

// ToOCSF converts the findings of a report to OCSF 1.3.0 events, one per
// finding, in report order. See the mapping above and docs/exporters.md.
func ToOCSF(r *Report, opts *OCSFOptions) ([]OCSFEvent, error) {
	if r == nil {
		return nil, errNilReport
	}
	if opts == nil {
		opts = &OCSFOptions{}
	}
	product := OCSFProduct{Name: sarifDefaultDriver}
	if t := r.Tool; t != nil {
		if t.Name != "" {
			product.Name = t.Name
		}
		product.VendorName, product.Version, product.URL = t.Vendor, t.Version, t.InfoURL
	}
	fallback := opts.Time
	if fallback.IsZero() {
		fallback = r.Metadata.Timestamp
	}
	events := make([]OCSFEvent, 0, len(r.Findings))
	size := 0
	for i := range r.Findings {
		f, err := exportFinding(&r.Findings[i])
		if err != nil {
			return nil, err
		}
		ev := ocsfEventOf(r, &f, product, fallback)
		size += ocsfSizeHint(&ev)
		if size > MaxExportBytes {
			return nil, ErrExportTooLarge
		}
		events = append(events, ev)
	}
	return events, nil
}

// ocsfSizeHint approximates an event's encoded size from its free text.
func ocsfSizeHint(ev *OCSFEvent) int {
	n := 512 + len(ev.FindingInfo.Title) + len(ev.FindingInfo.Desc) + len(ev.Message)
	for _, v := range ev.Vulnerabilities {
		n += 128 + len(v.Title) + len(v.Desc)
		for _, r := range v.References {
			n += len(r)
		}
	}
	for k, v := range ev.Unmapped {
		n += len(k) + len(v)
	}
	return n
}

// ocsfSeverity maps a severity to severity_id and its caption.
func ocsfSeverity(s Severity) (int, string) {
	switch s {
	case SeverityCritical:
		return 5, "Critical"
	case SeverityHigh:
		return 4, "High"
	case SeverityMedium:
		return 3, "Medium"
	case SeverityLow:
		return 2, "Low"
	case SeverityInfo:
		return 1, "Informational"
	}
	return 0, "Unknown"
}

// ocsfStatus maps a status to status_id and its caption.
func ocsfStatus(s FindingStatus) (int, string) {
	switch s {
	case FindingStatusOpen:
		return 1, "New"
	case FindingStatusInProgress:
		return 2, "In Progress"
	case FindingStatusSuppressed:
		return 3, "Suppressed"
	case FindingStatusResolved:
		return 4, "Resolved"
	case FindingStatusFalsePositive:
		return 99, "False Positive"
	case FindingStatusAcceptedRisk:
		return 99, "Accepted Risk"
	}
	return 0, ""
}

func epochMillis(t *time.Time) int64 {
	if t == nil || t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func ocsfEventOf(r *Report, f *Finding, product OCSFProduct, fallback time.Time) OCSFEvent {
	class, className := OCSFClassVulnerabilityFinding, "Vulnerability Finding"
	if f.Type == FindingTypeCompliance || f.Type == FindingTypeMisconfiguration {
		class, className = OCSFClassComplianceFinding, "Compliance Finding"
	}
	activity, activityName := OCSFActivityCreate, "Create"
	if f.Status == FindingStatusResolved {
		activity, activityName = OCSFActivityClose, "Close"
	}
	ev := OCSFEvent{
		ActivityID:      activity,
		ActivityName:    activityName,
		CategoryUID:     OCSFCategoryFindings,
		CategoryName:    "Findings",
		ClassUID:        class,
		ClassName:       className,
		TypeUID:         class*100 + activity,
		TypeName:        className + ": " + activityName,
		ConfidenceScore: f.Confidence,
		Message:         f.Message,
		Metadata:        OCSFMetadata{Version: OCSFVersion, Product: product},
	}
	ev.SeverityID, ev.Severity = ocsfSeverity(f.Severity)
	ev.StatusID, ev.Status = ocsfStatus(f.Status)
	switch {
	case f.LastSeenAt != nil && !f.LastSeenAt.IsZero():
		ev.Time = f.LastSeenAt.UnixMilli()
	case f.FirstSeenAt != nil && !f.FirstSeenAt.IsZero():
		ev.Time = f.FirstSeenAt.UnixMilli()
	case !fallback.IsZero():
		ev.Time = fallback.UnixMilli()
	}

	uid := f.Fingerprint
	if uid == "" {
		uid = f.ID
	}
	title := f.Title
	if title == "" {
		title = f.RuleID
	}
	ev.FindingInfo = OCSFFindingInfo{
		UID:           uid,
		Title:         title,
		Desc:          f.Description,
		FirstSeenTime: epochMillis(f.FirstSeenAt),
		LastSeenTime:  epochMillis(f.LastSeenAt),
	}
	if f.Category != "" {
		ev.FindingInfo.Types = []string{f.Category}
	}
	if f.RuleID != "" || f.RuleName != "" {
		ev.FindingInfo.Analytic = &OCSFAnalytic{UID: f.RuleID, Name: f.RuleName, TypeID: 1, Type: "Rule"}
	}

	if res, ok := ocsfResourceOf(r, f); ok {
		ev.Resources = []OCSFResource{res}
	}
	ev.Unmapped = map[string]string{"ctis_type": string(f.Type)}
	if cd := f.Compliance; cd != nil && cd.FrameworkVersion != "" {
		ev.Unmapped["compliance_framework_version"] = cd.FrameworkVersion
	}
	if s := f.Secret; s != nil {
		for k, v := range map[string]string{"secret_type": s.SecretType, "secret_service": s.Service, "secret_masked_value": s.MaskedValue} {
			if v != "" {
				ev.Unmapped[k] = v
			}
		}
	}

	var rem *OCSFRemediation
	if f.Remediation != nil && f.Remediation.Recommendation != "" {
		rem = &OCSFRemediation{Desc: f.Remediation.Recommendation, References: f.Remediation.References}
	}
	if class == OCSFClassComplianceFinding {
		ev.Compliance = ocsfComplianceOf(f)
		ev.Remediation = rem
		return ev
	}
	ev.Vulnerabilities = ocsfVulnerabilitiesOf(f, rem)
	return ev
}

func ocsfResourceOf(r *Report, f *Finding) (OCSFResource, bool) {
	if a := findAsset(r, f.AssetRef); a != nil {
		return OCSFResource{UID: a.ID, Name: a.Value, Type: string(a.Type)}, true
	}
	if f.AssetValue != "" || f.AssetRef != "" {
		return OCSFResource{UID: f.AssetRef, Name: f.AssetValue, Type: string(f.AssetType)}, true
	}
	return OCSFResource{}, false
}

func ocsfComplianceOf(f *Finding) *OCSFCompliance {
	c := &OCSFCompliance{Standards: []string{}}
	if cd := f.Compliance; cd != nil {
		if cd.Framework != "" {
			c.Standards = []string{cd.Framework}
		}
		c.Control = cd.ControlID
		switch strings.ToLower(cd.Result) {
		case "pass":
			c.StatusID, c.Status = 1, "Pass"
		case "fail":
			c.StatusID, c.Status = 3, "Fail"
		case "":
		default:
			c.StatusID, c.Status = 99, cd.Result
		}
	}
	if m := f.Misconfiguration; m != nil {
		if len(c.Standards) == 0 && m.Provider != "" {
			c.Standards = []string{m.Provider}
		}
		if c.Control == "" {
			c.Control = m.PolicyID
		}
		if c.StatusID == 0 {
			c.StatusID, c.Status = 3, "Fail"
		}
	}
	return c
}

func ocsfVulnerabilitiesOf(f *Finding, rem *OCSFRemediation) []OCSFVulnerability {
	_, sev := ocsfSeverity(f.Severity)
	first := OCSFVulnerability{
		Title:       f.Title,
		Desc:        f.Description,
		Severity:    sev,
		References:  f.References,
		Remediation: rem,
	}
	v := f.Vulnerability
	if v == nil {
		if loc := ocsfCodeOf(f.Location); loc != nil {
			first.AffectedCode = []OCSFAffectedCode{*loc}
		}
		return []OCSFVulnerability{first}
	}
	first.IsExploitAvailable = v.ExploitAvailable
	if v.Package != "" {
		first.AffectedPackages = []OCSFPackage{{Name: v.Package, Version: v.AffectedVersion, PURL: v.PURL, FixedInVersion: v.FixedVersion}}
	}
	if loc := ocsfCodeOf(f.Location); loc != nil {
		first.AffectedCode = []OCSFAffectedCode{*loc}
	}

	cves := ocsfCVEs(v)
	cwes := v.CWEIDs
	if len(cwes) == 0 && v.CWEID != "" {
		cwes = []string{v.CWEID}
	}
	n := max(len(cves), len(cwes), 1)
	out := make([]OCSFVulnerability, n)
	out[0] = first
	for i := range n {
		if i < len(cves) {
			out[i].CVE = &OCSFCVE{UID: cves[i]}
		}
		if i < len(cwes) {
			out[i].CWE = &OCSFCWE{UID: cwes[i]}
		}
	}
	// Scores go with the first CVE (a finding's scores are of its primary
	// vulnerability); without a CVE they have no OCSF place.
	if out[0].CVE != nil {
		out[0].CVE.CVSS, out[0].CVE.EPSS = ocsfScoresOf(f)
	}
	return out
}

// ocsfCVEs lists a finding's CVE ids once, primary first.
func ocsfCVEs(v *VulnerabilityDetails) []string {
	var out []string
	seen := map[string]bool{}
	add := func(id string) {
		u := strings.ToUpper(strings.TrimSpace(id))
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	add(v.CVEID)
	for _, id := range v.CVEIDs {
		add(id)
	}
	for _, id := range v.IDs {
		if id.Type == VulnerabilityIDCVE {
			add(id.ID)
		}
	}
	return out
}

func ocsfScoresOf(f *Finding) ([]OCSFCVSS, *OCSFEPSS) {
	var cvss []OCSFCVSS
	var epss *OCSFEPSS
	for i := range f.Scores {
		s := &f.Scores[i]
		switch s.System {
		case ScoreSystemCVSS:
			c := OCSFCVSS{Version: s.Version, VectorString: s.Vector}
			if s.Value != nil {
				val := *s.Value
				c.BaseScore = &val
			}
			cvss = append(cvss, c)
		case ScoreSystemEPSS:
			if s.Value != nil {
				if epss == nil {
					epss = &OCSFEPSS{}
				}
				epss.Score = formatScore(*s.Value)
			}
		case ScoreSystemEPSSPercentile:
			if s.Value != nil {
				if epss == nil {
					epss = &OCSFEPSS{}
				}
				val := *s.Value
				epss.Percentile = &val
			}
		}
	}
	if len(cvss) == 0 && f.Vulnerability != nil && (f.Vulnerability.CVSSScore > 0 || f.Vulnerability.CVSSVector != "") {
		v := f.Vulnerability
		c := OCSFCVSS{Version: v.CVSSVersion, VectorString: v.CVSSVector}
		if v.CVSSScore > 0 {
			val := v.CVSSScore
			c.BaseScore = &val
		}
		cvss = append(cvss, c)
	}
	return cvss, epss
}

func ocsfCodeOf(l *FindingLocation) *OCSFAffectedCode {
	if l == nil || l.Path == "" {
		return nil
	}
	return &OCSFAffectedCode{File: OCSFFile{Name: path.Base(l.Path), Path: l.Path}, StartLine: l.StartLine, EndLine: l.EndLine}
}
