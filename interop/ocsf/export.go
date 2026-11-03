package ocsf

import (
	"strconv"

	"github.com/openctemio/ctis/v2/internal/exportkit"

	"github.com/openctemio/ctis/v2"

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
//   - time: last_seen_at, else first_seen_at, else Options.Time, else
//     report.metadata.timestamp.
//   - the CTIS finding type -> unmapped["ctis_type"]; the compliance
//     framework version -> unmapped["compliance_framework_version"]; a
//     secret's type, service and masked value -> unmapped (masked, never
//     the raw match).

// Version is the OCSF schema version Events writes.
const Version = "1.3.0"

// OCSF class, category and activity ids used by Events.
const (
	CategoryFindings          = 2
	ClassVulnerabilityFinding = 2002
	ClassComplianceFinding    = 2003
	ActivityCreate            = 1
	ActivityClose             = 3
)

// defaultProduct names the product of a report without a tool.
const defaultProduct = "ctis"

// ErrTooLarge is returned when the encoded output would exceed MaxBytes.
var ErrTooLarge = exportkit.ErrTooLarge

// MaxBytes is the largest output Export returns.
const MaxBytes = exportkit.MaxBytes

// Export is Events encoded as a JSON array of events.
func Export(r *ctis.Report, opts *Options) ([]byte, error) {
	events, err := Events(r, opts)
	if err != nil {
		return nil, err
	}
	return exportkit.Marshal(events)
}

// Options configure Events. The zero value is valid.
type Options struct {
	// Time of an event whose finding has no seen time. Zero:
	// report.metadata.timestamp.
	Time time.Time
}

// Event is one OCSF Vulnerability Finding or Compliance Finding event.
type Event struct {
	ActivityID      int               `json:"activity_id"`
	ActivityName    string            `json:"activity_name"`
	CategoryUID     int               `json:"category_uid"`
	CategoryName    string            `json:"category_name"`
	ClassUID        int               `json:"class_uid"`
	ClassName       string            `json:"class_name"`
	TypeUID         int               `json:"type_uid"`
	TypeName        string            `json:"type_name"`
	SeverityID      int               `json:"severity_id"`
	Severity        string            `json:"severity"`
	StatusID        int               `json:"status_id,omitempty"`
	Status          string            `json:"status,omitempty"`
	Time            int64             `json:"time"`
	ConfidenceScore int               `json:"confidence_score,omitempty"`
	Message         string            `json:"message,omitempty"`
	Metadata        Metadata          `json:"metadata"`
	FindingInfo     FindingInfo       `json:"finding_info"`
	Vulnerabilities []Vulnerability   `json:"vulnerabilities,omitempty"`
	Compliance      *Compliance       `json:"compliance,omitempty"`
	Remediation     *Remediation      `json:"remediation,omitempty"`
	Resources       []Resource        `json:"resources,omitempty"`
	Unmapped        map[string]string `json:"unmapped,omitempty"`
}

// Metadata is the event's metadata object.
type Metadata struct {
	Version string  `json:"version"`
	Product Product `json:"product"`
}

// Product is the product that reported the finding.
type Product struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name,omitempty"`
	Version    string `json:"version,omitempty"`
	URL        string `json:"url_string,omitempty"`
}

// FindingInfo is the finding_info object.
type FindingInfo struct {
	UID           string    `json:"uid"`
	Title         string    `json:"title"`
	Desc          string    `json:"desc,omitempty"`
	Types         []string  `json:"types,omitempty"`
	FirstSeenTime int64     `json:"first_seen_time,omitempty"`
	LastSeenTime  int64     `json:"last_seen_time,omitempty"`
	Analytic      *Analytic `json:"analytic,omitempty"`
}

// Analytic is the rule that produced the finding.
type Analytic struct {
	UID    string `json:"uid,omitempty"`
	Name   string `json:"name,omitempty"`
	TypeID int    `json:"type_id"`
	Type   string `json:"type"`
}

// Vulnerability is one entry of vulnerabilities[].
type Vulnerability struct {
	Title              string         `json:"title,omitempty"`
	Desc               string         `json:"desc,omitempty"`
	Severity           string         `json:"severity,omitempty"`
	CVE                *CVE           `json:"cve,omitempty"`
	CWE                *CWE           `json:"cwe,omitempty"`
	AffectedPackages   []Package      `json:"affected_packages,omitempty"`
	AffectedCode       []AffectedCode `json:"affected_code,omitempty"`
	References         []string       `json:"references,omitempty"`
	IsExploitAvailable bool           `json:"is_exploit_available,omitempty"`
	Remediation        *Remediation   `json:"remediation,omitempty"`
}

// CVE is a CVE with its scores.
type CVE struct {
	UID  string `json:"uid"`
	CVSS []CVSS `json:"cvss,omitempty"`
	EPSS *EPSS  `json:"epss,omitempty"`
}

// CVSS is one CVSS score.
type CVSS struct {
	Version      string   `json:"version"`
	BaseScore    *float64 `json:"base_score,omitempty"`
	VectorString string   `json:"vector_string,omitempty"`
}

// EPSS is an EPSS score.
type EPSS struct {
	Score      string   `json:"score"`
	Percentile *float64 `json:"percentile,omitempty"`
}

// CWE is a CWE.
type CWE struct {
	UID string `json:"uid"`
}

// Package is an affected package.
type Package struct {
	Name           string `json:"name"`
	Version        string `json:"version,omitempty"`
	PURL           string `json:"purl,omitempty"`
	FixedInVersion string `json:"fixed_in_version,omitempty"`
}

// AffectedCode is a code location of the finding.
type AffectedCode struct {
	File      File `json:"file"`
	StartLine int  `json:"start_line,omitempty"`
	EndLine   int  `json:"end_line,omitempty"`
}

// File is a file.
type File struct {
	Name string `json:"name"`
	Path string `json:"path,omitempty"`
}

// Remediation is how to fix the finding.
type Remediation struct {
	Desc       string   `json:"desc"`
	References []string `json:"references,omitempty"`
}

// Compliance is the compliance object of a Compliance Finding.
type Compliance struct {
	Standards []string `json:"standards"`
	Control   string   `json:"control,omitempty"`
	StatusID  int      `json:"status_id,omitempty"`
	Status    string   `json:"status,omitempty"`
}

// Resource is an affected resource.
type Resource struct {
	UID  string `json:"uid,omitempty"`
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}

// Events converts the findings of a report to OCSF 1.3.0 events, one per
// finding, in report order. See the mapping above and docs/exporters.md.
func Events(r *ctis.Report, opts *Options) ([]Event, error) {
	if r == nil {
		return nil, exportkit.ErrNilReport
	}
	if opts == nil {
		opts = &Options{}
	}
	product := Product{Name: defaultProduct}
	if t := r.Tool; t != nil {
		if t.Name != "" {
			product.Name = t.Name
		}
		product.VendorName, product.Version, product.URL = t.Vendor, t.Version, t.InfoURL
	}
	fallback := opts.Time
	if fallback.IsZero() {
		fallback = r.Metadata.GeneratedAt
	}
	events := make([]Event, 0, len(r.Findings))
	size := 0
	for i := range r.Findings {
		f, err := exportkit.Finding(&r.Findings[i])
		if err != nil {
			return nil, err
		}
		ev := ocsfEventOf(r, &f, product, fallback)
		size += ocsfSizeHint(&ev)
		if size > exportkit.MaxBytes {
			return nil, exportkit.ErrTooLarge
		}
		events = append(events, ev)
	}
	return events, nil
}

// ocsfSizeHint approximates an event's encoded size from its free text.
func ocsfSizeHint(ev *Event) int {
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
func ocsfSeverity(s ctis.Severity) (int, string) {
	return idCaption("severity", string(s))
}

// ocsfStatus maps a status to status_id and its caption.
func ocsfStatus(s ctis.FindingStatus) (int, string) {
	return idCaption("status", string(s))
}

// idCaption looks up "<id>|<caption>" in a table of the export mapping.
func idCaption(table, v string) (int, string) {
	e, _ := exp.Lookup(table, v)
	id, caption, _ := strings.Cut(e, "|")
	n, _ := strconv.Atoi(id)
	return n, caption
}

func epochMillis(t *time.Time) int64 {
	if t == nil || t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func ocsfEventOf(r *ctis.Report, f *ctis.Finding, product Product, fallback time.Time) Event {
	class, className := ClassVulnerabilityFinding, "Vulnerability Finding"
	if f.Type == ctis.FindingTypeCompliance || f.Type == ctis.FindingTypeMisconfiguration {
		class, className = ClassComplianceFinding, "Compliance Finding"
	}
	activity, activityName := ActivityCreate, "Create"
	if f.Status == ctis.FindingStatusResolved {
		activity, activityName = ActivityClose, "Close"
	}
	ev := Event{
		ActivityID:      activity,
		ActivityName:    activityName,
		CategoryUID:     CategoryFindings,
		CategoryName:    "Findings",
		ClassUID:        class,
		ClassName:       className,
		TypeUID:         class*100 + activity,
		TypeName:        className + ": " + activityName,
		ConfidenceScore: f.Confidence,
		Message:         f.Message,
		Metadata:        Metadata{Version: Version, Product: product},
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
	ev.FindingInfo = FindingInfo{
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
		ev.FindingInfo.Analytic = &Analytic{UID: f.RuleID, Name: f.RuleName, TypeID: 1, Type: "Rule"}
	}

	if res, ok := ocsfResourceOf(r, f); ok {
		ev.Resources = []Resource{res}
	}
	ev.Unmapped = map[string]string{"ctis_type": string(f.Type)}
	if cd := f.Compliance; cd != nil && cd.FrameworkVersion != "" {
		ev.Unmapped["compliance_framework_version"] = cd.FrameworkVersion
	}
	if s := f.Secret; s != nil {
		for k, v := range map[string]string{"secret_type": s.Type, "secret_service": s.Service, "secret_masked_value": s.MaskedValue} {
			if v != "" {
				ev.Unmapped[k] = v
			}
		}
	}

	var rem *Remediation
	if f.Remediation != nil && f.Remediation.Recommendation != "" {
		rem = &Remediation{Desc: f.Remediation.Recommendation, References: f.References}
	}
	if class == ClassComplianceFinding {
		ev.Compliance = ocsfComplianceOf(f)
		ev.Remediation = rem
		return ev
	}
	ev.Vulnerabilities = ocsfVulnerabilitiesOf(f, rem)
	return ev
}

func ocsfResourceOf(r *ctis.Report, f *ctis.Finding) (Resource, bool) {
	if a := exportkit.FindAsset(r, f.AssetRef); a != nil {
		return Resource{UID: a.ID, Name: a.Value, Type: string(a.Type)}, true
	}
	if f.AssetRef != "" {
		return Resource{UID: f.AssetRef}, true
	}
	return Resource{}, false
}

func ocsfComplianceOf(f *ctis.Finding) *Compliance {
	c := &Compliance{Standards: []string{}}
	if cd := f.Compliance; cd != nil {
		if cd.Framework != "" {
			c.Standards = []string{string(cd.Framework)}
		}
		c.Control = cd.ControlID
		switch strings.ToLower(f.Kind) {
		case "pass":
			c.StatusID, c.Status = 1, "Pass"
		case "fail":
			c.StatusID, c.Status = 3, "Fail"
		case "":
		default:
			c.StatusID, c.Status = 99, f.Kind
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

func ocsfVulnerabilitiesOf(f *ctis.Finding, rem *Remediation) []Vulnerability {
	_, sev := ocsfSeverity(f.Severity)
	first := Vulnerability{
		Title:       f.Title,
		Desc:        f.Description,
		Severity:    sev,
		References:  f.References,
		Remediation: rem,
	}
	v := f.Vulnerability
	if v == nil {
		if loc := ocsfCodeOf(f.Location); loc != nil {
			first.AffectedCode = []AffectedCode{*loc}
		}
		return []Vulnerability{first}
	}
	first.IsExploitAvailable = ctis.HasThreatSignal(v, ctis.ThreatSignalPublicExploit, ctis.ThreatSignalWeaponized, ctis.ThreatSignalExploitedInWild, ctis.ThreatSignalKEV)
	if v.PackageName != "" {
		pkg := Package{Name: v.PackageName, Version: v.InstalledVersion, PURL: v.PURL}
		if len(v.FixedVersions) > 0 {
			pkg.FixedInVersion = v.FixedVersions[0]
		}
		first.AffectedPackages = []Package{pkg}
	}
	if loc := ocsfCodeOf(f.Location); loc != nil {
		first.AffectedCode = []AffectedCode{*loc}
	}

	cves := ocsfCVEs(v)
	cwes := v.CWEIDs
	n := max(len(cves), len(cwes), 1)
	out := make([]Vulnerability, n)
	out[0] = first
	for i := range n {
		if i < len(cves) {
			out[i].CVE = &CVE{UID: cves[i]}
		}
		if i < len(cwes) {
			out[i].CWE = &CWE{UID: cwes[i]}
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
func ocsfCVEs(v *ctis.VulnerabilityDetails) []string {
	var out []string
	seen := map[string]bool{}
	add := func(id string) {
		u := strings.ToUpper(strings.TrimSpace(id))
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	for _, id := range v.IDs {
		if id.Type == ctis.VulnerabilityIDCVE {
			add(id.ID)
		}
	}
	return out
}

func ocsfScoresOf(f *ctis.Finding) ([]CVSS, *EPSS) {
	var cvss []CVSS
	var epss *EPSS
	for i := range f.Scores {
		s := &f.Scores[i]
		switch s.System {
		case ctis.ScoreSystemCVSS:
			c := CVSS{Version: s.Version, VectorString: s.Vector}
			if s.Value != nil {
				val := *s.Value
				c.BaseScore = &val
			}
			cvss = append(cvss, c)
		case ctis.ScoreSystemEPSS:
			if s.Value != nil {
				if epss == nil {
					epss = &EPSS{}
				}
				epss.Score = exportkit.FormatScore(*s.Value)
			}
		case ctis.ScoreSystemEPSSPercentile:
			if s.Value != nil {
				if epss == nil {
					epss = &EPSS{}
				}
				val := *s.Value
				epss.Percentile = &val
			}
		}
	}
	return cvss, epss
}

func ocsfCodeOf(l *ctis.FindingLocation) *AffectedCode {
	if l == nil || l.Path == "" {
		return nil
	}
	return &AffectedCode{File: File{Name: path.Base(l.Path), Path: l.Path}, StartLine: l.StartLine, EndLine: l.EndLine}
}
