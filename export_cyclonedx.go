package ctis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// CTIS to CycloneDX 1.6 (a BOM with a VDR/VEX).
//
// Mapping (the CycloneDX importer reads every member back):
//   - dependencies -> components (bom-ref = dependency id); the dependency
//     graph -> dependencies[] (relationship direct -> the subject's
//     dependsOn); dependency properties written by the importer (group,
//     hash_*, cpe, scope, publisher, supplier, description, property:*)
//     -> their CycloneDX members.
//   - the subject asset (CycloneDXOptions.SubjectAssetID, else the first
//     asset) -> metadata.component.
//   - vulnerability findings -> vulnerabilities[], one per vulnerability id,
//     with every affected component in affects[]; scores -> ratings;
//     vulnerability.ids -> id and references; cwe_ids -> cwes; vex ->
//     analysis (state, justification, detail); remediation -> recommendation,
//     workaround, advisories.
//   - report.metadata.properties bom_serial_number, bom_version,
//     bom_timestamp (set by the importer) -> serialNumber, version,
//     metadata.timestamp.
//
// Findings of other types (secret, misconfiguration, compliance, web3) are
// not part of a BOM and are left out.

const (
	cdxSpecVersion = "1.6"
	cdxBOMFormat   = "CycloneDX"
)

// CycloneDXOptions configure ToCycloneDX. The zero value is valid.
type CycloneDXOptions struct {
	// serialNumber of the BOM (urn:uuid:...). Empty: the report's
	// metadata.properties bom_serial_number, else a UUID derived from the
	// report's content (stable for the same report).
	SerialNumber string

	// metadata.timestamp of the BOM. Zero: the report's
	// metadata.properties bom_timestamp, else report.metadata.timestamp.
	Timestamp time.Time

	// Id of the asset the BOM describes (metadata.component). Empty: the
	// first asset of the report.
	SubjectAssetID string
}

type cdxOutBOM struct {
	BOMFormat       string            `json:"bomFormat"`
	SpecVersion     string            `json:"specVersion"`
	SerialNumber    string            `json:"serialNumber,omitempty"`
	Version         int               `json:"version"`
	Metadata        *cdxOutMetadata   `json:"metadata,omitempty"`
	Components      []cdxOutComponent `json:"components,omitempty"`
	Dependencies    []cdxOutDep       `json:"dependencies,omitempty"`
	Vulnerabilities []cdxOutVuln      `json:"vulnerabilities,omitempty"`
}

type cdxOutMetadata struct {
	Timestamp string           `json:"timestamp,omitempty"`
	Tools     *cdxOutTools     `json:"tools,omitempty"`
	Component *cdxOutComponent `json:"component,omitempty"`
}

type cdxOutTools struct {
	Components []cdxOutComponent `json:"components"`
}

type cdxOutComponent struct {
	Type        string           `json:"type"`
	BOMRef      string           `json:"bom-ref,omitempty"`
	Supplier    *cdxOutEntity    `json:"supplier,omitempty"`
	Publisher   string           `json:"publisher,omitempty"`
	Group       string           `json:"group,omitempty"`
	Name        string           `json:"name"`
	Version     string           `json:"version,omitempty"`
	Description string           `json:"description,omitempty"`
	Scope       string           `json:"scope,omitempty"`
	Hashes      []cdxOutHash     `json:"hashes,omitempty"`
	Licenses    []cdxOutLicense  `json:"licenses,omitempty"`
	CPE         string           `json:"cpe,omitempty"`
	PURL        string           `json:"purl,omitempty"`
	Properties  []cdxOutProperty `json:"properties,omitempty"`
}

type cdxOutEntity struct {
	Name string `json:"name"`
}

type cdxOutHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxOutLicense struct {
	License    *cdxOutLicenseName `json:"license,omitempty"`
	Expression string             `json:"expression,omitempty"`
}

type cdxOutLicenseName struct {
	Name string `json:"name"`
}

type cdxOutProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxOutDep struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

type cdxOutSource struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

type cdxOutRef struct {
	ID     string        `json:"id"`
	Source *cdxOutSource `json:"source,omitempty"`
}

type cdxOutRating struct {
	Source        *cdxOutSource `json:"source,omitempty"`
	Score         *float64      `json:"score,omitempty"`
	Severity      string        `json:"severity,omitempty"`
	Method        string        `json:"method,omitempty"`
	Vector        string        `json:"vector,omitempty"`
	Justification string        `json:"justification,omitempty"`
}

type cdxOutAdvisory struct {
	Title string `json:"title,omitempty"`
	URL   string `json:"url"`
}

type cdxOutAnalysis struct {
	State         string   `json:"state,omitempty"`
	Justification string   `json:"justification,omitempty"`
	Response      []string `json:"response,omitempty"`
	Detail        string   `json:"detail,omitempty"`
	LastUpdated   string   `json:"lastUpdated,omitempty"`
}

type cdxOutVersion struct {
	Version string `json:"version,omitempty"`
	Range   string `json:"range,omitempty"`
	Status  string `json:"status,omitempty"`
}

type cdxOutAffect struct {
	Ref      string          `json:"ref"`
	Versions []cdxOutVersion `json:"versions,omitempty"`
}

type cdxOutVuln struct {
	BOMRef         string           `json:"bom-ref,omitempty"`
	ID             string           `json:"id"`
	Source         *cdxOutSource    `json:"source,omitempty"`
	References     []cdxOutRef      `json:"references,omitempty"`
	Ratings        []cdxOutRating   `json:"ratings,omitempty"`
	CWEs           []int            `json:"cwes,omitempty"`
	Description    string           `json:"description,omitempty"`
	Detail         string           `json:"detail,omitempty"`
	Recommendation string           `json:"recommendation,omitempty"`
	Workaround     string           `json:"workaround,omitempty"`
	Advisories     []cdxOutAdvisory `json:"advisories,omitempty"`
	Created        string           `json:"created,omitempty"`
	Published      string           `json:"published,omitempty"`
	Updated        string           `json:"updated,omitempty"`
	Rejected       string           `json:"rejected,omitempty"`
	Analysis       *cdxOutAnalysis  `json:"analysis,omitempty"`
	Affects        []cdxOutAffect   `json:"affects,omitempty"`
	Properties     []cdxOutProperty `json:"properties,omitempty"`
}

// cdxHashAlgs maps a lower-cased hash algorithm to its CycloneDX spelling.
var cdxHashAlgs = map[string]string{
	"md5": "MD5", "sha-1": "SHA-1", "sha-256": "SHA-256", "sha-384": "SHA-384", "sha-512": "SHA-512",
	"sha3-256": "SHA3-256", "sha3-384": "SHA3-384", "sha3-512": "SHA3-512",
	"blake2b-256": "BLAKE2b-256", "blake2b-384": "BLAKE2b-384", "blake2b-512": "BLAKE2b-512", "blake3": "BLAKE3",
}

// cdxJustifications are the CycloneDX analysis justifications.
var cdxJustifications = map[string]bool{
	"code_not_present": true, "code_not_reachable": true, "requires_configuration": true,
	"requires_dependency": true, "requires_environment": true, "protected_by_compiler": true,
	"protected_at_runtime": true, "protected_at_perimeter": true, "protected_by_mitigating_control": true,
}

// cdxJustificationOf is the inverse of NormalizeVEXJustification for the
// CycloneDX values: the source's own word when it is a CycloneDX value,
// else the nearest CycloneDX value of the CTIS justification.
func cdxJustificationOf(v *VEX) string {
	if n := strings.ToLower(strings.TrimSpace(v.NativeJustification)); cdxJustifications[n] {
		return n
	}
	switch v.Justification {
	case VEXJustificationComponentNotPresent, VEXJustificationVulnerableCodeNotPresent:
		return "code_not_present"
	case VEXJustificationVulnerableCodeNotInExecutePath:
		return "code_not_reachable"
	case VEXJustificationVulnerableCodeCannotBeControlledByAdversary:
		return "requires_environment"
	case VEXJustificationInlineMitigationsAlreadyExist:
		return "protected_by_mitigating_control"
	}
	return ""
}

// cdxStateOf maps a VEX status to a CycloneDX analysis state.
func cdxStateOf(s VEXStatus) string {
	switch s {
	case VEXStatusNotAffected:
		return "not_affected"
	case VEXStatusAffected:
		return "exploitable"
	case VEXStatusFixed:
		return "resolved"
	case VEXStatusUnderInvestigation:
		return "in_triage"
	}
	return ""
}

// cdxRatingSeverities are the CycloneDX rating severities.
var cdxRatingSeverities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true, "none": true, "unknown": true}

// cdxMethodOf maps a score to a CycloneDX rating method; ok is false for a
// system CycloneDX has no rating for (EPSS, VPR).
func cdxMethodOf(s *Score) (string, bool) {
	switch s.System {
	case ScoreSystemCVSS:
		switch s.Version {
		case "2.0":
			return "CVSSv2", true
		case "3.0":
			return "CVSSv3", true
		case "3.1":
			return "CVSSv31", true
		case "4.0":
			return "CVSSv4", true
		}
		return "other", true
	case ScoreSystemSSVC:
		return "SSVC", true
	case ScoreSystemVendor:
		return "other", true
	}
	return "", false
}

// cdxSPDXToken matches a license value written as an SPDX expression.
var cdxSPDXToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+\-]*$`)

func cdxLicenseOf(l string) cdxOutLicense {
	if cdxSPDXToken.MatchString(l) || strings.Contains(l, " AND ") || strings.Contains(l, " OR ") || strings.Contains(l, " WITH ") {
		return cdxOutLicense{Expression: l}
	}
	return cdxOutLicense{License: &cdxOutLicenseName{Name: l}}
}

// cdxDepKeys are the dependency properties mapped to CycloneDX members.
var cdxDepKeys = map[string]bool{"group": true, "cpe": true, "scope": true, "publisher": true, "supplier": true, "description": true}

func cdxComponentOf(d *Dependency, ref string) cdxOutComponent {
	c := cdxOutComponent{
		Type:        d.Type,
		BOMRef:      ref,
		Name:        d.Name,
		Version:     d.Version,
		PURL:        d.PURL,
		Group:       propString(d.Properties, "group"),
		CPE:         propString(d.Properties, "cpe"),
		Scope:       propString(d.Properties, "scope"),
		Publisher:   propString(d.Properties, "publisher"),
		Description: propString(d.Properties, "description"),
	}
	if c.Type == "" {
		c.Type = "library"
	}
	if s := propString(d.Properties, "supplier"); s != "" {
		c.Supplier = &cdxOutEntity{Name: s}
	}
	for _, l := range d.Licenses {
		if l != "" {
			c.Licenses = append(c.Licenses, cdxLicenseOf(l))
		}
	}
	keys := make([]string, 0, len(d.Properties))
	for k := range d.Properties {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := propString(d.Properties, k)
		switch {
		case v == "" || cdxDepKeys[k]:
		case strings.HasPrefix(k, "hash_"):
			if alg, ok := cdxHashAlgs[strings.TrimPrefix(k, "hash_")]; ok {
				c.Hashes = append(c.Hashes, cdxOutHash{Alg: alg, Content: v})
			}
		case strings.HasPrefix(k, "property:"):
			c.Properties = append(c.Properties, cdxOutProperty{Name: strings.TrimPrefix(k, "property:"), Value: v})
		default:
			c.Properties = append(c.Properties, cdxOutProperty{Name: "ctis:" + k, Value: v})
		}
	}
	return c
}

// cdxSubjectOf writes the asset a BOM describes.
func cdxSubjectOf(a *Asset) *cdxOutComponent {
	c := &cdxOutComponent{
		Type:    propString(a.Properties, "component_type"),
		BOMRef:  a.ID,
		Name:    a.Name,
		Version: propString(a.Properties, "version"),
		CPE:     propString(a.Properties, "cpe"),
	}
	if c.Name == "" {
		c.Name = a.Value
	}
	if strings.HasPrefix(a.Value, "pkg:") {
		c.PURL = a.Value
	}
	if c.Type == "" {
		switch a.Type {
		case AssetTypeContainer:
			c.Type = "container"
		case AssetTypeHost:
			c.Type = "operating-system"
		default:
			c.Type = "application"
		}
	}
	if c.BOMRef == "" {
		c.BOMRef = "subject"
	}
	return c
}

// cdxSerial derives a stable urn:uuid from the report's content (a UUID of
// version 8, the RFC 9562 form for name-based UUIDs of other hashes).
func cdxSerial(r *Report) string {
	b, _ := json.Marshal(r)
	sum := sha256.Sum256(b)
	u := sum[:16]
	u[6] = (u[6] & 0x0f) | 0x80
	u[8] = (u[8] & 0x3f) | 0x80
	h := hex.EncodeToString(u)
	return "urn:uuid:" + h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// cdxVulnID is the vulnerability id a finding is grouped under.
func cdxVulnID(f *Finding) string {
	if id, ok := NormalizeVulnerabilityID(f.RuleID); ok && id.Type != VulnerabilityIDVendor {
		return f.RuleID
	}
	if v := f.Vulnerability; v != nil {
		if len(v.IDs) > 0 {
			return v.IDs[0].ID
		}
		if v.CVEID != "" {
			return v.CVEID
		}
		if len(v.CVEIDs) > 0 {
			return v.CVEIDs[0]
		}
	}
	return f.RuleID
}

// cdxBuilder holds the components while the BOM is built.
type cdxBuilder struct {
	bom    cdxOutBOM
	refs   map[string]bool
	byPURL map[string]string
	byName map[string]string
}

func (b *cdxBuilder) addComponent(c cdxOutComponent) {
	b.refs[c.BOMRef] = true
	if c.PURL != "" {
		if _, ok := b.byPURL[c.PURL]; !ok {
			b.byPURL[c.PURL] = c.BOMRef
		}
	}
	name := c.Name
	if c.Group != "" {
		name = c.Group + "/" + name
	}
	key := nameAtVersion(name, c.Version)
	if _, ok := b.byName[key]; !ok {
		b.byName[key] = c.BOMRef
	}
	b.bom.Components = append(b.bom.Components, c)
}

func nameAtVersion(name, version string) string {
	if version == "" {
		return name
	}
	return name + "@" + version
}

// componentFor returns the bom-ref of the component a finding affects,
// adding one from the finding's package when the report lists none.
func (b *cdxBuilder) componentFor(v *VulnerabilityDetails) string {
	if v == nil {
		return ""
	}
	if ref, ok := b.byPURL[v.PURL]; ok && v.PURL != "" {
		return ref
	}
	if v.Package == "" {
		return ""
	}
	key := nameAtVersion(v.Package, v.AffectedVersion)
	if ref, ok := b.byName[key]; ok {
		return ref
	}
	ref := v.PURL
	if ref == "" {
		ref = "pkg-" + key
	}
	if !b.refs[ref] {
		b.addComponent(cdxOutComponent{Type: "library", BOMRef: ref, Name: v.Package, Version: v.AffectedVersion, PURL: v.PURL, CPE: v.CPE})
	}
	return ref
}

// ToCycloneDX converts a report to a CycloneDX 1.6 JSON BOM with its
// vulnerabilities. See the mapping above and docs/exporters.md.
func ToCycloneDX(r *Report, opts *CycloneDXOptions) ([]byte, error) {
	if r == nil {
		return nil, errNilReport
	}
	if opts == nil {
		opts = &CycloneDXOptions{}
	}
	b := &cdxBuilder{
		bom:    cdxOutBOM{BOMFormat: cdxBOMFormat, SpecVersion: cdxSpecVersion, Version: 1},
		refs:   map[string]bool{},
		byPURL: map[string]string{},
		byName: map[string]string{},
	}
	meta := r.Metadata.Properties
	b.bom.SerialNumber = opts.SerialNumber
	if b.bom.SerialNumber == "" {
		b.bom.SerialNumber = propString(meta, "bom_serial_number")
	}
	if b.bom.SerialNumber == "" {
		b.bom.SerialNumber = cdxSerial(r)
	}
	switch v := meta["bom_version"].(type) {
	case int:
		b.bom.Version = max(v, 1)
	case float64:
		b.bom.Version = max(int(v), 1)
	}
	md := &cdxOutMetadata{}
	switch {
	case !opts.Timestamp.IsZero():
		md.Timestamp = opts.Timestamp.UTC().Format(time.RFC3339)
	case propString(meta, "bom_timestamp") != "":
		md.Timestamp = propString(meta, "bom_timestamp")
	case !r.Metadata.Timestamp.IsZero():
		md.Timestamp = r.Metadata.Timestamp.UTC().Format(time.RFC3339)
	}
	if t := r.Tool; t != nil && t.Name != "" {
		md.Tools = &cdxOutTools{Components: []cdxOutComponent{{Type: "application", Name: t.Name, Version: t.Version}}}
	}
	subject := findAsset(r, opts.SubjectAssetID)
	if subject == nil && opts.SubjectAssetID == "" && len(r.Assets) > 0 {
		subject = &r.Assets[0]
	}
	if subject != nil {
		md.Component = cdxSubjectOf(subject)
		b.refs[md.Component.BOMRef] = true
	}
	b.bom.Metadata = md

	// Components, by dependency id.
	idOf := map[string]string{} // dependency id or name -> bom-ref
	for i := range r.Dependencies {
		d := &r.Dependencies[i]
		if d.Name == "" {
			continue
		}
		ref := d.ID
		if ref == "" {
			ref = d.PURL
		}
		if ref == "" {
			ref = nameAtVersion(d.Name, d.Version)
		}
		if b.refs[ref] {
			continue
		}
		b.addComponent(cdxComponentOf(d, ref))
		idOf[ref] = ref
		if _, ok := idOf[d.Name]; !ok {
			idOf[d.Name] = ref
		}
	}

	// The dependency graph, when the report has one.
	hasGraph := false
	for i := range r.Dependencies {
		if r.Dependencies[i].Relationship != "" || len(r.Dependencies[i].DependsOn) > 0 {
			hasGraph = true
			break
		}
	}
	if hasGraph {
		var direct []string
		var deps []cdxOutDep
		seen := map[string]bool{}
		for i := range r.Dependencies {
			d := &r.Dependencies[i]
			ref := d.ID
			if ref == "" {
				ref = d.PURL
			}
			if ref == "" {
				ref = nameAtVersion(d.Name, d.Version)
			}
			if d.Name == "" || seen[ref] {
				continue
			}
			seen[ref] = true
			if d.Relationship == "direct" {
				direct = append(direct, ref)
			}
			dep := cdxOutDep{Ref: ref}
			for _, on := range d.DependsOn {
				if t, ok := idOf[on]; ok && t != ref && !contains(dep.DependsOn, t) {
					dep.DependsOn = append(dep.DependsOn, t)
				}
			}
			deps = append(deps, dep)
		}
		if md.Component != nil {
			b.bom.Dependencies = append(b.bom.Dependencies, cdxOutDep{Ref: md.Component.BOMRef, DependsOn: direct})
		}
		b.bom.Dependencies = append(b.bom.Dependencies, deps...)
	}

	// Vulnerabilities, one per id, in first-seen order.
	index := map[string]int{}
	for i := range r.Findings {
		src := &r.Findings[i]
		if src.Type != FindingTypeVulnerability && src.Vulnerability == nil {
			continue
		}
		if src.Type != FindingTypeVulnerability && src.Type != "" {
			continue
		}
		f, err := exportFinding(src)
		if err != nil {
			return nil, err
		}
		vid := cdxVulnID(&f)
		if vid == "" {
			continue
		}
		at, ok := index[vid]
		if !ok {
			at = len(b.bom.Vulnerabilities)
			index[vid] = at
			b.bom.Vulnerabilities = append(b.bom.Vulnerabilities, cdxVulnOf(&f, vid))
		}
		if ref := b.componentFor(f.Vulnerability); ref != "" {
			v := &b.bom.Vulnerabilities[at]
			if !cdxHasAffect(v.Affects, ref) {
				v.Affects = append(v.Affects, cdxOutAffect{Ref: ref, Versions: cdxVersionsOf(&f)})
			}
		}
	}
	return marshalExport(b.bom)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func cdxHasAffect(list []cdxOutAffect, ref string) bool {
	for _, a := range list {
		if a.Ref == ref {
			return true
		}
	}
	return false
}

// cdxVersionsOf reads back the affects versions the importer kept
// ("<range or version> (<status>)" per line), else the finding's affected
// version range.
func cdxVersionsOf(f *Finding) []cdxOutVersion {
	var out []cdxOutVersion
	if s := f.SourceExtra["affects_versions"]; s != "" {
		for _, l := range strings.Split(s, "\n") {
			l = strings.TrimSpace(l)
			if l == "" {
				continue
			}
			val, status := l, ""
			if i := strings.LastIndex(l, " ("); i > 0 && strings.HasSuffix(l, ")") {
				val, status = l[:i], l[i+2:len(l)-1]
			}
			v := cdxOutVersion{Status: status}
			if strings.HasPrefix(val, "vers:") {
				v.Range = val
			} else {
				v.Version = val
			}
			out = append(out, v)
		}
		return out
	}
	if v := f.Vulnerability; v != nil && v.AffectedVersionRange != "" {
		out = append(out, cdxOutVersion{Range: v.AffectedVersionRange, Status: "affected"})
	}
	return out
}

func cdxVulnOf(f *Finding, vid string) cdxOutVuln {
	out := cdxOutVuln{ID: vid}
	if f.Native != nil {
		out.BOMRef = f.Native.InstanceID
	}
	v := f.Vulnerability
	if v == nil {
		v = &VulnerabilityDetails{}
	}
	if ds := v.DataSource; ds != nil && (ds.Name != "" || ds.URL != "") {
		out.Source = &cdxOutSource{Name: ds.Name, URL: ds.URL}
	}
	seen := map[string]bool{strings.ToUpper(vid): true}
	for _, id := range v.IDs {
		if seen[strings.ToUpper(id.ID)] || len(out.References) >= MaxVulnerabilityIDs {
			continue
		}
		seen[strings.ToUpper(id.ID)] = true
		ref := cdxOutRef{ID: id.ID}
		if id.Source != "" {
			ref.Source = &cdxOutSource{Name: id.Source}
		}
		out.References = append(out.References, ref)
	}
	for _, id := range append([]string{v.CVEID}, v.CVEIDs...) {
		if id == "" || seen[strings.ToUpper(id)] || len(out.References) >= MaxVulnerabilityIDs {
			continue
		}
		seen[strings.ToUpper(id)] = true
		out.References = append(out.References, cdxOutRef{ID: id})
	}

	// Ratings from the scores; scores CycloneDX has no method for are kept
	// as properties.
	var props []cdxOutProperty
	for i := range f.Scores {
		if i >= MaxScores {
			break
		}
		s := &f.Scores[i]
		method, ok := cdxMethodOf(s)
		if !ok {
			if s.Value != nil {
				props = append(props, cdxOutProperty{Name: "ctis:score:" + string(s.System), Value: formatScore(*s.Value)})
			}
			continue
		}
		rt := cdxOutRating{Method: method, Vector: s.Vector}
		if s.Source != "" {
			rt.Source = &cdxOutSource{Name: s.Source}
		}
		if s.Value != nil && s.System != ScoreSystemSSVC {
			val := *s.Value
			rt.Score = &val
		}
		if l := strings.ToLower(s.Label); cdxRatingSeverities[l] {
			rt.Severity = l
		}
		rt.Justification = f.SourceExtra["rating_justification:"+cdxExtraKey(s.Source+":"+method)]
		out.Ratings = append(out.Ratings, rt)
	}
	if len(out.Ratings) == 0 && (v.CVSSScore > 0 || v.CVSSVector != "") {
		// Only the single legacy CVSS members.
		s := Score{System: ScoreSystemCVSS, Version: v.CVSSVersion, Vector: v.CVSSVector}
		if s.Version == "" {
			s.Version = CVSSVersionOfVector(v.CVSSVector)
		}
		method, _ := cdxMethodOf(&s)
		rt := cdxOutRating{Method: method, Vector: v.CVSSVector, Severity: cdxSeverityOf(f.Severity)}
		if v.CVSSScore > 0 {
			val := v.CVSSScore
			rt.Score = &val
		}
		if v.CVSSSource != "" {
			rt.Source = &cdxOutSource{Name: v.CVSSSource}
		}
		out.Ratings = append(out.Ratings, rt)
	}
	if len(out.Ratings) == 0 && f.SourceExtra["severity_note"] == "" && f.Severity.IsValid() {
		out.Ratings = []cdxOutRating{{Severity: cdxSeverityOf(f.Severity), Method: "other", Source: &cdxOutSource{Name: "ctis"}}}
	}

	cwes := v.CWEIDs
	if len(cwes) == 0 && v.CWEID != "" {
		cwes = []string{v.CWEID}
	}
	for _, c := range cwes {
		if n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(c)), "CWE-")); err == nil && n > 0 {
			out.CWEs = append(out.CWEs, n)
		}
	}

	// The importer joins description and detail; split them again.
	out.Description = f.Message
	switch {
	case f.Message == "":
		out.Description = f.Description
	case f.Description != f.Message:
		if d, ok := strings.CutPrefix(f.Description, f.Message+"\n\n"); ok {
			out.Detail = d
		} else {
			out.Detail = f.Description
		}
	}

	if rem := f.Remediation; rem != nil {
		out.Recommendation = rem.Recommendation
		for _, s := range rem.Steps {
			if w, ok := strings.CutPrefix(s, "Workaround: "); ok {
				out.Workaround = w
				break
			}
		}
		for _, a := range rem.Advisories {
			if a.URL != "" && len(out.Advisories) < MaxAdvisories {
				out.Advisories = append(out.Advisories, cdxOutAdvisory{Title: a.ID, URL: a.URL})
			}
		}
	}
	out.Published = formatTime(v.PublishedAt)
	out.Updated = formatTime(v.ModifiedAt)
	out.Created = f.SourceExtra["created"]
	out.Rejected = f.SourceExtra["rejected"]

	if x := f.VEX; x != nil {
		a := &cdxOutAnalysis{State: cdxStateOf(x.Status), Justification: cdxJustificationOf(x), Detail: x.Statement, LastUpdated: formatTime(x.AsOf)}
		if x.Status != VEXStatusNotAffected && x.NativeJustification == "" {
			a.Justification = ""
		}
		out.Analysis = a
	} else if f.Status == FindingStatusFalsePositive {
		out.Analysis = &cdxOutAnalysis{State: "false_positive"}
	}
	if out.Analysis != nil {
		if s := f.SourceExtra["analysis_response"]; s != "" {
			for _, r := range strings.Split(s, ",") {
				if r = strings.TrimSpace(r); r != "" {
					out.Analysis.Response = append(out.Analysis.Response, r)
				}
			}
		}
	}

	// References the importer did not derive from source or advisories.
	derived := map[string]bool{}
	if out.Source != nil {
		derived[out.Source.URL] = true
	}
	for _, a := range out.Advisories {
		derived[a.URL] = true
	}
	var extraRefs []string
	for _, r := range f.References {
		if !derived[r] {
			extraRefs = append(extraRefs, r)
		}
	}
	if len(extraRefs) > 0 {
		props = append(props, cdxOutProperty{Name: "ctis:references", Value: strings.Join(extraRefs, "\n")})
	}

	keys := make([]string, 0, len(f.SourceExtra))
	for k := range f.SourceExtra {
		if strings.HasPrefix(k, "property:") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		out.Properties = append(out.Properties, cdxOutProperty{Name: strings.TrimPrefix(k, "property:"), Value: f.SourceExtra[k]})
	}
	out.Properties = append(out.Properties, props...)
	return out
}

// cdxExtraKey bounds a source_extra key part the way the importer does
// (whitespace folded, at most 64 characters).
func cdxExtraKey(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 64 {
		return string(r[:64])
	}
	return s
}

func cdxSeverityOf(s Severity) string {
	if cdxRatingSeverities[string(s)] {
		return string(s)
	}
	return ""
}
