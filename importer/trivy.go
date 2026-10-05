package importer

import (
	"io"
	"sort"
	"strings"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/fingerprint"
)

// trivy JSON (trivy image|fs|repo|config --format json). The mapping is
// spec_trivy.go.

func init() {
	parsers[FormatTrivy] = parseTrivy
	tools[FormatTrivy] = ctis.Tool{Name: "trivy", Vendor: "Aqua Security", Capabilities: []string{"sca", "misconfiguration", "secret"}}
}

type trivyCVSS struct {
	V2Vector  string  `json:"V2Vector"`
	V3Vector  string  `json:"V3Vector"`
	V40Vector string  `json:"V40Vector"`
	V2Score   float64 `json:"V2Score"`
	V3Score   float64 `json:"V3Score"`
	V40Score  float64 `json:"V40Score"`
}

type trivyVuln struct {
	VulnerabilityID  string               `json:"VulnerabilityID"`
	VendorIDs        []string             `json:"VendorIDs"`
	PkgID            string               `json:"PkgID"`
	PkgName          string               `json:"PkgName"`
	PkgPath          string               `json:"PkgPath"`
	PkgIdentifier    *trivyPkgID          `json:"PkgIdentifier"`
	InstalledVersion string               `json:"InstalledVersion"`
	FixedVersion     string               `json:"FixedVersion"`
	Status           string               `json:"Status"`
	SeveritySource   string               `json:"SeveritySource"`
	Severity         string               `json:"Severity"`
	VendorSeverity   map[string]int       `json:"VendorSeverity"`
	Title            string               `json:"Title"`
	Description      string               `json:"Description"`
	PrimaryURL       string               `json:"PrimaryURL"`
	DataSource       *ctis.VulnDataSource `json:"DataSource"`
	CVSS             map[string]trivyCVSS `json:"CVSS"`
	CweIDs           []string             `json:"CweIDs"`
	References       []string             `json:"References"`
	PublishedDate    string               `json:"PublishedDate"`
	LastModifiedDate string               `json:"LastModifiedDate"`
	Layer            *struct {
		Digest string `json:"Digest"`
		DiffID string `json:"DiffID"`
	} `json:"Layer"`
}

type trivyPkgID struct {
	PURL string `json:"PURL"`
	UID  string `json:"UID"`
}

type trivyMisconf struct {
	Type          string   `json:"Type"`
	ID            string   `json:"ID"`
	AVDID         string   `json:"AVDID"`
	Title         string   `json:"Title"`
	Description   string   `json:"Description"`
	Message       string   `json:"Message"`
	Namespace     string   `json:"Namespace"`
	Query         string   `json:"Query"`
	Resolution    string   `json:"Resolution"`
	Severity      string   `json:"Severity"`
	PrimaryURL    string   `json:"PrimaryURL"`
	References    []string `json:"References"`
	Status        string   `json:"Status"`
	CauseMetadata *struct {
		Resource  string `json:"Resource"`
		Provider  string `json:"Provider"`
		Service   string `json:"Service"`
		StartLine int    `json:"StartLine"`
		EndLine   int    `json:"EndLine"`
	} `json:"CauseMetadata"`
}

type trivySecret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Match     string `json:"Match"`
}

type trivyPackage struct {
	ID           string      `json:"ID"`
	Name         string      `json:"Name"`
	Version      string      `json:"Version"`
	Identifier   *trivyPkgID `json:"Identifier"`
	Licenses     []string    `json:"Licenses"`
	DependsOn    []string    `json:"DependsOn"`
	Relationship string      `json:"Relationship"`
}

type trivyResult struct {
	Target            string         `json:"Target"`
	Class             string         `json:"Class"`
	Type              string         `json:"Type"`
	Packages          []trivyPackage `json:"Packages"`
	Vulnerabilities   []trivyVuln    `json:"Vulnerabilities"`
	Misconfigurations []trivyMisconf `json:"Misconfigurations"`
	Secrets           []trivySecret  `json:"Secrets"`
}

type trivyReport struct {
	SchemaVersion int    `json:"SchemaVersion"`
	CreatedAt     string `json:"CreatedAt"`
	ArtifactName  string `json:"ArtifactName"`
	ArtifactType  string `json:"ArtifactType"`
	Metadata      *struct {
		OS *struct {
			Family string `json:"Family"`
			Name   string `json:"Name"`
		} `json:"OS"`
		ImageID     string   `json:"ImageID"`
		RepoDigests []string `json:"RepoDigests"`
		RepoTags    []string `json:"RepoTags"`
	} `json:"Metadata"`
	Results []trivyResult `json:"Results"`
}

func parseTrivy(b *builder, r io.Reader) error {
	data, err := readAll(r, FormatTrivy, b.lim)
	if err != nil {
		return err
	}
	doc, err := scanJSON(data, FormatTrivy, b.lim, b.obs, "/Results[]")
	if err != nil {
		return err
	}
	var rep trivyReport
	if err := doc.decode(&rep); err != nil {
		return err
	}
	for ri := range rep.Results {
		res := &rep.Results[ri]
		target := line(res.Target, 1024)
		for i := range res.Packages {
			if err := b.trivyPackage(&res.Packages[i]); err != nil {
				return err
			}
		}
		for i := range res.Vulnerabilities {
			if err := b.trivyRecord(trivyVulnFinding(&res.Vulnerabilities[i], target)); err != nil {
				return err
			}
		}
		for i := range res.Misconfigurations {
			if err := b.trivyRecord(trivyMisconfFinding(&res.Misconfigurations[i], target)); err != nil {
				return err
			}
		}
		for i := range res.Secrets {
			if err := b.trivyRecord(trivySecretFinding(&res.Secrets[i], target)); err != nil {
				return err
			}
		}
	}
	if len(b.res.Report.Findings) == 0 && len(b.res.Report.Dependencies) == 0 && b.opts.Repository == "" {
		return nil
	}
	a := b.codeAsset(trivyArtifact(&rep))
	return b.bindAll(a)
}

func (b *builder) trivyRecord(f ctis.Finding, ok bool) error {
	b.res.Stats.Records++
	if err := b.tick(); err != nil {
		return err
	}
	if !ok {
		b.res.Stats.Skipped++
		b.issue(Issue{Path: "/Results", Message: "record without an id: skipped"})
		return nil
	}
	return b.finding(f)
}

func (b *builder) trivyPackage(p *trivyPackage) error {
	name := line(p.Name, capShort)
	if name == "" {
		return nil
	}
	d := ctis.Dependency{Name: name, Version: line(p.Version, 128), ID: line(p.ID, capShort), Relationship: line(strings.ToLower(p.Relationship), 32)}
	if p.Identifier != nil {
		d.PURL = sanePURL(p.Identifier.PURL)
		d.UID = line(p.Identifier.UID, capShort)
	}
	for _, l := range p.Licenses {
		if len(d.Licenses) < 20 {
			d.Licenses = append(d.Licenses, line(l, 128))
		}
	}
	for _, on := range p.DependsOn {
		if len(d.DependsOn) < 500 {
			d.DependsOn = append(d.DependsOn, line(on, capShort))
		}
	}
	return b.dependency(d)
}

// sanePURL keeps a package URL without control characters or spaces.
func sanePURL(p string) string {
	p = strings.TrimSpace(p)
	if !strings.HasPrefix(p, "pkg:") || len(p) > 2048 || strings.ContainsFunc(p, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return ""
	}
	return p
}

// trivyArtifact is the asset trivy names: the image of an image scan, the
// repository of a repository scan. A file-system scan names a local path,
// which is no asset.
func trivyArtifact(rep *trivyReport) *ctis.Asset {
	name := line(rep.ArtifactName, capShort)
	if name == "" {
		return nil
	}
	switch rep.ArtifactType {
	case "container_image":
		a := ctis.Asset{ID: codeAssetID, Type: ctis.AssetTypeContainer, Value: name, Name: name, Properties: ctis.Properties{"source": "trivy_artifact"}}
		if m := rep.Metadata; m != nil {
			if m.ImageID != "" {
				a.Properties["image_id"] = line(m.ImageID, capShort)
			}
			if m.OS != nil && m.OS.Family != "" {
				a.Properties["os"] = line(strings.TrimSpace(m.OS.Family+" "+m.OS.Name), capShort)
			}
			if len(m.RepoDigests) > 0 {
				a.Properties["repo_digest"] = line(m.RepoDigests[0], capShort)
			}
		}
		return &a
	case "repository":
		a := repoAsset(name, "", "", "trivy_artifact")
		return &a
	}
	return nil
}

func trivySeverity(s string) ctis.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return ctis.SeverityCritical
	case "HIGH":
		return ctis.SeverityHigh
	case "MEDIUM":
		return ctis.SeverityMedium
	case "LOW":
		return ctis.SeverityLow
	case "UNKNOWN":
		return ctis.SeverityInfo
	}
	return ctis.SeverityMedium
}

func trivyVulnFinding(v *trivyVuln, target string) (ctis.Finding, bool) {
	id := line(v.VulnerabilityID, capShort)
	if id == "" {
		return ctis.Finding{}, false
	}
	pkg := line(v.PkgName, capShort)
	title := line(v.Title, capTitle)
	if title == "" {
		title = line(id+" in "+pkg, capTitle)
	}
	f := ctis.Finding{
		Type:        ctis.FindingTypeVulnerability,
		Title:       title,
		Description: text(v.Description, capDescription),
		Severity:    trivySeverity(v.Severity),
		RuleID:      id,
		Native:      &ctis.NativeIdentity{Scheme: ctis.NativeSchemeOther, VulnID: id, Severity: line(v.Severity, ctis.MaxNativeValueLen)},
	}
	vd := &ctis.VulnerabilityDetails{
		Package:         pkg,
		AffectedVersion: line(v.InstalledVersion, 128),
		FixedVersion:    line(v.FixedVersion, 256),
		VulnStatus:      line(v.Status, 32),
		SeveritySource:  line(v.SeveritySource, 64),
		PublishedAt:     parseTime(v.PublishedDate),
		ModifiedAt:      parseTime(v.LastModifiedDate),
	}
	addVulnID(vd, id)
	for _, vid := range v.VendorIDs {
		addVendorID(vd, vid, "")
	}
	for _, c := range v.CweIDs {
		if cw := cweID(c); cw != "" {
			vd.CWEIDs = appendUnique(vd.CWEIDs, cw)
		}
	}
	if len(vd.CWEIDs) > 0 {
		vd.CWEID = vd.CWEIDs[0]
	}
	if v.PkgIdentifier != nil {
		vd.PURL = sanePURL(v.PkgIdentifier.PURL)
	}
	if v.DataSource != nil {
		vd.DataSource = &ctis.VulnDataSource{ID: line(v.DataSource.ID, 64), Name: line(v.DataSource.Name, capShort), URL: line(v.DataSource.URL, capReference)}
	}
	if len(v.VendorSeverity) > 0 {
		vd.VendorSeverity = map[string]int{}
		for _, k := range sortedKeysOf(v.VendorSeverity) {
			if len(vd.VendorSeverity) < 32 {
				vd.VendorSeverity[line(k, 64)] = v.VendorSeverity[k]
			}
		}
	}
	// Every source's CVSS goes to scores; the legacy members take the
	// highest v3 score (nvd first on a tie), else v2.
	var bestScore float64
	for _, src := range sortedKeysOf(v.CVSS) {
		c := v.CVSS[src]
		for _, s := range []struct {
			ver, vec string
			val      float64
		}{{"4.0", c.V40Vector, c.V40Score}, {"", c.V3Vector, c.V3Score}, {"2.0", c.V2Vector, c.V2Score}} {
			if s.val <= 0 && s.vec == "" {
				continue
			}
			ver := s.ver
			if ver == "" {
				ver = ctis.CVSSVersionOfVector(s.vec)
				if ver == "" {
					ver = "3.1"
				}
			}
			sc := ctis.Score{System: ctis.ScoreSystemCVSS, Version: ver, Vector: line(s.vec, ctis.MaxScoreVectorLen), Source: line(src, ctis.MaxScoreSourceLen)}
			if s.val > 0 && s.val <= 10 {
				val := s.val
				sc.Value = &val
			}
			addScore(&f, sc)
		}
		if c.V3Score <= 10 && (c.V3Score > bestScore || (c.V3Score == bestScore && src == "nvd" && c.V3Score > 0)) {
			bestScore = c.V3Score
			vd.CVSSScore, vd.CVSSVector, vd.CVSSVersion, vd.CVSSSource = c.V3Score, line(c.V3Vector, ctis.MaxScoreVectorLen), "3.1", trivyCVSSSource(src)
			if ver := ctis.CVSSVersionOfVector(c.V3Vector); ver != "" {
				vd.CVSSVersion = ver
			}
		}
	}
	if bestScore == 0 {
		for _, src := range sortedKeysOf(v.CVSS) {
			if c := v.CVSS[src]; c.V2Score > 0 && c.V2Score <= 10 {
				vd.CVSSScore, vd.CVSSVector, vd.CVSSVersion, vd.CVSSSource = c.V2Score, line(c.V2Vector, ctis.MaxScoreVectorLen), "2.0", trivyCVSSSource(src)
				break
			}
		}
	}
	if v.Layer != nil && (v.Layer.Digest != "" || v.Layer.DiffID != "") {
		vd.Layer = &ctis.ContainerLayer{Digest: line(v.Layer.Digest, capShort), DiffID: line(v.Layer.DiffID, capShort)}
	}
	f.Vulnerability = vd
	f.References = addRefs(f.References, v.PrimaryURL)
	f.References = addRefs(f.References, v.References...)
	if p := line(v.PkgPath, 1024); p != "" {
		f.Location = &ctis.FindingLocation{Path: p}
	}
	f.Fingerprint = fingerprint.GenerateSCA(v.PkgName, v.InstalledVersion, v.VulnerabilityID)
	f.Tags = addTags(nil, "trivy", target)
	if vd.FixedVersion != "" {
		f.Remediation = &ctis.Remediation{FixAvailable: true, SolutionType: ctis.SolutionTypeUpgrade, Recommendation: line("Upgrade "+pkg+" to "+vd.FixedVersion, capRemediation)}
	}
	extras(&f, "pkg_id", v.PkgID, "target", target)
	return f, true
}

// trivyCVSSSource keeps the CTIS cvss_source words and calls every other
// source vendor.
func trivyCVSSSource(src string) string {
	switch src {
	case "nvd", "ghsa", "redhat", "bitnami":
		return src
	}
	return "vendor"
}

func trivyMisconfFinding(m *trivyMisconf, target string) (ctis.Finding, bool) {
	id := line(m.ID, capShort)
	if id == "" {
		id = line(m.AVDID, capShort)
	}
	if id == "" {
		return ctis.Finding{}, false
	}
	title := line(m.Title, capTitle)
	if title == "" {
		title = id
	}
	f := ctis.Finding{
		Type:        ctis.FindingTypeMisconfiguration,
		Title:       title,
		Description: text(m.Description, capDescription),
		Message:     line(m.Message, 8<<10),
		Severity:    trivySeverity(m.Severity),
		RuleID:      id,
		Misconfiguration: &ctis.MisconfigurationDetails{
			PolicyID:   id,
			PolicyName: title,
			AVDID:      line(m.AVDID, 64),
			Namespace:  line(m.Namespace, capShort),
			Query:      line(m.Query, 1024),
		},
		Native: &ctis.NativeIdentity{Scheme: ctis.NativeSchemeOther, VulnID: id, Severity: line(m.Severity, ctis.MaxNativeValueLen), Status: line(m.Status, ctis.MaxNativeValueLen)},
	}
	start := 0
	if c := m.CauseMetadata; c != nil {
		f.Misconfiguration.Provider = line(c.Provider, capShort)
		f.Misconfiguration.Service = line(c.Service, capShort)
		f.Misconfiguration.ResourceName = line(c.Resource, capShort)
		if c.StartLine > 0 {
			start = c.StartLine
			f.Location = &ctis.FindingLocation{Path: target, StartLine: c.StartLine, EndLine: nonNeg(c.EndLine)}
		}
	}
	if r := text(m.Resolution, capRemediation); r != "" {
		f.Remediation = &ctis.Remediation{Recommendation: r, SolutionType: ctis.SolutionTypeConfig}
	}
	f.References = addRefs(f.References, m.PrimaryURL)
	f.References = addRefs(f.References, m.References...)
	f.Fingerprint = fingerprint.GenerateSAST(target, m.ID, start, 0)
	f.Tags = addTags(nil, "trivy", "misconfiguration", target)
	extras(&f, "misconfig_type", m.Type, "target", target)
	return f, true
}

func trivySecretFinding(s *trivySecret, target string) (ctis.Finding, bool) {
	rule := line(s.RuleID, capShort)
	if rule == "" {
		return ctis.Finding{}, false
	}
	title := line(s.Title, capTitle)
	if title == "" {
		title = rule
	}
	f := ctis.Finding{
		Type:     ctis.FindingTypeSecret,
		Title:    title,
		Severity: trivySeverity(s.Severity),
		RuleID:   rule,
		Secret:   &ctis.SecretDetails{SecretType: trivySecretType(s.Category, rule)},
		Native:   &ctis.NativeIdentity{Scheme: ctis.NativeSchemeOther, VulnID: rule, Severity: line(s.Severity, ctis.MaxNativeValueLen)},
	}
	if s.StartLine > 0 {
		f.Location = &ctis.FindingLocation{Path: target, StartLine: s.StartLine, EndLine: nonNeg(s.EndLine)}
		// trivy masks the secret in Match itself; mask the line again,
		// in case a run turned that off.
		if s.Match != "" && !isMasked(s.Match) {
			f.Location.Snippet = ctis.MaskSecretMatch(s.Match)
		} else if s.Match != "" {
			f.Location.Snippet = line(s.Match, 16<<10)
		}
	}
	f.Fingerprint = fingerprint.GenerateSecret(target, s.RuleID, s.StartLine, fingerprintMask(s.Match))
	f.Tags = addTags(nil, "trivy", "secret", target)
	extra(&f, "category", s.Category)
	return f, true
}

// trivySecretType names the CTIS secret type of a trivy secret from its
// category, else from its rule id.
func trivySecretType(category, rule string) string {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "aws":
		return "aws_key"
	case "gcp", "google":
		return "gcp_key"
	case "azure":
		return "azure_key"
	case "github", "gitlab", "slack":
		return "token"
	case "asymmetricprivatekey", "privatekey":
		return "private_key"
	case "jwt":
		return "jwt"
	}
	return leakSecretType(rule)
}

// isMasked reports whether trivy already masked the secret in a match line
// (it replaces the secret with asterisks).
func isMasked(s string) bool { return strings.Contains(s, "****") }

func sortedKeysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
