package importer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/openctemio/ctis"
)

// grype JSON output: the vulnerability matches of the packages found in an
// image, directory or SBOM. The mapping is spec_grype.go.

func init() {
	parsers[FormatGrype] = parseGrype
	tools[FormatGrype] = ctis.Tool{Name: "grype", Vendor: "Anchore", Capabilities: []string{"sca"}}
}

type grypeCVSS struct {
	Source  string `json:"source"`
	Type    string `json:"type"`
	Version string `json:"version"`
	Vector  string `json:"vector"`
	Metrics struct {
		BaseScore           *float64 `json:"baseScore"`
		ExploitabilityScore *float64 `json:"exploitabilityScore"`
		ImpactScore         *float64 `json:"impactScore"`
	} `json:"metrics"`
}

type grypeEPSS struct {
	CVE        string   `json:"cve"`
	EPSS       *float64 `json:"epss"`
	Percentile *float64 `json:"percentile"`
	Date       string   `json:"date"`
}

type grypeKEV struct {
	CVE                        string   `json:"cve"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	DateAdded                  string   `json:"dateAdded"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    string   `json:"dueDate"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
	Notes                      string   `json:"notes"`
	URLs                       []string `json:"urls"`
	CWEs                       []string `json:"cwes"`
}

type grypeVulnMeta struct {
	ID             string      `json:"id"`
	DataSource     string      `json:"dataSource"`
	Namespace      string      `json:"namespace"`
	Severity       string      `json:"severity"`
	URLs           []string    `json:"urls"`
	Description    string      `json:"description"`
	CVSS           []grypeCVSS `json:"cvss"`
	EPSS           []grypeEPSS `json:"epss"`
	KnownExploited []grypeKEV  `json:"knownExploited"`
}

type grypeMatch struct {
	Vulnerability struct {
		grypeVulnMeta
		Fix struct {
			Versions []string `json:"versions"`
			State    string   `json:"state"`
		} `json:"fix"`
		Advisories []struct {
			ID   string `json:"id"`
			Link string `json:"link"`
		} `json:"advisories"`
		Risk *float64 `json:"risk"`
	} `json:"vulnerability"`
	RelatedVulnerabilities []grypeVulnMeta `json:"relatedVulnerabilities"`
	MatchDetails           []struct {
		Type    string `json:"type"`
		Matcher string `json:"matcher"`
		Fix     struct {
			SuggestedVersion string `json:"suggestedVersion"`
		} `json:"fix"`
	} `json:"matchDetails"`
	Artifact grypeArtifact `json:"artifact"`
}

type grypeArtifact struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Type      string `json:"type"`
	Locations []struct {
		Path    string `json:"path"`
		LayerID string `json:"layerID"`
	} `json:"locations"`
	Language  string    `json:"language"`
	Licenses  []flexStr `json:"licenses"`
	CPEs      []string  `json:"cpes"`
	PURL      string    `json:"purl"`
	Upstreams []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"upstreams"`
}

type grypeTarget struct {
	UserInput      string   `json:"userInput"`
	ImageID        string   `json:"imageID"`
	ManifestDigest string   `json:"manifestDigest"`
	Tags           []string `json:"tags"`
	RepoDigests    []string `json:"repoDigests"`
	Architecture   string   `json:"architecture"`
	OS             string   `json:"os"`
	Path           string   `json:"path"`
}

type grypeOutput struct {
	Matches []json.RawMessage `json:"matches"`
	Source  struct {
		Type   string          `json:"type"`
		Target json.RawMessage `json:"target"`
	} `json:"source"`
	Distro struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"distro"`
	Descriptor struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Timestamp string `json:"timestamp"`
		DB        struct {
			Built         string  `json:"built"`
			SchemaVersion flexStr `json:"schemaVersion"`
		} `json:"db"`
	} `json:"descriptor"`
}

const grypeM = "/matches[]"

func parseGrype(b *builder, r io.Reader) error {
	data, err := readAll(r, FormatGrype, b.lim)
	if err != nil {
		return err
	}
	doc, err := scanJSON(data, FormatGrype, b.lim, b.obs, grypeM)
	if err != nil {
		return err
	}
	var out grypeOutput
	if err := doc.decode(&out); err != nil {
		return err
	}
	if out.Matches == nil {
		return &ParseError{Format: FormatGrype, Msg: "no matches array", Err: ErrMalformed}
	}
	if v := line(out.Descriptor.Version, 64); v != "" && b.res.Report.Tool != nil {
		b.res.Report.Tool.Version = v
	}
	props := ctis.Properties{}
	if v := line(out.Descriptor.DB.Built, 64); v != "" {
		props["grype_db_built"] = v
	}
	if v := line(out.Descriptor.DB.SchemaVersion.String(), 32); v != "" {
		props["grype_db_schema"] = v
	}
	if t := parseTime(out.Descriptor.Timestamp); t != nil {
		props["generated_at"] = t.Format("2006-01-02T15:04:05Z07:00")
	}
	if len(props) > 0 {
		b.res.Report.Metadata.Properties = props
	}

	asset := b.grypeAsset(out.Source.Type, out.Source.Target, out.Distro.Name, out.Distro.Version)
	var assetID string
	depIDs := map[string]bool{}
	for i, raw := range out.Matches {
		b.res.Stats.Records++
		if err := b.tick(); err != nil {
			return err
		}
		ptr := fmt.Sprintf("/matches/%d", i)
		var m grypeMatch
		if err := json.Unmarshal(raw, &m); err != nil {
			b.issue(doc.issueAt(grypeM, i, ptr, "skipped: "+jsonErrText(err)))
			b.res.Stats.Skipped++
			continue
		}
		vid := strings.TrimSpace(m.Vulnerability.ID)
		pkg := line(m.Artifact.Name, capShort)
		if vid == "" || pkg == "" {
			b.issue(doc.issueAt(grypeM, i, ptr, "match without a vulnerability id or a package name: skipped"))
			b.res.Stats.Skipped++
			continue
		}
		if assetID == "" {
			if assetID, err = b.asset(asset); err != nil {
				return err
			}
		}
		dep := grypeDependency(&m.Artifact)
		if !depIDs[dep.ID] {
			depIDs[dep.ID] = true
			if err := b.dependency(dep); err != nil {
				return err
			}
		}
		if err := b.finding(b.grypeFinding(&m, vid, assetID, ptr, i, doc)); err != nil {
			return err
		}
	}
	return nil
}

// grypeAsset is the scanned source: an image is a container asset named by
// the image reference, a directory or file a repository-like asset named by
// its path, an SBOM unclassified.
func (b *builder) grypeAsset(kind string, target json.RawMessage, distro, distroVersion string) ctis.Asset {
	if a := b.opts.DefaultAsset; a != nil && a.Value != "" {
		return b.defaultAsset()
	}
	var t grypeTarget
	target = bytes.TrimSpace(target)
	if len(target) > 0 && target[0] == '"' {
		var s string
		_ = json.Unmarshal(target, &s)
		t.Path = s
	} else if len(target) > 0 && target[0] == '{' {
		_ = json.Unmarshal(target, &t)
	}
	kind = strings.ToLower(strings.TrimSpace(kind))
	value := line(firstNonEmpty(t.UserInput, t.Path), capShort)
	typ := ctis.AssetTypeRepository
	switch kind {
	case "image":
		typ = ctis.AssetTypeContainer
	case "sbom", "":
		typ = ctis.AssetTypeUnclassified
	}
	if value == "" {
		value = "grype-" + firstNonEmpty(kind, "scan")
	}
	a := ctis.Asset{ID: "grype-" + value, Type: typ, Value: value, Name: value}
	p := ctis.Properties{}
	set := func(k, v string) {
		if v = line(v, capShort); v != "" {
			p[k] = v
		}
	}
	set("source_type", kind)
	set("image_id", t.ImageID)
	set("manifest_digest", t.ManifestDigest)
	set("architecture", t.Architecture)
	set("os", t.OS)
	if len(t.RepoDigests) > 0 {
		set("repo_digest", t.RepoDigests[0])
	}
	if len(t.Tags) > 0 {
		set("image_tag", t.Tags[0])
	}
	if distro != "" {
		set("distro", strings.TrimSpace(distro+" "+distroVersion))
	}
	if len(p) > 0 {
		a.Properties = p
	}
	return a
}

func grypeDependency(a *grypeArtifact) ctis.Dependency {
	name := line(a.Name, capShort)
	version := line(a.Version, capShort)
	purl := cleanPURL(a.PURL)
	id := line(firstNonEmpty(a.ID, purl, nameVersion(name, version)), capShort)
	d := ctis.Dependency{ID: id, Name: name, Version: version, PURL: purl, Type: line(a.Type, 32)}
	if e := vulnEcosystem(firstNonEmpty(purlType(purl), a.Language, a.Type)); e != "" {
		d.Ecosystem = e
	}
	for _, l := range a.Licenses {
		if v := line(l.String(), capShort); v != "" && len(d.Licenses) < 16 {
			d.Licenses = appendUnique(d.Licenses, v)
		}
	}
	if len(a.Locations) > 0 {
		d.Path = line(a.Locations[0].Path, 1024)
		addDepProperty(&d, "layer_id", a.Locations[0].LayerID)
	}
	if len(a.CPEs) > 0 {
		addDepProperty(&d, "cpe", a.CPEs[0])
	}
	if len(a.Upstreams) > 0 {
		addDepProperty(&d, "upstream", nameVersion(a.Upstreams[0].Name, a.Upstreams[0].Version))
	}
	addDepProperty(&d, "language", a.Language)
	return d
}

func (b *builder) grypeFinding(m *grypeMatch, vid, assetID, ptr string, i int, doc *jsonDoc) ctis.Finding {
	v := &m.Vulnerability
	art := &m.Artifact
	pkg := line(art.Name, capShort)
	version := line(art.Version, capShort)
	f := ctis.Finding{
		Type:        ctis.FindingTypeVulnerability,
		Title:       line(vid+" in "+nameVersion(pkg, version), capTitle),
		AssetRef:    assetID,
		RuleID:      line(vid, capShort),
		Description: text(v.Description, capDescription),
		Native: &ctis.NativeIdentity{
			Scheme:   ctis.NativeSchemeOther,
			VulnID:   line(vid, ctis.MaxNativeIDLen),
			Family:   line(v.Namespace, ctis.MaxNativeIDLen),
			Severity: line(v.Severity, ctis.MaxNativeValueLen),
			RawRef:   ptr,
		},
	}
	vuln := &ctis.VulnerabilityDetails{
		Package:         pkg,
		AffectedVersion: version,
		PURL:            cleanPURL(art.PURL),
	}
	if e := vulnEcosystem(firstNonEmpty(purlType(vuln.PURL), art.Language, art.Type)); e != "" {
		vuln.Ecosystem = e
	}
	if len(art.CPEs) > 0 {
		vuln.CPE = line(art.CPEs[0], capShort)
	}
	addVulnID(vuln, vid)
	metas := append([]grypeVulnMeta{v.grypeVulnMeta}, m.RelatedVulnerabilities...)
	for k, meta := range metas {
		if k > 0 {
			addVulnID(vuln, meta.ID)
			if f.Description == "" {
				f.Description = text(meta.Description, capDescription)
			}
		}
		for _, c := range meta.CVSS {
			s, ok := cvssVectorScore(c.Vector, grypeSource(c.Source, meta.Namespace))
			if !ok {
				continue
			}
			if c.Metrics.BaseScore != nil && *c.Metrics.BaseScore >= 0 && *c.Metrics.BaseScore <= 10 {
				vc := *c.Metrics.BaseScore
				s.Value = &vc
			}
			addScore(&f, s)
		}
		for _, e := range meta.EPSS {
			if e.EPSS != nil && *e.EPSS >= 0 && *e.EPSS <= 1 {
				vc := *e.EPSS
				addScore(&f, ctis.Score{System: ctis.ScoreSystemEPSS, Value: &vc, Source: "first", AsOf: parseTime(e.Date)})
				if vc > vuln.EPSSScore {
					vuln.EPSSScore = vc
				}
			}
			if e.Percentile != nil && *e.Percentile >= 0 && *e.Percentile <= 1 {
				vc := *e.Percentile
				addScore(&f, ctis.Score{System: ctis.ScoreSystemEPSSPercentile, Value: &vc, Source: "first", AsOf: parseTime(e.Date)})
				if vc > vuln.EPSSPercentile {
					vuln.EPSSPercentile = vc
				}
			}
		}
		for _, kev := range meta.KnownExploited {
			vuln.InCISAKEV = true
			vuln.ExploitAvailable = true
			for _, c := range kev.CWEs {
				if c = strings.ToUpper(strings.TrimSpace(c)); strings.HasPrefix(c, "CWE-") && len(c) <= 16 {
					vuln.CWEIDs = appendUnique(vuln.CWEIDs, c)
				}
			}
			extras(&f, "kev_date_added", kev.DateAdded, "kev_due_date", kev.DueDate,
				"kev_required_action", kev.RequiredAction, "kev_ransomware_use", kev.KnownRansomwareCampaignUse,
				"kev_notes", kev.Notes, "kev_vendor_product", strings.TrimSpace(kev.VendorProject+" "+kev.Product))
			for _, u := range kev.URLs {
				if validURL(u) {
					f.References = addRefs(f.References, u)
				}
			}
		}
		for _, u := range meta.URLs {
			if validURL(u) {
				f.References = addRefs(f.References, u)
			}
		}
		if validURL(meta.DataSource) {
			f.References = addRefs(f.References, meta.DataSource)
		}
	}
	if len(vuln.CWEIDs) > 0 {
		vuln.CWEID = vuln.CWEIDs[0]
	}
	f.Vulnerability = vuln
	setLegacyCVSS(&f)

	sev, ok := severityWord(v.Severity)
	if !ok {
		best := -1.0
		for _, s := range f.Scores {
			if s.System == ctis.ScoreSystemCVSS && s.Value != nil && *s.Value > best {
				best = *s.Value
			}
		}
		if best >= 0 {
			sev = severityFromCVSS(best)
		} else {
			sev = ctis.SeverityMedium
			b.issue(doc.issueAt(grypeM, i, ptr, fmt.Sprintf("unknown severity %q and no CVSS score, kept as medium", line(v.Severity, 32))))
		}
	}
	f.Severity = sev

	for _, fv := range v.Fix.Versions {
		if fv = line(fv, 128); fv != "" && len(vuln.FixedVersions) < 16 {
			vuln.FixedVersions = appendUnique(vuln.FixedVersions, fv)
		}
	}
	if len(vuln.FixedVersions) > 0 {
		vuln.FixedVersion = vuln.FixedVersions[0]
	}
	rem := &ctis.Remediation{}
	switch strings.ToLower(strings.TrimSpace(v.Fix.State)) {
	case "fixed":
		rem.FixAvailable = true
		rem.SolutionType = ctis.SolutionTypeUpgrade
		if vuln.FixedVersion != "" {
			rem.Recommendation = "Upgrade " + pkg + " to " + strings.Join(vuln.FixedVersions, " or ") + "."
		}
	case "wont-fix":
		rem.SolutionType = ctis.SolutionTypeNoFix
	}
	for _, a := range v.Advisories {
		addAdvisoryURL(rem, a.ID, a.Link)
	}
	if rem.FixAvailable || rem.SolutionType != "" || len(rem.Advisories) > 0 {
		f.Remediation = rem
	}
	if v.Risk != nil && *v.Risk >= 0 && *v.Risk <= 1e6 {
		vc := *v.Risk
		addScore(&f, ctis.Score{System: ctis.ScoreSystemVendor, Value: &vc, Label: "risk", Source: "grype"})
	}
	if len(art.Locations) > 0 {
		if p := line(art.Locations[0].Path, 1024); p != "" {
			f.Location = &ctis.FindingLocation{Path: p}
		}
	}
	extras(&f, "fix_state", v.Fix.State, "namespace", v.Namespace)
	if len(m.MatchDetails) > 0 {
		md := m.MatchDetails[0]
		extras(&f, "match_type", md.Type, "matcher", md.Matcher, "suggested_version", md.Fix.SuggestedVersion)
	}
	return f
}

// grypeSource names who scored a CVSS entry: the source host
// ("nvd@nist.gov" is nvd), else the namespace's feed.
func grypeSource(source, namespace string) string {
	s := strings.ToLower(strings.TrimSpace(source))
	switch {
	case strings.Contains(s, "nvd"):
		return "nvd"
	case strings.Contains(s, "github") || strings.Contains(s, "ghsa"):
		return "ghsa"
	case s != "":
		return line(s, ctis.MaxScoreSourceLen)
	}
	if ns, _, ok := strings.Cut(strings.ToLower(namespace), ":"); ok && ns != "" {
		return line(ns, ctis.MaxScoreSourceLen)
	}
	return "vendor"
}

// addAdvisoryURL adds an advisory with an http(s) link.
func addAdvisoryURL(rem *ctis.Remediation, id, link string) {
	id = line(id, ctis.MaxVulnerabilityIDLen)
	if !validURL(link) {
		link = ""
	}
	if id == "" && link == "" || len(rem.Advisories) >= ctis.MaxAdvisories {
		return
	}
	rem.Advisories = append(rem.Advisories, ctis.Advisory{ID: id, URL: line(link, ctis.MaxAdvisoryURLLen)})
}
