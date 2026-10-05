package importer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/ctis"
)

// osv-scanner JSON results: the packages found in each scanned source
// (lockfile, SBOM, directory, image) with the OSV records of their
// vulnerabilities. The mapping is spec_osv.go.

func init() {
	parsers[FormatOSV] = parseOSV
	tools[FormatOSV] = ctis.Tool{Name: "osv-scanner", Capabilities: []string{"sca"}}
}

type osvOutput struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"source"`
		Packages []osvPackage `json:"packages"`
	} `json:"results"`
}

type osvPackage struct {
	Package struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Ecosystem string `json:"ecosystem"`
		PURL      string `json:"purl"`
		Commit    string `json:"commit"`
	} `json:"package"`
	DependencyGroups []string    `json:"dependency_groups"`
	Licenses         []string    `json:"licenses"`
	Vulnerabilities  []osvRecord `json:"vulnerabilities"`
	Groups           []struct {
		IDs         []string `json:"ids"`
		Aliases     []string `json:"aliases"`
		MaxSeverity string   `json:"max_severity"`
	} `json:"groups"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvRecord struct {
	ID        string        `json:"id"`
	Modified  string        `json:"modified"`
	Published string        `json:"published"`
	Withdrawn string        `json:"withdrawn"`
	Aliases   []string      `json:"aliases"`
	Related   []string      `json:"related"`
	Upstream  []string      `json:"upstream"`
	Summary   string        `json:"summary"`
	Details   string        `json:"details"`
	Severity  []osvSeverity `json:"severity"`
	Affected  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			PURL      string `json:"purl"`
		} `json:"package"`
		Severity []osvSeverity `json:"severity"`
		Ranges   []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
				Limit        string `json:"limit"`
			} `json:"events"`
		} `json:"ranges"`
		EcosystemSpecific json.RawMessage `json:"ecosystem_specific"`
		DatabaseSpecific  json.RawMessage `json:"database_specific"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
}

func parseOSV(b *builder, r io.Reader) error {
	data, err := readAll(r, FormatOSV, b.lim)
	if err != nil {
		return err
	}
	doc, err := scanJSON(data, FormatOSV, b.lim, b.obs, "/results[]/packages[]")
	if err != nil {
		return err
	}
	var out osvOutput
	if err := doc.decode(&out); err != nil {
		return err
	}
	pkgIdx := -1
	depIDs := map[string]bool{}
	for ri := range out.Results {
		res := &out.Results[ri]
		label := line(res.Source.Path, capShort)
		if label == "" {
			label = "osv-scanner"
		}
		assetID := ""
		for pi := range res.Packages {
			pkgIdx++
			if err := b.tick(); err != nil {
				return err
			}
			p := &res.Packages[pi]
			ptr := fmt.Sprintf("/results/%d/packages/%d", ri, pi)
			name := line(p.Package.Name, capShort)
			if name == "" {
				b.issue(doc.issueAt("/results[]/packages[]", pkgIdx, ptr, "package without a name: skipped"))
				b.res.Stats.Skipped += max(len(p.Groups), len(p.Vulnerabilities))
				continue
			}
			if assetID == "" {
				a := ctis.Asset{ID: "osv-" + label, Type: ctis.AssetTypeRepository, Value: label, Name: label}
				if t := line(res.Source.Type, 32); t != "" {
					a.Properties = ctis.Properties{"source_type": t}
				}
				if assetID, err = b.asset(a); err != nil {
					return err
				}
			}
			dep := osvDependency(p, label)
			if !depIDs[dep.ID] {
				depIDs[dep.ID] = true
				if err := b.dependency(dep); err != nil {
					return err
				}
			}
			if err := b.osvFindings(doc, p, assetID, label, pkgIdx, ptr); err != nil {
				return err
			}
		}
	}
	return nil
}

func osvDependency(p *osvPackage, label string) ctis.Dependency {
	name := line(p.Package.Name, capShort)
	version := line(p.Package.Version, capShort)
	eco := line(p.Package.Ecosystem, 32)
	purl := cleanPURL(p.Package.PURL)
	key := purl
	if key == "" {
		key = eco + ":" + nameVersion(name, version)
	}
	d := ctis.Dependency{ID: line(label+"|"+key, capShort*2), Name: name, Version: version, PURL: purl, Path: label}
	if e := vulnEcosystem(eco); e != "" {
		d.Ecosystem = e
	} else {
		d.Ecosystem = strings.ToLower(eco)
	}
	for _, l := range p.Licenses {
		if l = line(l, capShort); l != "" && len(d.Licenses) < 16 {
			d.Licenses = appendUnique(d.Licenses, l)
		}
	}
	if len(p.DependencyGroups) > 0 {
		addDepProperty(&d, "dependency_groups", strings.Join(p.DependencyGroups, ","))
	}
	addDepProperty(&d, "commit", p.Package.Commit)
	return d
}

// osvGroup is the records of one vulnerability under all its ids.
type osvGroup struct {
	ids         []string
	aliases     []string
	maxSeverity string
	records     []*osvRecord
}

func (b *builder) osvFindings(doc *jsonDoc, p *osvPackage, assetID, label string, pkgIdx int, ptr string) error {
	byID := map[string]*osvRecord{}
	for i := range p.Vulnerabilities {
		rec := &p.Vulnerabilities[i]
		if id := strings.TrimSpace(rec.ID); id != "" {
			if _, ok := byID[id]; !ok {
				byID[id] = rec
			}
		}
	}
	var groups []osvGroup
	used := map[string]bool{}
	for _, g := range p.Groups {
		og := osvGroup{ids: g.IDs, aliases: g.Aliases, maxSeverity: strings.TrimSpace(g.MaxSeverity)}
		for _, id := range g.IDs {
			if rec, ok := byID[strings.TrimSpace(id)]; ok && !used[rec.ID] {
				used[rec.ID] = true
				og.records = append(og.records, rec)
			}
		}
		groups = append(groups, og)
	}
	// Records no group names stand alone.
	for i := range p.Vulnerabilities {
		rec := &p.Vulnerabilities[i]
		if id := strings.TrimSpace(rec.ID); id != "" && !used[id] {
			used[id] = true
			groups = append(groups, osvGroup{ids: []string{id}, records: []*osvRecord{rec}})
		}
	}
	for gi := range groups {
		b.res.Stats.Records++
		g := &groups[gi]
		if len(g.records) == 0 {
			b.issue(doc.issueAt("/results[]/packages[]", pkgIdx, fmt.Sprintf("%s/groups/%d", ptr, gi), fmt.Sprintf("group %s names no record of this package: skipped", line(strings.Join(g.ids, ","), 128))))
			b.res.Stats.Skipped++
			continue
		}
		primary := g.records[0]
		if strings.TrimSpace(primary.Withdrawn) != "" {
			b.issue(doc.issueAt("/results[]/packages[]", pkgIdx, ptr, fmt.Sprintf("%s was withdrawn by its database: skipped", line(primary.ID, 128))))
			b.res.Stats.Skipped++
			continue
		}
		f := b.osvFinding(p, g, assetID)
		if err := b.finding(f); err != nil {
			return err
		}
	}
	return nil
}

// osvSource names the database of an OSV id for score sources.
func osvSource(id string) string {
	if strings.HasPrefix(strings.ToUpper(id), "GHSA-") {
		return "ghsa"
	}
	return "osv"
}

func osvScores(f *ctis.Finding, sev []osvSeverity, source string) {
	for _, s := range sev {
		switch strings.ToUpper(strings.TrimSpace(s.Type)) {
		case "CVSS_V2", "CVSS_V3", "CVSS_V4":
			if sc, ok := cvssVectorScore(s.Score, source); ok {
				addScore(f, sc)
			}
		default:
			if lbl := line(s.Score, ctis.MaxScoreLabelLen); lbl != "" {
				addScore(f, ctis.Score{System: ctis.ScoreSystemVendor, Label: lbl, Source: line(strings.ToLower(s.Type), ctis.MaxScoreSourceLen)})
			}
		}
	}
}

func (b *builder) osvFinding(p *osvPackage, g *osvGroup, assetID string) ctis.Finding {
	primary := g.records[0]
	pid := line(primary.ID, ctis.MaxNativeIDLen)
	name := line(p.Package.Name, capShort)
	version := line(p.Package.Version, capShort)
	eco := line(p.Package.Ecosystem, 32)

	title := pid + " in " + nameVersion(name, version)
	if s := line(primary.Summary, capTitle); s != "" {
		title = pid + ": " + s
	}
	f := ctis.Finding{
		Type:     ctis.FindingTypeVulnerability,
		Title:    line(title, capTitle),
		RuleID:   pid,
		RuleName: pid,
		AssetRef: assetID,
		Native:   &ctis.NativeIdentity{Scheme: ctis.NativeSchemeOther, VulnID: pid, RawRef: line(osvPackageRef(p)+"/"+pid, ctis.MaxRawRefLen)},
	}
	vuln := &ctis.VulnerabilityDetails{
		Package:         name,
		AffectedVersion: version,
		Ecosystem:       vulnEcosystem(eco),
	}
	for _, id := range g.ids {
		addVulnID(vuln, id)
	}
	for _, id := range g.aliases {
		addVulnID(vuln, id)
	}
	var related, upstream []string
	var published, modified *time.Time
	for _, rec := range g.records {
		addVulnID(vuln, rec.ID)
		for _, a := range rec.Aliases {
			addVulnID(vuln, a)
		}
		related = append(related, rec.Related...)
		upstream = append(upstream, rec.Upstream...)
		if t := parseTime(rec.Published); t != nil && (published == nil || t.Before(*published)) {
			published = t
		}
		if t := parseTime(rec.Modified); t != nil && (modified == nil || t.After(*modified)) {
			modified = t
		}
		osvScores(&f, rec.Severity, osvSource(rec.ID))
		for _, ref := range rec.References {
			u := line(ref.URL, capReference)
			if u == "" {
				continue
			}
			f.References = addRefs(f.References, u)
			if strings.EqualFold(ref.Type, "ADVISORY") {
				if f.Remediation == nil {
					f.Remediation = &ctis.Remediation{}
				}
				if len(f.Remediation.Advisories) < ctis.MaxAdvisories && len(u) <= ctis.MaxAdvisoryURLLen {
					f.Remediation.Advisories = append(f.Remediation.Advisories, ctis.Advisory{URL: u, Source: osvSource(rec.ID)})
				}
			}
		}
		osvDatabaseSpecific(&f, vuln, "database_specific:"+line(rec.ID, 64), rec.DatabaseSpecific)
		// The affected entry of this package.
		for _, a := range rec.Affected {
			if !strings.EqualFold(strings.TrimSpace(a.Package.Name), name) || (eco != "" && a.Package.Ecosystem != "" && !strings.EqualFold(strings.TrimSpace(a.Package.Ecosystem), eco)) {
				continue
			}
			if vuln.PURL == "" {
				if pu := cleanPURL(a.Package.PURL); pu != "" {
					if version != "" && !strings.Contains(pu, "@") {
						pu += "@" + version
					}
					vuln.PURL = cleanPURL(pu)
				}
			}
			osvScores(&f, a.Severity, osvSource(rec.ID))
			var spans []string
			for _, rg := range a.Ranges {
				var parts []string
				for _, ev := range rg.Events {
					switch {
					case ev.Introduced != "" && ev.Introduced != "0":
						parts = append(parts, ">="+line(ev.Introduced, 64))
					case ev.Fixed != "":
						parts = append(parts, "<"+line(ev.Fixed, 64))
						if len(vuln.FixedVersions) < 32 {
							vuln.FixedVersions = appendUnique(vuln.FixedVersions, line(ev.Fixed, 64))
						}
					case ev.LastAffected != "":
						parts = append(parts, "<="+line(ev.LastAffected, 64))
					case ev.Limit != "":
						parts = append(parts, "<"+line(ev.Limit, 64))
					}
				}
				if len(parts) > 0 && len(spans) < 16 {
					spans = append(spans, strings.Join(parts, ", "))
				}
			}
			if len(spans) > 0 && vuln.AffectedVersionRange == "" {
				vuln.AffectedVersionRange = line(strings.Join(spans, " || "), 1024)
			}
			osvDatabaseSpecific(&f, nil, "affected_database_specific:"+line(rec.ID, 48), a.DatabaseSpecific)
			osvDatabaseSpecific(&f, nil, "ecosystem_specific:"+line(rec.ID, 48), a.EcosystemSpecific)
		}
	}
	if vuln.PURL == "" {
		vuln.PURL = cleanPURL(p.Package.PURL)
	}
	if vuln.Ecosystem == "" {
		vuln.Ecosystem = vulnEcosystem(purlType(vuln.PURL))
	}
	vuln.PublishedAt, vuln.ModifiedAt = published, modified
	if len(vuln.FixedVersions) > 0 {
		vuln.FixedVersion = vuln.FixedVersions[0]
		if f.Remediation == nil {
			f.Remediation = &ctis.Remediation{}
		}
		f.Remediation.FixAvailable = true
		f.Remediation.SolutionType = ctis.SolutionTypeUpgrade
		f.Remediation.Recommendation = line(fmt.Sprintf("Upgrade %s to %s or later.", name, vuln.FixedVersion), capRemediation)
	}
	if len(vuln.CWEIDs) > 0 {
		vuln.CWEID = vuln.CWEIDs[0]
	}
	f.Vulnerability = vuln

	// Severity: the group's highest CVSS score, else the database's word.
	nativeSev := g.maxSeverity
	if v, err := strconv.ParseFloat(g.maxSeverity, 64); err == nil && v >= 0 && v <= 10 {
		f.Severity = severityFromCVSS(v)
	} else if w, ok := osvSeverityWord(primary.DatabaseSpecific); ok {
		f.Severity, nativeSev = w.sev, w.word
	} else {
		f.Severity = ctis.SeverityMedium
		nativeSev = ""
		extra(&f, "severity_note", "no max_severity or database severity; kept as medium")
	}
	f.Native.Severity = line(nativeSev, ctis.MaxNativeValueLen)
	setLegacyCVSS(&f)

	desc := text(primary.Summary, capDescription)
	if det := text(primary.Details, capDescription); det != "" {
		if desc != "" {
			desc = text(desc+"\n\n"+det, capDescription)
		} else {
			desc = det
		}
	}
	f.Description = desc
	f.Message = line(primary.Summary, 8<<10)
	if len(related) > 0 {
		extra(&f, "related", strings.Join(related, ", "))
	}
	if len(upstream) > 0 {
		extra(&f, "upstream", strings.Join(upstream, ", "))
	}
	if g.maxSeverity != "" {
		extra(&f, "max_severity", g.maxSeverity)
	}
	return f
}

func osvPackageRef(p *osvPackage) string {
	return nameVersion(p.Package.Ecosystem+":"+p.Package.Name, p.Package.Version)
}

type osvWord struct {
	sev  ctis.Severity
	word string
}

// osvSeverityWord reads database_specific.severity (GitHub: LOW, MODERATE,
// HIGH, CRITICAL).
func osvSeverityWord(raw json.RawMessage) (osvWord, bool) {
	var ds struct {
		Severity string `json:"severity"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &ds) != nil {
		return osvWord{}, false
	}
	s, ok := severityWord(ds.Severity)
	return osvWord{s, ds.Severity}, ok
}

// osvDatabaseSpecific keeps a database_specific or ecosystem_specific object
// as compact JSON in source_extra, and reads the CWE ids GitHub puts there.
func osvDatabaseSpecific(f *ctis.Finding, vuln *ctis.VulnerabilityDetails, key string, raw json.RawMessage) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return
	}
	if vuln != nil {
		var ds struct {
			CWEIDs []string `json:"cwe_ids"`
		}
		if json.Unmarshal(raw, &ds) == nil {
			for _, c := range ds.CWEIDs {
				c = strings.ToUpper(line(c, 16))
				if strings.HasPrefix(c, "CWE-") && len(vuln.CWEIDs) < 50 {
					vuln.CWEIDs = appendUnique(vuln.CWEIDs, c)
				}
			}
		}
	}
	var buf bytes.Buffer
	if json.Compact(&buf, raw) == nil {
		extra(f, key, buf.String())
	}
}
