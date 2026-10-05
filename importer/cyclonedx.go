package importer

import (
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/openctemio/ctis"
)

// CycloneDX 1.4-1.6 JSON: an SBOM (components, dependencies), a VDR
// (vulnerabilities) or a VEX (vulnerabilities with analysis). The mapping is
// spec_cyclonedx.go.

func init() {
	parsers[FormatCycloneDX] = parseCycloneDX
	tools[FormatCycloneDX] = ctis.Tool{Name: "cyclonedx", Capabilities: []string{"sca"}}
}

type cdxDoc struct {
	BOMFormat       string          `json:"bomFormat"`
	SpecVersion     string          `json:"specVersion"`
	SerialNumber    string          `json:"serialNumber"`
	Version         int             `json:"version"`
	Metadata        *cdxMetadata    `json:"metadata"`
	Components      []cdxComponent  `json:"components"`
	Dependencies    []cdxDependency `json:"dependencies"`
	Vulnerabilities []cdxVuln       `json:"vulnerabilities"`
}

type cdxMetadata struct {
	Timestamp string        `json:"timestamp"`
	Component *cdxComponent `json:"component"`
}

type cdxComponent struct {
	BOMRef      string         `json:"bom-ref"`
	Type        string         `json:"type"`
	Group       string         `json:"group"`
	Name        string         `json:"name"`
	Version     string         `json:"version"`
	Description string         `json:"description"`
	Scope       string         `json:"scope"`
	PURL        string         `json:"purl"`
	CPE         string         `json:"cpe"`
	Hashes      []cdxHash      `json:"hashes"`
	Licenses    []cdxLicense   `json:"licenses"`
	Supplier    *cdxEntity     `json:"supplier"`
	Publisher   string         `json:"publisher"`
	Properties  []cdxProperty  `json:"properties"`
	Components  []cdxComponent `json:"components"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxLicense struct {
	License *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"license"`
	Expression string `json:"expression"`
}

type cdxEntity struct {
	Name string `json:"name"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type cdxSource struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type cdxVuln struct {
	BOMRef     string     `json:"bom-ref"`
	ID         string     `json:"id"`
	Source     *cdxSource `json:"source"`
	References []struct {
		ID     string     `json:"id"`
		Source *cdxSource `json:"source"`
	} `json:"references"`
	Ratings []struct {
		Source        *cdxSource `json:"source"`
		Score         *float64   `json:"score"`
		Severity      string     `json:"severity"`
		Method        string     `json:"method"`
		Vector        string     `json:"vector"`
		Justification string     `json:"justification"`
	} `json:"ratings"`
	CWEs           []int  `json:"cwes"`
	Description    string `json:"description"`
	Detail         string `json:"detail"`
	Recommendation string `json:"recommendation"`
	Workaround     string `json:"workaround"`
	Advisories     []struct {
		Title string `json:"title"`
		URL   string `json:"url"`
	} `json:"advisories"`
	Created   string `json:"created"`
	Published string `json:"published"`
	Updated   string `json:"updated"`
	Rejected  string `json:"rejected"`
	Analysis  *struct {
		State         string   `json:"state"`
		Justification string   `json:"justification"`
		Response      []string `json:"response"`
		Detail        string   `json:"detail"`
		FirstIssued   string   `json:"firstIssued"`
		LastUpdated   string   `json:"lastUpdated"`
	} `json:"analysis"`
	Affects []struct {
		Ref      string `json:"ref"`
		Versions []struct {
			Version string `json:"version"`
			Range   string `json:"range"`
			Status  string `json:"status"`
		} `json:"versions"`
	} `json:"affects"`
	Properties []cdxProperty `json:"properties"`
}

// cdxNested folds nested component paths: /components[]/components[]/x and
// /metadata/component/components[]/x are both /components[]/x.
var cdxNested = regexp.MustCompile(`^(?:/metadata/component)?(?:/components\[\])+`)

func cdxRewrite(p string) string {
	return cdxNested.ReplaceAllString(p, "/components[]")
}

// cdxComp is a component of the document, flattened.
type cdxComp struct {
	c   *cdxComponent
	dep *ctis.Dependency // nil for the subject
}

func parseCycloneDX(b *builder, r io.Reader) error {
	data, err := readAll(r, FormatCycloneDX, b.lim)
	if err != nil {
		return err
	}
	b.obs.rewrite = cdxRewrite
	doc, err := scanJSON(data, FormatCycloneDX, b.lim, b.obs, "/vulnerabilities[]", "/components[]")
	if err != nil {
		return err
	}
	var d cdxDoc
	if err := doc.decode(&d); err != nil {
		return err
	}
	if !strings.EqualFold(d.BOMFormat, "CycloneDX") {
		return &ParseError{Format: FormatCycloneDX, Msg: "bomFormat is not CycloneDX", Err: ErrMalformed}
	}

	rep := b.res.Report
	props := ctis.Properties{}
	if s := line(d.SerialNumber, capShort); s != "" {
		props["bom_serial_number"] = s
	}
	if d.Version > 0 {
		props["bom_version"] = d.Version
	}
	if s := line(d.SpecVersion, 16); s != "" {
		props["cyclonedx_spec_version"] = s
	}
	if d.Metadata != nil {
		if t := parseTime(d.Metadata.Timestamp); t != nil {
			props["bom_timestamp"] = t.Format("2006-01-02T15:04:05Z07:00")
		}
	}
	if len(props) > 0 {
		rep.Metadata.Properties = props
	}
	docSource := "cyclonedx"
	if s := line(d.SerialNumber, ctis.MaxVEXSourceLen-16); s != "" {
		docSource = s
	}

	// Components, flattened, by bom-ref.
	byRef := map[string]*cdxComp{}
	var subject *cdxComponent
	if d.Metadata != nil && d.Metadata.Component != nil {
		subject = d.Metadata.Component
		if ref := strings.TrimSpace(subject.BOMRef); ref != "" {
			byRef[ref] = &cdxComp{c: subject}
		}
	}
	ids := map[string]bool{}
	var order []*cdxComp
	var walk func(list []cdxComponent, path string) error
	walk = func(list []cdxComponent, path string) error {
		for i := range list {
			if err := b.tick(); err != nil {
				return err
			}
			c := &list[i]
			dep, ok := cdxToDependency(c)
			at := -1
			if path == "/components" {
				at = i
			}
			if !ok {
				b.issue(doc.issueAt("/components[]", at, fmt.Sprintf("%s/%d", path, i), "component without a name: skipped"))
			} else {
				if ids[dep.ID] {
					b.issue(doc.issueAt("/components[]", at, fmt.Sprintf("%s/%d", path, i), fmt.Sprintf("bom-ref %q is used twice: the second component is skipped", dep.ID)))
				} else {
					ids[dep.ID] = true
					cc := &cdxComp{c: c, dep: &dep}
					order = append(order, cc)
					if ref := strings.TrimSpace(c.BOMRef); ref != "" {
						if _, taken := byRef[ref]; !taken {
							byRef[ref] = cc
						}
					}
				}
			}
			if len(c.Components) > 0 {
				if err := walk(c.Components, fmt.Sprintf("%s/%d/components", path, i)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if subject != nil && len(subject.Components) > 0 {
		if err := walk(subject.Components, "/metadata/component/components"); err != nil {
			return err
		}
	}
	if err := walk(d.Components, "/components"); err != nil {
		return err
	}

	// The dependency graph.
	subjectRef := ""
	if subject != nil {
		subjectRef = strings.TrimSpace(subject.BOMRef)
	}
	direct := map[string]bool{}
	hasGraph := len(d.Dependencies) > 0
	for _, dg := range d.Dependencies {
		ref := strings.TrimSpace(dg.Ref)
		if ref == subjectRef && ref != "" {
			for _, on := range dg.DependsOn {
				direct[strings.TrimSpace(on)] = true
			}
			continue
		}
		cc, ok := byRef[ref]
		if !ok || cc.dep == nil {
			continue
		}
		for _, on := range dg.DependsOn {
			on = strings.TrimSpace(on)
			target, ok := byRef[on]
			if !ok || target.dep == nil || on == ref || len(cc.dep.DependsOn) >= maxDependsOn {
				continue
			}
			cc.dep.DependsOn = appendUnique(cc.dep.DependsOn, target.dep.ID)
		}
	}

	// The subject asset, created when anything needs it.
	assetID := ""
	ensureAsset := func() (string, error) {
		if assetID != "" {
			return assetID, nil
		}
		a := cdxSubjectAsset(subject, d.SerialNumber)
		if subject == nil {
			b.issue(Issue{Path: "/metadata/component", Message: "the BOM names no subject component; its components and findings are put on an unclassified asset named after the BOM"})
		}
		id, err := b.asset(a)
		assetID = id
		return id, err
	}
	if len(order) > 0 {
		if _, err := ensureAsset(); err != nil {
			return err
		}
	}
	for _, cc := range order {
		ref := strings.TrimSpace(cc.c.BOMRef)
		switch {
		case direct[ref] && ref != "":
			cc.dep.Relationship = "direct"
		case hasGraph:
			cc.dep.Relationship = "indirect"
		}
		if err := b.dependency(*cc.dep); err != nil {
			return err
		}
	}

	// Vulnerabilities.
	for i := range d.Vulnerabilities {
		if err := b.tick(); err != nil {
			return err
		}
		if err := b.cdxVuln(doc, &d.Vulnerabilities[i], i, byRef, docSource, ensureAsset); err != nil {
			return err
		}
	}
	return nil
}

// cdxToDependency converts a component; ok is false without a name.
func cdxToDependency(c *cdxComponent) (ctis.Dependency, bool) {
	name := line(c.Name, capShort)
	if name == "" {
		return ctis.Dependency{}, false
	}
	purl := cleanPURL(c.PURL)
	version := line(c.Version, capShort)
	id := line(c.BOMRef, capShort)
	if id == "" {
		id = purl
	}
	if id == "" {
		id = nameVersion(name, version)
	}
	d := ctis.Dependency{
		ID:      id,
		Name:    name,
		Version: version,
		Type:    line(c.Type, 32),
		PURL:    purl,
	}
	if g := line(c.Group, capShort); g != "" {
		addDepProperty(&d, "group", g)
	}
	d.Ecosystem = purlType(purl)
	for _, l := range c.Licenses {
		switch {
		case l.Expression != "":
			d.Licenses = appendUnique(d.Licenses, line(l.Expression, capShort))
		case l.License != nil && l.License.ID != "":
			d.Licenses = appendUnique(d.Licenses, line(l.License.ID, capShort))
		case l.License != nil && l.License.Name != "":
			d.Licenses = appendUnique(d.Licenses, line(l.License.Name, capShort))
		}
		if len(d.Licenses) >= 16 {
			break
		}
	}
	for _, h := range c.Hashes {
		if alg := strings.ToLower(line(h.Alg, 16)); alg != "" {
			addDepProperty(&d, "hash_"+alg, h.Content)
		}
	}
	addDepProperty(&d, "cpe", c.CPE)
	addDepProperty(&d, "scope", c.Scope)
	addDepProperty(&d, "publisher", c.Publisher)
	if c.Supplier != nil {
		addDepProperty(&d, "supplier", c.Supplier.Name)
	}
	if desc := line(c.Description, capShort); desc != "" {
		addDepProperty(&d, "description", desc)
	}
	for _, p := range c.Properties {
		if n := line(p.Name, 96); n != "" {
			addDepProperty(&d, "property:"+n, p.Value)
		}
	}
	return d, true
}

// cdxSubjectAsset is the asset an SBOM describes.
func cdxSubjectAsset(c *cdxComponent, serial string) ctis.Asset {
	if c == nil {
		v := line(serial, capShort)
		if v == "" {
			v = "cyclonedx-bom"
		}
		return ctis.Asset{ID: "sbom-" + v, Type: ctis.AssetTypeUnclassified, Value: v, Name: v}
	}
	name := line(c.Name, capShort)
	if g := line(c.Group, capShort); g != "" && name != "" {
		name = g + "/" + name
	}
	value := cleanPURL(c.PURL)
	if value == "" {
		value = nameVersion(name, line(c.Version, capShort))
	}
	if value == "" {
		value = line(serial, capShort)
	}
	if value == "" {
		value = "cyclonedx-bom"
	}
	if name == "" {
		name = value
	}
	a := ctis.Asset{ID: "sbom-" + value, Type: assetTypeOfPurpose(c.Type), Value: value, Name: line(name, capShort)}
	p := ctis.Properties{}
	if v := line(c.Version, capShort); v != "" {
		p["version"] = v
	}
	if c.Type != "" {
		p["component_type"] = line(c.Type, 32)
	}
	if cpe := line(c.CPE, capShort); cpe != "" {
		p["cpe"] = cpe
	}
	if len(p) > 0 {
		a.Properties = p
	}
	return a
}

// cdxProduct describes the component a vulnerability affects.
func cdxProduct(ref string, byRef map[string]*cdxComp) (Product, *cdxComponent, bool) {
	ref = strings.TrimSpace(ref)
	if cc, ok := byRef[ref]; ok {
		c := cc.c
		return Product{PURL: cleanPURL(c.PURL), CPE: line(c.CPE, capShort), Name: line(c.Name, capShort), Version: line(c.Version, capShort)}, c, true
	}
	if p := cleanPURL(ref); p != "" {
		return Product{PURL: p}, nil, true
	}
	return Product{}, nil, false
}

// cdxRatingSystem maps a rating method to a score system and version.
func cdxRatingSystem(method, vector string) (ctis.ScoreSystem, string) {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "CVSSV2":
		return ctis.ScoreSystemCVSS, "2.0"
	case "CVSSV3":
		if v := ctis.CVSSVersionOfVector(vector); v == "3.1" {
			return ctis.ScoreSystemCVSS, "3.1"
		}
		return ctis.ScoreSystemCVSS, "3.0"
	case "CVSSV31":
		return ctis.ScoreSystemCVSS, "3.1"
	case "CVSSV4":
		return ctis.ScoreSystemCVSS, "4.0"
	case "SSVC":
		return ctis.ScoreSystemSSVC, ""
	}
	if v := ctis.CVSSVersionOfVector(vector); v != "" {
		return ctis.ScoreSystemCVSS, v
	}
	return ctis.ScoreSystemVendor, ""
}

func (b *builder) cdxVuln(doc *jsonDoc, v *cdxVuln, idx int, byRef map[string]*cdxComp, docSource string, ensureAsset func() (string, error)) error {
	ptr := fmt.Sprintf("/vulnerabilities/%d", idx)
	vid := line(v.ID, ctis.MaxNativeIDLen)
	if vid == "" {
		b.issue(doc.issueAt("/vulnerabilities[]", idx, ptr, "vulnerability without an id: skipped"))
		b.res.Stats.Skipped++
		return nil
	}

	// The typed ids, shared by findings and the statement.
	ids := &ctis.VulnerabilityDetails{}
	addVulnID(ids, vid)
	for _, ref := range v.References {
		src := ""
		if ref.Source != nil {
			src = ref.Source.Name
		}
		addVendorID(ids, ref.ID, strings.ToLower(src))
	}

	// The affected products.
	type affected struct {
		p        Product
		c        *cdxComponent
		versions []string
	}
	var affects []affected
	var unresolved []string
	for _, a := range v.Affects {
		p, c, ok := cdxProduct(a.Ref, byRef)
		if !ok {
			unresolved = append(unresolved, line(a.Ref, 128))
			continue
		}
		var versions []string
		for _, ver := range a.Versions {
			if r := firstNonEmpty(ver.Range, ver.Version); r != "" && len(versions) < 32 {
				versions = append(versions, line(r+" ("+firstNonEmpty(ver.Status, "affected")+")", 256))
			}
		}
		affects = append(affects, affected{p, c, versions})
	}
	if len(unresolved) > 0 {
		b.issue(doc.issueAt("/vulnerabilities[]", idx, ptr+"/affects", fmt.Sprintf("%s: %d affected refs name no component of this BOM and are not package URLs: %s", vid, len(unresolved), strings.Join(unresolved, ", "))))
	}

	// The VEX analysis.
	var vex *ctis.VEX
	suppress := false
	if a := v.Analysis; a != nil && strings.TrimSpace(a.State) != "" {
		asOf := parseTime(a.LastUpdated)
		if asOf == nil {
			asOf = parseTime(a.FirstIssued)
		}
		x, err := vexOf(a.State, a.Justification, a.Detail, docSource, asOf)
		if err != nil {
			if strings.EqualFold(strings.TrimSpace(a.State), "false_positive") {
				// The producer's own disposition of its finding.
				suppress = true
			} else {
				b.issue(doc.issueAt("/vulnerabilities[]", idx, ptr+"/analysis", vid+": "+err.Error()))
			}
		} else {
			vex = &x
			// Only a statement that passed vexOf takes the finding away: a
			// bare not_affected claim leaves it in place.
			switch strings.ToLower(strings.TrimSpace(a.State)) {
			case "not_affected", "resolved", "resolved_with_pedigree":
				suppress = true
			}
			var products []Product
			for _, af := range affects {
				products = append(products, af.p)
			}
			if len(products) > 0 {
				if err := b.statement(VEXStatement{VulnerabilityIDs: ids.IDs, Products: products, VEX: x}); err != nil {
					return err
				}
			} else {
				b.issue(doc.issueAt("/vulnerabilities[]", idx, ptr+"/analysis", vid+": the statement names no product it can be matched on"))
			}
		}
	}

	for j, af := range affects {
		b.res.Stats.Records++
		if suppress {
			b.res.Stats.Skipped++
			continue
		}
		if af.c == nil {
			// A package URL outside the BOM: nothing in this report is
			// affected.
			b.res.Stats.Skipped++
			continue
		}
		assetID, err := ensureAsset()
		if err != nil {
			return err
		}
		f := b.cdxFinding(v, vid, ids, af.c, af.versions, assetID, fmt.Sprintf("%s/affects/%d", ptr, j))
		f.VEX = vex
		if err := b.finding(f); err != nil {
			return err
		}
	}
	return nil
}

func (b *builder) cdxFinding(v *cdxVuln, vid string, ids *ctis.VulnerabilityDetails, c *cdxComponent, ranges []string, assetID, rawRef string) ctis.Finding {
	name := line(c.Name, capShort)
	if g := line(c.Group, capShort); g != "" {
		name = g + "/" + name
	}
	version := line(c.Version, capShort)
	purl := cleanPURL(c.PURL)
	f := ctis.Finding{
		Type:     ctis.FindingTypeVulnerability,
		Title:    line(fmt.Sprintf("%s in %s", vid, nameVersion(name, version)), capTitle),
		RuleID:   vid,
		RuleName: vid,
		AssetRef: assetID,
		Native: &ctis.NativeIdentity{
			Scheme:     ctis.NativeSchemeOther,
			VulnID:     vid,
			InstanceID: line(v.BOMRef, ctis.MaxNativeIDLen),
			RawRef:     line(rawRef, ctis.MaxRawRefLen),
		},
	}
	vuln := &ctis.VulnerabilityDetails{
		CVEID:           ids.CVEID,
		CVEIDs:          append([]string(nil), ids.CVEIDs...),
		IDs:             append([]ctis.VulnerabilityID(nil), ids.IDs...),
		Package:         name,
		PURL:            purl,
		AffectedVersion: version,
		Ecosystem:       vulnEcosystem(purlType(purl)),
		PublishedAt:     parseTime(v.Published),
		ModifiedAt:      parseTime(v.Updated),
	}
	for _, cwe := range v.CWEs {
		if cwe > 0 && len(vuln.CWEIDs) < 50 {
			vuln.CWEIDs = appendUnique(vuln.CWEIDs, "CWE-"+strconv.Itoa(cwe))
		}
	}
	if len(vuln.CWEIDs) > 0 {
		vuln.CWEID = vuln.CWEIDs[0]
	}
	if cpe := line(c.CPE, capShort); cpe != "" {
		vuln.CPE = cpe
	}
	if v.Source != nil {
		vuln.DataSource = &ctis.VulnDataSource{Name: line(v.Source.Name, capShort), URL: line(v.Source.URL, capReference)}
		f.References = addRefs(f.References, v.Source.URL)
	}
	f.Vulnerability = vuln

	// Ratings: every one a score; the severity from the best.
	var sev ctis.Severity
	var nativeSev string
	bestRank := -1
	for _, r := range v.Ratings {
		src := ""
		if r.Source != nil {
			src = line(r.Source.Name, ctis.MaxScoreSourceLen)
		}
		vector := line(r.Vector, ctis.MaxScoreVectorLen)
		sys, ver := cdxRatingSystem(r.Method, vector)
		s := ctis.Score{System: sys, Version: ver, Vector: vector, Source: src, Label: line(r.Severity, ctis.MaxScoreLabelLen)}
		if r.Score != nil && sys != ctis.ScoreSystemSSVC {
			val := *r.Score
			s.Value = &val
		}
		if sys == ctis.ScoreSystemVendor && s.Source == "" {
			s.Source = strings.ToLower(line(r.Method, ctis.MaxScoreSourceLen))
		}
		addScore(&f, s)
		if j := line(r.Justification, 512); j != "" {
			extra(&f, "rating_justification:"+line(src+":"+r.Method, 64), j)
		}
		rank := cvssOrder(ver)
		if sys != ctis.ScoreSystemCVSS {
			rank = 0
		}
		if r.Severity == "" && r.Score == nil {
			continue
		}
		if rank > bestRank {
			bestRank = rank
			if w, ok := severityWord(r.Severity); ok {
				sev, nativeSev = w, r.Severity
			} else if r.Score != nil && sys == ctis.ScoreSystemCVSS && *r.Score >= 0 && *r.Score <= 10 {
				sev, nativeSev = severityFromCVSS(*r.Score), floatString(*r.Score)
			}
		}
	}
	if sev == "" {
		sev = ctis.SeverityMedium
		nativeSev = ""
		extra(&f, "severity_note", "no rating with a severity; kept as medium")
	}
	f.Severity = sev
	f.Native.Severity = line(nativeSev, ctis.MaxNativeValueLen)
	setLegacyCVSS(&f)

	desc := text(v.Description, capDescription)
	if det := text(v.Detail, capDescription); det != "" && det != desc {
		if desc != "" {
			desc = text(desc+"\n\n"+det, capDescription)
		} else {
			desc = det
		}
	}
	f.Description = desc
	if v.Description != "" {
		f.Message = line(v.Description, 8<<10)
	}

	rec := text(v.Recommendation, capRemediation)
	work := text(v.Workaround, capRemediation)
	if rec != "" || work != "" || len(v.Advisories) > 0 {
		f.Remediation = &ctis.Remediation{Recommendation: rec}
		if work != "" {
			f.Remediation.Steps = []string{text("Workaround: "+work, 2<<10)}
			if rec == "" {
				f.Remediation.SolutionType = ctis.SolutionTypeWorkaround
			}
		}
		for _, a := range v.Advisories {
			u := line(a.URL, ctis.MaxAdvisoryURLLen)
			id := line(a.Title, ctis.MaxVulnerabilityIDLen)
			if (u == "" && id == "") || len(f.Remediation.Advisories) >= ctis.MaxAdvisories {
				continue
			}
			f.Remediation.Advisories = append(f.Remediation.Advisories, ctis.Advisory{ID: id, URL: u})
			f.References = addRefs(f.References, u)
		}
	}

	// Version ranges of the affected component, as the document states them.
	if len(ranges) > 0 {
		extra(&f, "affects_versions", strings.Join(ranges, "\n"))
	}
	if v.Analysis != nil {
		if len(v.Analysis.Response) > 0 {
			extra(&f, "analysis_response", strings.Join(v.Analysis.Response, ", "))
		}
	}
	extra(&f, "created", v.Created)
	extra(&f, "rejected", v.Rejected)
	for _, p := range v.Properties {
		if n := line(p.Name, 96); n != "" {
			extra(&f, "property:"+n, p.Value)
		}
	}
	return f
}
