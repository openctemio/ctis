package importer

import (
	"fmt"
	"io"
	"strings"

	"github.com/openctemio/ctis"
)

// SPDX 2.2 / 2.3 JSON: packages and their relationships. SPDX carries no
// vulnerabilities; a document gives the described package as the asset and
// every other package as a dependency. The mapping is spec_spdx.go.

func init() {
	parsers[FormatSPDX] = parseSPDX
	tools[FormatSPDX] = ctis.Tool{Name: "spdx", Capabilities: []string{"sca"}}
}

type spdxDoc struct {
	SPDXVersion       string `json:"spdxVersion"`
	SPDXID            string `json:"SPDXID"`
	Name              string `json:"name"`
	DocumentNamespace string `json:"documentNamespace"`
	CreationInfo      *struct {
		Created  string   `json:"created"`
		Creators []string `json:"creators"`
	} `json:"creationInfo"`
	DocumentDescribes []string           `json:"documentDescribes"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxPackage struct {
	SPDXID                string `json:"SPDXID"`
	Name                  string `json:"name"`
	VersionInfo           string `json:"versionInfo"`
	Supplier              string `json:"supplier"`
	Originator            string `json:"originator"`
	DownloadLocation      string `json:"downloadLocation"`
	Homepage              string `json:"homepage"`
	LicenseConcluded      string `json:"licenseConcluded"`
	LicenseDeclared       string `json:"licenseDeclared"`
	PrimaryPackagePurpose string `json:"primaryPackagePurpose"`
	Checksums             []struct {
		Algorithm     string `json:"algorithm"`
		ChecksumValue string `json:"checksumValue"`
	} `json:"checksums"`
	ExternalRefs []struct {
		ReferenceCategory string `json:"referenceCategory"`
		ReferenceType     string `json:"referenceType"`
		ReferenceLocator  string `json:"referenceLocator"`
	} `json:"externalRefs"`
	ReleaseDate string `json:"releaseDate"`
	BuiltDate   string `json:"builtDate"`
}

type spdxRelationship struct {
	Element string `json:"spdxElementId"`
	Type    string `json:"relationshipType"`
	Related string `json:"relatedSpdxElement"`
}

// spdxLicense returns a license expression unless it is NOASSERTION/NONE.
func spdxLicense(s string) string {
	s = line(s, capShort)
	switch strings.ToUpper(s) {
	case "", "NOASSERTION", "NONE":
		return ""
	}
	return s
}

// spdxOrganization returns the name of an "Organization: name (email)"
// supplier or originator. A "Person:" value names a person and is not read.
func spdxOrganization(s string) string {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), "Organization:")
	if !ok {
		return ""
	}
	if i := strings.Index(rest, "("); i >= 0 {
		rest = rest[:i]
	}
	return line(rest, capShort)
}

func parseSPDX(b *builder, r io.Reader) error {
	data, err := readAll(r, FormatSPDX, b.lim)
	if err != nil {
		return err
	}
	doc, err := scanJSON(data, FormatSPDX, b.lim, b.obs, "/packages[]", "/relationships[]")
	if err != nil {
		return err
	}
	var d spdxDoc
	if err := doc.decode(&d); err != nil {
		return err
	}
	if !strings.HasPrefix(strings.TrimSpace(d.SPDXVersion), "SPDX-2.") {
		return &ParseError{Format: FormatSPDX, Msg: fmt.Sprintf("spdxVersion %q is not SPDX 2.x", line(d.SPDXVersion, 32)), Err: ErrMalformed}
	}

	rep := b.res.Report
	props := ctis.Properties{"spdx_version": line(d.SPDXVersion, 16)}
	if s := line(d.Name, capShort); s != "" {
		props["sbom_name"] = s
	}
	if s := line(d.DocumentNamespace, capReference); s != "" {
		props["sbom_namespace"] = s
	}
	if d.CreationInfo != nil {
		if t := parseTime(d.CreationInfo.Created); t != nil {
			props["sbom_created"] = t.Format("2006-01-02T15:04:05Z07:00")
		}
		var tools []string
		for _, c := range d.CreationInfo.Creators {
			if t, ok := strings.CutPrefix(strings.TrimSpace(c), "Tool:"); ok && len(tools) < 8 {
				tools = append(tools, line(t, capShort))
			}
		}
		if len(tools) > 0 {
			props["sbom_tools"] = strings.Join(tools, ", ")
		}
	}
	rep.Metadata.Properties = props

	// The described package.
	subjectID := ""
	if len(d.DocumentDescribes) > 0 {
		subjectID = strings.TrimSpace(d.DocumentDescribes[0])
	}
	for _, rel := range d.Relationships {
		if subjectID != "" {
			break
		}
		switch strings.ToUpper(strings.TrimSpace(rel.Type)) {
		case "DESCRIBES":
			if strings.TrimSpace(rel.Element) == strings.TrimSpace(d.SPDXID) {
				subjectID = strings.TrimSpace(rel.Related)
			}
		case "DESCRIBED_BY":
			if strings.TrimSpace(rel.Related) == strings.TrimSpace(d.SPDXID) {
				subjectID = strings.TrimSpace(rel.Element)
			}
		}
	}

	var subject *spdxPackage
	deps := map[string]*ctis.Dependency{}
	var order []string
	for i := range d.Packages {
		if err := b.tick(); err != nil {
			return err
		}
		p := &d.Packages[i]
		id := line(p.SPDXID, capShort)
		ptr := fmt.Sprintf("/packages/%d", i)
		switch {
		case id == "" || line(p.Name, capShort) == "":
			b.issue(doc.issueAt("/packages[]", i, ptr, "package without SPDXID or name: skipped"))
			continue
		case id == subjectID && subject == nil:
			subject = p
			continue
		case deps[id] != nil:
			b.issue(doc.issueAt("/packages[]", i, ptr, fmt.Sprintf("SPDXID %q is used twice: the second package is skipped", id)))
			continue
		}
		dep := spdxDependency(p, id)
		deps[id] = &dep
		order = append(order, id)
	}
	if subjectID != "" && subject == nil {
		b.issue(Issue{Path: "/documentDescribes", Message: fmt.Sprintf("the described element %q is not a package of this document", line(subjectID, 128))})
	}

	// Relationships: A DEPENDS_ON B and B DEPENDENCY_OF A, A CONTAINS B and
	// B CONTAINED_BY A.
	direct := map[string]bool{}
	hasGraph := false
	link := func(from, to string) {
		hasGraph = true
		if from == subjectID && subjectID != "" {
			direct[to] = true
			return
		}
		fd, ok := deps[from]
		if !ok || deps[to] == nil || from == to || len(fd.DependsOn) >= maxDependsOn {
			return
		}
		fd.DependsOn = appendUnique(fd.DependsOn, to)
	}
	for _, rel := range d.Relationships {
		if err := b.tick(); err != nil {
			return err
		}
		a, z := strings.TrimSpace(rel.Element), strings.TrimSpace(rel.Related)
		switch strings.ToUpper(strings.TrimSpace(rel.Type)) {
		case "DEPENDS_ON", "CONTAINS":
			link(a, z)
		case "DEPENDENCY_OF", "CONTAINED_BY":
			link(z, a)
		}
	}

	if len(order) == 0 {
		return nil
	}
	if _, err := b.asset(spdxSubjectAsset(subject, d.Name)); err != nil {
		return err
	}
	if subject == nil {
		b.issue(Issue{Path: "/documentDescribes", Message: "the document describes no package; its packages are put on a repository asset named after the document"})
	}
	for _, id := range order {
		dep := deps[id]
		switch {
		case direct[id]:
			dep.Relationship = "direct"
		case hasGraph:
			dep.Relationship = "indirect"
		}
		b.res.Stats.Records++
		if err := b.dependency(*dep); err != nil {
			return err
		}
	}
	return nil
}

func spdxDependency(p *spdxPackage, id string) ctis.Dependency {
	d := ctis.Dependency{ID: id, Name: line(p.Name, capShort), Version: line(p.VersionInfo, capShort)}
	if l := spdxLicense(p.LicenseConcluded); l != "" {
		d.Licenses = append(d.Licenses, l)
	} else if l := spdxLicense(p.LicenseDeclared); l != "" {
		d.Licenses = append(d.Licenses, l)
	}
	if purpose := line(p.PrimaryPackagePurpose, 32); purpose != "" {
		d.Type = strings.ToLower(purpose)
	}
	var security []string
	for _, ref := range p.ExternalRefs {
		loc := line(ref.ReferenceLocator, capReference)
		switch strings.ToLower(strings.TrimSpace(ref.ReferenceType)) {
		case "purl":
			if d.PURL == "" {
				d.PURL = cleanPURL(loc)
			}
		case "cpe23type", "cpe22type":
			addDepProperty(&d, "cpe", loc)
		case "advisory", "fix", "url", "swid":
			if len(security) < 8 && loc != "" {
				security = append(security, loc)
			}
		default:
			if strings.EqualFold(strings.ReplaceAll(ref.ReferenceCategory, "_", "-"), "PERSISTENT-ID") {
				addDepProperty(&d, "persistent_id_"+strings.ToLower(line(ref.ReferenceType, 16)), loc)
			}
		}
	}
	if len(security) > 0 {
		addDepProperty(&d, "security_refs", strings.Join(security, " "))
	}
	d.Ecosystem = purlType(d.PURL)
	for _, c := range p.Checksums {
		if alg := strings.ToLower(line(c.Algorithm, 16)); alg != "" {
			addDepProperty(&d, "checksum_"+alg, c.ChecksumValue)
		}
	}
	addDepProperty(&d, "supplier", spdxOrganization(p.Supplier))
	addDepProperty(&d, "originator", spdxOrganization(p.Originator))
	if loc := line(p.DownloadLocation, capReference); loc != "" && !strings.EqualFold(loc, "NOASSERTION") && !strings.EqualFold(loc, "NONE") {
		addDepProperty(&d, "download_location", loc)
	}
	addDepProperty(&d, "homepage", p.Homepage)
	addDepProperty(&d, "release_date", p.ReleaseDate)
	addDepProperty(&d, "built_date", p.BuiltDate)
	return d
}

// spdxSubjectAsset is the asset the document describes.
func spdxSubjectAsset(p *spdxPackage, docName string) ctis.Asset {
	if p == nil {
		v := line(docName, capShort)
		if v == "" {
			v = "spdx-document"
		}
		return ctis.Asset{ID: "sbom-" + v, Type: ctis.AssetTypeRepository, Value: v, Name: v}
	}
	name := line(p.Name, capShort)
	version := line(p.VersionInfo, capShort)
	value := ""
	for _, ref := range p.ExternalRefs {
		if strings.EqualFold(strings.TrimSpace(ref.ReferenceType), "purl") {
			value = cleanPURL(ref.ReferenceLocator)
			break
		}
	}
	if value == "" {
		value = nameVersion(name, version)
	}
	a := ctis.Asset{ID: "sbom-" + value, Type: assetTypeOfPurpose(p.PrimaryPackagePurpose), Value: value, Name: name}
	pr := ctis.Properties{}
	if version != "" {
		pr["version"] = version
	}
	if s := line(p.PrimaryPackagePurpose, 32); s != "" {
		pr["package_purpose"] = strings.ToLower(s)
	}
	if len(pr) > 0 {
		a.Properties = pr
	}
	return a
}
