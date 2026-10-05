package importer

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/fingerprint"
)

// vuls JSON scan result of one server (results/<date>/<server>.json). The
// mapping is spec_vuls.go.

func init() {
	parsers[FormatVuls] = parseVuls
	tools[FormatVuls] = ctis.Tool{Name: "vuls", Vendor: "future-architect", InfoURL: "https://vuls.io", Capabilities: []string{"va"}}
}

type vulsPackage struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Release    string `json:"release"`
	Arch       string `json:"arch"`
	Repository string `json:"repository"`
	NewVersion string `json:"newVersion"`
	NewRelease string `json:"newRelease"`
}

type vulsContent struct {
	Type          string   `json:"type"`
	CveID         string   `json:"cveID"`
	Title         string   `json:"title"`
	Summary       string   `json:"summary"`
	Cvss3Score    float64  `json:"cvss3Score"`
	Cvss3Vector   string   `json:"cvss3Vector"`
	Cvss3Severity string   `json:"cvss3Severity"`
	Cvss2Score    float64  `json:"cvss2Score"`
	Cvss2Vector   string   `json:"cvss2Vector"`
	Cvss40Score   float64  `json:"cvss40Score"`
	Cvss40Vector  string   `json:"cvss40Vector"`
	CweIDs        []string `json:"cweIDs"`
	References    []struct {
		Source string `json:"source"`
		Link   string `json:"link"`
		RefID  string `json:"refID"`
	} `json:"references"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	SourceLink   string `json:"sourceLink"`
}

type vulsCVE struct {
	CveID       string `json:"cveID"`
	Confidences []struct {
		Score           int    `json:"score"`
		DetectionMethod string `json:"detectionMethod"`
	} `json:"confidences"`
	CveContents      map[string][]vulsContent `json:"cveContents"`
	AffectedPackages []struct {
		Name        string `json:"name"`
		FixedIn     string `json:"fixedIn"`
		NotFixedYet bool   `json:"notFixedYet"`
		FixState    string `json:"fixState"`
	} `json:"affectedPackages"`
	AlertDict json.RawMessage `json:"alertDict"`
}

type vulsReport struct {
	JSONVersion   int    `json:"jsonVersion"`
	ServerName    string `json:"serverName"`
	Family        string `json:"family"`
	Release       string `json:"release"`
	RunningKernel struct {
		Version        string `json:"version"`
		Release        string `json:"release"`
		RebootRequired bool   `json:"rebootRequired"`
	} `json:"runningKernel"`
	ScannedAt   string   `json:"scannedAt"`
	ScannedVia  string   `json:"scannedVia"`
	ScannedIPv4 []string `json:"scannedIpv4Addrs"`
	ScannedIPv6 []string `json:"scannedIpv6Addrs"`
	Platform    struct {
		Name       string `json:"name"`
		InstanceID string `json:"instanceID"`
	} `json:"platform"`
	Packages map[string]vulsPackage `json:"packages"`
	// An object keyed by CVE id (what vuls writes), or a list.
	ScannedCves json.RawMessage `json:"scannedCves"`
}

// vulsCVEs returns the scanned CVEs in a stable order (by key for the
// object form, in document order for the list form) with their keys.
func vulsCVEs(raw json.RawMessage) ([]string, []vulsCVE, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil, nil
	}
	if raw[0] == '[' {
		var list []vulsCVE
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, nil, err
		}
		keys := make([]string, len(list))
		for i := range list {
			keys[i] = strconv.Itoa(i)
		}
		return keys, list, nil
	}
	var m map[string]vulsCVE
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, nil, err
	}
	keys := sortedKeysOf(m)
	out := make([]vulsCVE, len(keys))
	for i, k := range keys {
		out[i] = m[k]
	}
	return keys, out, nil
}

func parseVuls(b *builder, r io.Reader) error {
	data, err := readAll(r, FormatVuls, b.lim)
	if err != nil {
		return err
	}
	doc, err := scanJSON(data, FormatVuls, b.lim, b.obs)
	if err != nil {
		return err
	}
	var rep vulsReport
	if err := doc.decode(&rep); err != nil {
		return err
	}
	keys, cves, err := vulsCVEs(rep.ScannedCves)
	if err != nil {
		return &ParseError{Format: FormatVuls, Msg: "scannedCves: " + jsonErrText(err), Err: ErrMalformed}
	}
	asset, ok := vulsAsset(&rep)
	if !ok {
		if len(cves) > 0 {
			b.issue(Issue{Message: "the result names no scanned host (no scannedIpv4Addrs, no serverName): nothing imported"})
			b.res.Stats.Records = len(cves)
			b.res.Stats.Skipped = len(cves)
		}
		return nil
	}
	assetID, err := b.asset(asset)
	if err != nil {
		return err
	}
	for _, name := range sortedKeysOf(rep.Packages) {
		p := rep.Packages[name]
		if err := b.dependency(ctis.Dependency{
			Name:      line(p.Name, capShort),
			Version:   line(vulsVersion(p), 128),
			Type:      "os",
			Ecosystem: vulsEcosystem(rep.Family),
			PURL:      sanePURL(vulsPURL(rep.Family, rep.Release, p.Name, vulsVersion(p), p.Arch)),
		}); err != nil {
			return err
		}
	}
	for i, key := range keys {
		b.res.Stats.Records++
		if err := b.tick(); err != nil {
			return err
		}
		cve := cves[i]
		f, ok := vulsFinding(&cve, &rep, assetID)
		if !ok {
			b.res.Stats.Skipped++
			b.issue(Issue{Path: "/scannedCves/" + line(key, 64), Message: "entry without cveID: skipped"})
			continue
		}
		if err := b.finding(f); err != nil {
			return err
		}
	}
	return nil
}

func vulsAsset(rep *vulsReport) (ctis.Asset, bool) {
	name := line(rep.ServerName, capShort)
	a := ctis.Asset{ID: "host-1", Type: ctis.AssetTypeHost, Name: name}
	for _, ip := range rep.ScannedIPv4 {
		if p := net.ParseIP(strings.TrimSpace(ip)); p != nil {
			a.Value = p.String()
			a.Type = ctis.AssetTypeIPAddress
			a.Technical = &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{Version: 4, Hostname: name}}
			break
		}
	}
	if a.Value == "" {
		a.Value = name
	}
	if a.Value == "" {
		return ctis.Asset{}, false
	}
	if a.Name == "" {
		a.Name = a.Value
	}
	a.Tags = addTags(nil, "vuls", rep.Family, rep.Release)
	if id := line(rep.Platform.InstanceID, ctis.MaxIdentityHintLen); id != "" {
		a.IdentityHints = &ctis.IdentityHints{CloudResourceID: id}
	}
	props := ctis.Properties{}
	for k, v := range map[string]string{"os_family": rep.Family, "os_release": rep.Release, "kernel_release": rep.RunningKernel.Release,
		"kernel_version": rep.RunningKernel.Version, "scanned_at": rep.ScannedAt, "scanned_via": rep.ScannedVia, "platform": rep.Platform.Name} {
		if v = line(v, capShort); v != "" {
			props[k] = v
		}
	}
	if rep.RunningKernel.RebootRequired {
		props["reboot_required"] = true
	}
	var v6 []string
	for _, ip := range rep.ScannedIPv6 {
		if p := net.ParseIP(strings.TrimSpace(ip)); p != nil && len(v6) < 16 {
			v6 = append(v6, p.String())
		}
	}
	if len(v6) > 0 {
		props["ipv6_addresses"] = strings.Join(v6, " ")
	}
	if len(props) > 0 {
		a.Properties = props
	}
	return a, true
}

func vulsVersion(p vulsPackage) string {
	if p.Release != "" {
		return p.Version + "-" + p.Release
	}
	return p.Version
}

// vulsContentOrder is the preference among a CVE's content sources.
var vulsContentOrder = []string{"nvd", "redhat", "ubuntu", "debian", "oracle", "amazon", "suse"}

// vulsBest returns the preferred content of a CVE: the first source of
// vulsContentOrder, else the first source by name.
func vulsBest(contents map[string][]vulsContent) *vulsContent {
	for _, s := range vulsContentOrder {
		if items := contents[s]; len(items) > 0 {
			return &items[0]
		}
	}
	for _, s := range sortedKeysOf(contents) {
		if items := contents[s]; len(items) > 0 {
			return &items[0]
		}
	}
	return nil
}

func vulsFinding(cve *vulsCVE, rep *vulsReport, assetID string) (ctis.Finding, bool) {
	id := line(cve.CveID, capShort)
	if id == "" {
		return ctis.Finding{}, false
	}
	c := vulsBest(cve.CveContents)
	f := ctis.Finding{
		Type:     ctis.FindingTypeVulnerability,
		Title:    id,
		RuleID:   id,
		AssetRef: assetID,
		Tags:     addTags(nil, "vuls", rep.ServerName),
		Native:   &ctis.NativeIdentity{Scheme: ctis.NativeSchemeOther, VulnID: id},
	}
	vd := &ctis.VulnerabilityDetails{}
	addVulnID(vd, id)
	if c != nil {
		if t := line(c.Title, capTitle); t != "" {
			f.Title = t
		}
		f.Description = text(c.Summary, capDescription)
		switch {
		case c.Cvss40Score > 0:
			vd.CVSSScore, vd.CVSSVector, vd.CVSSVersion = c.Cvss40Score, line(c.Cvss40Vector, ctis.MaxScoreVectorLen), "4.0"
		case c.Cvss3Score > 0:
			vd.CVSSScore, vd.CVSSVector, vd.CVSSVersion = c.Cvss3Score, line(c.Cvss3Vector, ctis.MaxScoreVectorLen), "3.1"
			if v := ctis.CVSSVersionOfVector(c.Cvss3Vector); v != "" {
				vd.CVSSVersion = v
			}
		case c.Cvss2Score > 0:
			vd.CVSSScore, vd.CVSSVector, vd.CVSSVersion = c.Cvss2Score, line(c.Cvss2Vector, ctis.MaxScoreVectorLen), "2.0"
		}
		if vd.CVSSScore > 10 {
			vd.CVSSScore, vd.CVSSVector, vd.CVSSVersion = 0, "", ""
		}
		for _, cw := range c.CweIDs {
			if cid := cweID(cw); cid != "" {
				vd.CWEIDs = appendUnique(vd.CWEIDs, cid)
			}
		}
		if len(vd.CWEIDs) > 0 {
			vd.CWEID = vd.CWEIDs[0]
		}
		vd.PublishedAt = parseTime(c.Published)
		vd.ModifiedAt = parseTime(c.LastModified)
		f.References = addRefs(f.References, c.SourceLink)
		for _, ref := range c.References {
			f.References = addRefs(f.References, ref.Link)
		}
	}
	// Every source's scores, in source order.
	for _, src := range sortedKeysOf(cve.CveContents) {
		for _, cc := range cve.CveContents[src] {
			for _, s := range []struct {
				ver, vec string
				val      float64
			}{{"4.0", cc.Cvss40Vector, cc.Cvss40Score}, {"", cc.Cvss3Vector, cc.Cvss3Score}, {"2.0", cc.Cvss2Vector, cc.Cvss2Score}} {
				if s.val <= 0 || s.val > 10 {
					continue
				}
				ver := s.ver
				if ver == "" {
					if ver = ctis.CVSSVersionOfVector(s.vec); ver == "" {
						ver = "3.1"
					}
				}
				val := s.val
				addScore(&f, ctis.Score{System: ctis.ScoreSystemCVSS, Version: ver, Vector: line(s.vec, ctis.MaxScoreVectorLen), Value: &val, Source: line(src, ctis.MaxScoreSourceLen)})
			}
		}
	}
	if len(cve.AffectedPackages) > 0 {
		ap := cve.AffectedPackages[0]
		vd.Package = line(ap.Name, capShort)
		vd.FixedVersion = line(ap.FixedIn, 256)
		if p, ok := rep.Packages[ap.Name]; ok {
			ver := vulsVersion(p)
			vd.AffectedVersion = line(ver, 128)
			vd.PURL = sanePURL(vulsPURL(rep.Family, rep.Release, ap.Name, ver, p.Arch))
		}
		switch {
		case ap.FixedIn != "":
			f.Remediation = &ctis.Remediation{Recommendation: line("Update "+ap.Name+" to version "+ap.FixedIn, capRemediation), FixAvailable: true, SolutionType: ctis.SolutionTypeUpgrade}
		case ap.NotFixedYet:
			f.Remediation = &ctis.Remediation{Recommendation: "No fix available yet. Consider mitigation or alternative packages.", SolutionType: ctis.SolutionTypeNoFix}
		}
		if ap.FixState != "" {
			extra(&f, "fix_state", ap.FixState)
		}
	}
	f.Vulnerability = vd
	f.Severity = vulsSeverity(vd.CVSSScore)
	if len(cve.Confidences) > 0 {
		if s := cve.Confidences[0].Score; s >= 0 && s <= 100 {
			f.Confidence = s
		}
		extra(&f, "detection_method", cve.Confidences[0].DetectionMethod)
	}
	if vd.Package != "" {
		f.Fingerprint = fingerprint.GenerateSCA(vd.Package, vd.AffectedVersion, cve.CveID)
	} else {
		f.Fingerprint = fingerprint.GenerateSCA(rep.ServerName, "", cve.CveID)
	}
	return f, true
}

func vulsSeverity(score float64) ctis.Severity {
	switch {
	case score >= 9.0:
		return ctis.SeverityCritical
	case score >= 7.0:
		return ctis.SeverityHigh
	case score >= 4.0:
		return ctis.SeverityMedium
	case score > 0:
		return ctis.SeverityLow
	}
	return ctis.SeverityInfo
}

func vulsPURL(family, release, name, version, arch string) string {
	if name == "" {
		return ""
	}
	typ, ns := vulsPURLType(family)
	p := "pkg:" + typ + "/" + ns + "/" + name + "@" + version
	var q []string
	if arch != "" {
		q = append(q, "arch="+arch)
	}
	if release != "" {
		q = append(q, "distro="+release)
	}
	if len(q) > 0 {
		p += "?" + strings.Join(q, "&")
	}
	return p
}

func vulsPURLType(family string) (string, string) {
	lf := strings.ToLower(family)
	switch lf {
	case "debian", "ubuntu", "raspbian":
		return "deb", lf
	case "redhat", "centos", "alma", "rocky":
		return "rpm", lf
	case "fedora":
		return "rpm", "fedora"
	case "amazon":
		return "rpm", "amzn"
	case "oracle":
		return "rpm", "oraclelinux"
	case "alpine":
		return "apk", "alpine"
	case "freebsd":
		return "pkg", "freebsd"
	}
	if strings.Contains(lf, "suse") || strings.Contains(lf, "sles") {
		return "rpm", "opensuse"
	}
	return "generic", lf
}

func vulsEcosystem(family string) string {
	lf := strings.ToLower(family)
	switch lf {
	case "debian", "ubuntu", "raspbian":
		return "deb"
	case "redhat", "centos", "alma", "rocky", "fedora", "amazon", "oracle", "suse":
		return "rpm"
	case "alpine":
		return "apk"
	}
	return line(lf, 64)
}
