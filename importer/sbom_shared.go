package importer

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/openctemio/ctis/v2"
)

// Helpers of the SBOM and package-vulnerability importers (CycloneDX, SPDX,
// OSV).

// maxDependsOn bounds the depends_on list of one dependency.
const maxDependsOn = 1000

// maxDepProperties bounds the properties of one dependency.
const maxDepProperties = 32

// purlType returns the type of a package URL ("npm", "golang", "maven"), or
// "" when s is not a package URL.
func purlType(purl string) string {
	rest, ok := strings.CutPrefix(strings.TrimSpace(purl), "pkg:")
	if !ok {
		return ""
	}
	rest = strings.TrimLeft(rest, "/")
	i := strings.IndexByte(rest, '/')
	if i <= 0 {
		return ""
	}
	t := strings.ToLower(rest[:i])
	for _, r := range t {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '.' && r != '-' && r != '+' {
			return ""
		}
	}
	return t
}

// cleanPURL bounds a package URL and drops one with control characters or
// whitespace (a hostile value must not reach a receiver's match keys).
func cleanPURL(purl string) string {
	purl = strings.TrimSpace(purl)
	if purl == "" || len(purl) > 2048 || purlType(purl) == "" {
		return ""
	}
	for _, r := range purl {
		if r <= ' ' || r == 0x7f {
			return ""
		}
	}
	return purl
}

// goodPURL returns a package URL that has a canonical form, else "".
func goodPURL(purl string) string {
	purl = cleanPURL(purl)
	if purl == "" {
		return ""
	}
	if _, _, err := ctis.CanonicalPurl(purl); err != nil {
		return ""
	}
	return purl
}

// purlName returns the name of a package URL with its namespace
// ("@scope/name", "group:artifact"), unescaped, or "".
func purlName(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return ""
	}
	if i := strings.IndexAny(rest, "@?#"); i >= 0 {
		rest = rest[:i]
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) < 2 {
		return ""
	}
	name := strings.Join(parts[1:], "/")
	if u, err := url.PathUnescape(name); err == nil {
		name = u
	}
	return name
}

// purlTypes maps OSV ecosystem names and language words to the package URL
// type.
var purlTypes = map[string]string{
	"npm": "npm", "pypi": "pypi", "pip": "pypi", "maven": "maven", "gradle": "maven",
	"nuget": "nuget", "cargo": "cargo", "crates.io": "cargo", "golang": "golang", "go": "golang",
	"composer": "composer", "packagist": "composer", "gem": "gem", "rubygems": "gem",
	"hex": "hex", "pub": "pub", "swift": "swift", "swifturl": "swift", "cocoapods": "cocoapods",
}

// purlOf builds a package URL from an OSV ecosystem, a name and a version;
// "" when the ecosystem has no package URL type or the result is not a
// canonical package URL.
func purlOf(ecosystem, name, version string) string {
	typ := purlTypes[strings.ToLower(strings.TrimSpace(ecosystem))]
	name = strings.TrimSpace(name)
	if typ == "" || name == "" {
		return ""
	}
	if typ == "maven" {
		name = strings.Replace(name, ":", "/", 1)
	}
	segs := strings.Split(name, "/")
	for i, sg := range segs {
		segs[i] = url.PathEscape(sg)
	}
	p := "pkg:" + typ + "/" + strings.Join(segs, "/")
	if version != "" {
		p += "@" + url.PathEscape(version)
	}
	return goodPURL(p)
}

// severityFromCVSS bands a CVSS base score (the CVSS v3/v4 qualitative
// scale).
func severityFromCVSS(score float64) ctis.Severity {
	switch {
	case score >= 9:
		return ctis.SeverityCritical
	case score >= 7:
		return ctis.SeverityHigh
	case score >= 4:
		return ctis.SeverityMedium
	case score > 0:
		return ctis.SeverityLow
	}
	return ctis.SeverityInfo
}

// severityWord maps a qualitative severity word of an advisory database
// (CRITICAL, HIGH, MODERATE, MEDIUM, LOW, NONE, INFO).
func severityWord(s string) (ctis.Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return ctis.SeverityCritical, true
	case "high", "important":
		return ctis.SeverityHigh, true
	case "medium", "moderate":
		return ctis.SeverityMedium, true
	case "low":
		return ctis.SeverityLow, true
	case "none", "info", "informational", "negligible":
		return ctis.SeverityInfo, true
	}
	return "", false
}

// cvssVectorScore returns a CVSS score of a vector string with no value.
func cvssVectorScore(vector, source string) (ctis.Score, bool) {
	vector = line(vector, ctis.MaxScoreVectorLen)
	ver := ctis.CVSSVersionOfVector(vector)
	if ver == "" {
		return ctis.Score{}, false
	}
	return ctis.Score{System: ctis.ScoreSystemCVSS, Version: ver, Vector: vector, Source: line(source, ctis.MaxScoreSourceLen)}, true
}

// subjectAssetOf chooses the asset type and value of an SBOM subject (a
// CycloneDX metadata component, an SPDX root package): a container is an
// image when its name and version make an image reference, a component with
// a package URL is that package, anything else is unclassified, named by
// name and version (or fallback).
func subjectAssetOf(kind, purl, name, version, fallback string) (ctis.AssetType, string) {
	if strings.EqualFold(strings.TrimSpace(kind), "container") && name != "" {
		ref := name
		if strings.HasPrefix(version, "sha256:") {
			ref += "@" + version
		}
		if c, err := ctis.CanonicalImage(ref); err == nil {
			return ctis.AssetTypeContainerImage, c
		}
	}
	if purl = goodPURL(purl); purl != "" {
		return ctis.AssetTypePackage, purl
	}
	v := nameVersion(name, version)
	if v == "" {
		v = fallback
	}
	return ctis.AssetTypeUnclassified, v
}

// cvssOrder ranks CVSS versions: the newest version wins.
func cvssOrder(version string) int {
	switch version {
	case "4.0":
		return 4
	case "3.1":
		return 3
	case "3.0":
		return 2
	case "2.0":
		return 1
	}
	return 0
}

// addDepProperty sets a bounded dependency property.
func addDepProperty(d *ctis.Dependency, key, value string) {
	value = line(value, capShort*4)
	if value == "" {
		return
	}
	if d.Properties == nil {
		d.Properties = ctis.Properties{}
	}
	if _, ok := d.Properties[key]; !ok && len(d.Properties) >= maxDepProperties {
		return
	}
	d.Properties[key] = value
}

// nameVersion returns "name@version", or the name alone.
func nameVersion(name, version string) string {
	if version == "" {
		return name
	}
	return name + "@" + version
}

// floatString formats a score for a native value.
func floatString(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }
