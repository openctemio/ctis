package importer

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/openctemio/ctis"
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

// vulnEcosystems maps purl types and OSV ecosystem names to the
// vulnerability.ecosystem vocabulary of CTIS.
var vulnEcosystems = map[string]string{
	"npm": "npm", "pypi": "pip", "pip": "pip", "maven": "maven", "gradle": "gradle",
	"nuget": "nuget", "cargo": "cargo", "crates.io": "cargo", "golang": "go", "go": "go",
	"composer": "composer", "packagist": "composer", "gem": "rubygems", "rubygems": "rubygems",
	"hex": "hex", "pub": "pub", "swift": "swift", "swifturl": "swift", "cocoapods": "cocoapods",
}

// vulnEcosystem returns the CTIS ecosystem of a purl type or OSV ecosystem,
// or "" when CTIS has no word for it (the dependency keeps the native one).
func vulnEcosystem(native string) string {
	return vulnEcosystems[strings.ToLower(strings.TrimSpace(native))]
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

// cvssOrder ranks CVSS versions for the legacy single cvss_* members: the
// newest version wins.
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

// setLegacyCVSS fills the single-valued cvss_* members from the best CVSS
// score of f.
func setLegacyCVSS(f *ctis.Finding) {
	if f.Vulnerability == nil {
		return
	}
	best := -1
	for i, s := range f.Scores {
		if s.System != ctis.ScoreSystemCVSS {
			continue
		}
		if best < 0 || cvssOrder(s.Version) > cvssOrder(f.Scores[best].Version) ||
			(cvssOrder(s.Version) == cvssOrder(f.Scores[best].Version) && s.Value != nil && f.Scores[best].Value == nil) {
			best = i
		}
	}
	if best < 0 {
		return
	}
	s := f.Scores[best]
	f.Vulnerability.CVSSVersion = s.Version
	f.Vulnerability.CVSSVector = s.Vector
	if s.Value != nil {
		f.Vulnerability.CVSSScore = *s.Value
	}
	switch strings.ToLower(s.Source) {
	case "nvd", "ghsa", "redhat", "bitnami":
		f.Vulnerability.CVSSSource = strings.ToLower(s.Source)
	default:
		f.Vulnerability.CVSSSource = "vendor"
	}
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

// assetTypeOfPurpose maps an SBOM subject kind (CycloneDX component type,
// SPDX primaryPackagePurpose) to a CTIS asset type.
func assetTypeOfPurpose(kind string) ctis.AssetType {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(kind), "_", "-")) {
	case "container":
		return ctis.AssetTypeContainer
	case "operating-system", "device", "firmware", "platform":
		return ctis.AssetTypeHost
	}
	return ctis.AssetTypeRepository
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
