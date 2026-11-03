// Package importkit holds the text, reference and package helpers shared by
// the importers of package importer and the interoperability adapters
// (v2/interop/<format>, nested modules of this repository). It is internal: the
// helpers are not part of the module's API and change with the importers.
package importkit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/ctis/v2"
)

// Text caps, the same as the CTIS receiver caps (spec section 7), so a
// report never carries more than a receiver keeps.
const (
	CapTitle       = 500
	CapCategory    = 255
	CapDescription = 32 << 10
	CapEvidence    = 64 << 10
	CapRemediation = 16 << 10
	CapReference   = 2 << 10
	MaxReferences  = 100
	CapTag         = 100
	MaxTags        = 50
	CapShort       = 255
)

const TruncMarker = "…[truncated]"

// Text cleans a source text: control characters other than tab, newline and
// carriage return are removed, the ends are trimmed, and a value longer than
// limit characters is cut with a marker.
func Text(s string, limit int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return r
		}
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, s))
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	runes := []rune(s)
	return string(runes[:limit-utf8.RuneCountInString(TruncMarker)]) + TruncMarker
}

// Line cleans a one-line value: like text, and newlines and tabs become
// spaces.
func Line(s string, limit int) string {
	return Text(strings.Join(strings.Fields(s), " "), limit)
}

// AddRefs appends bounded, distinct references.
func AddRefs(dst []string, refs ...string) []string {
	for _, r := range refs {
		r = Line(r, CapReference)
		if r == "" || len(dst) >= MaxReferences {
			continue
		}
		dup := false
		for _, d := range dst {
			if d == r {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, r)
		}
	}
	return dst
}

// Extra stores an unmapped source value on f (bounded by ctis.SetSourceExtra).
func Extra(f *ctis.Finding, key, value string) {
	value = Text(value, ctis.MaxSourceExtraValueLen)
	if value == "" {
		return
	}
	ctis.SetSourceExtra(f, key, value)
}

// Extras stores key/value pairs in order (see extra).
func Extras(f *ctis.Finding, kv ...string) {
	for i := 0; i+1 < len(kv); i += 2 {
		Extra(f, kv[i], kv[i+1])
	}
}

// AddVulnID adds a CVE, GHSA or OSV id to v once (canonical form); an id of
// another shape is dropped. Use addVendorID for a vendor's own id.
func AddVulnID(v *ctis.VulnerabilityDetails, raw string) {
	if _, ok := ctis.NormalizeVulnerabilityID(strings.TrimSpace(raw)); !ok {
		return
	}
	v.AddID(raw, "")
}

// AddVendorID adds an id the vendor named source issued (an advisory number,
// a plugin id the source treats as the vulnerability's) to v.
func AddVendorID(v *ctis.VulnerabilityDetails, raw, source string) {
	id, ok := ctis.NormalizeVulnerabilityID(strings.TrimSpace(raw))
	if !ok || len(v.IDs) >= ctis.MaxVulnerabilityIDs {
		return
	}
	if id.Type == ctis.VulnerabilityIDVendor {
		id.Source = Line(source, ctis.MaxScoreSourceLen)
	}
	for _, have := range v.IDs {
		if have.Type == id.Type && strings.EqualFold(have.ID, id.ID) {
			return
		}
	}
	v.IDs = append(v.IDs, id)
}

// SourceRef is a bounded source reference.
func SourceRef(system, id string) ctis.SourceRef {
	return ctis.SourceRef{System: system, ID: Line(id, ctis.MaxSourceRefIDLen)}
}

// AddScore appends a score if there is room and it is valid on its own.
func AddScore(f *ctis.Finding, s ctis.Score) {
	if len(f.Scores) >= ctis.MaxScores {
		return
	}
	p := Probe()
	p.Assets = []ctis.Asset{{ID: "probe", Type: ctis.AssetTypeHost, Value: "probe.invalid"}}
	p.Findings = []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "t", Severity: ctis.SeverityInfo, AssetRef: "probe", Scores: []ctis.Score{s}}}
	if p.Validate() != nil {
		return
	}
	f.Scores = append(f.Scores, s)
}

// AddTags appends bounded, distinct tags.
func AddTags(dst []string, tags ...string) []string {
	for _, t := range tags {
		t = Line(t, CapTag)
		if t == "" || len(dst) >= MaxTags {
			continue
		}
		dup := false
		for _, d := range dst {
			if d == t {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, t)
		}
	}
	return dst
}

// VexOf builds a CTIS VEX statement from a document's native status and
// justification. It returns an error for a status no table knows, and for a
// not_affected statement with neither a known justification nor an impact
// statement (CTIS requires one of them, and a receiver must not suppress a
// finding on a bare claim).
func VexOf(nativeStatus, nativeJustification, statement, source string, asOf *time.Time) (ctis.VEX, error) {
	st, ok := ctis.NormalizeVEXStatus(nativeStatus)
	if !ok {
		return ctis.VEX{}, fmt.Errorf("unknown VEX status %q", Line(nativeStatus, 64))
	}
	v := ctis.VEX{
		Status:    st,
		Statement: Text(statement, ctis.MaxVEXStatementLen),
		Source:    Line(source, ctis.MaxVEXSourceLen),
		AsOf:      asOf,
	}
	if nj := strings.TrimSpace(nativeJustification); nj != "" {
		if st == ctis.VEXStatusNotAffected {
			if j, ok := ctis.NormalizeVEXJustification(nj); ok {
				v.Justification = j
			}
		}
		v.NativeJustification = Line(nj, ctis.MaxNativeValueLen)
	}
	if st == ctis.VEXStatusNotAffected && v.Justification == "" && v.Statement == "" {
		return ctis.VEX{}, fmt.Errorf("status not_affected without a justification or an impact statement")
	}
	return v, nil
}

// ParseTime reads an RFC 3339 time (with or without fractional seconds), or
// a date.
func ParseTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}

// DocRef builds a document-local reference "<prefix>-<s>" (ctis.IsDocumentRef:
// never UUID-shaped, at most 255 characters of the reference alphabet). When
// s does not fit the alphabet or the length, the reference is the prefix and
// a hash of s, so it is stable and still unique per s.
func DocRef(prefix, s string) string {
	ref := prefix + "-" + s
	if ctis.IsDocumentRef(ref) && !strings.HasSuffix(ref, "-") {
		return ref
	}
	h := sha256.Sum256([]byte(s))
	return prefix + "-h" + hex.EncodeToString(h[:12])
}

// RefOr returns s when it already is a document reference, else a reference
// derived from it (docRef with the prefix).
func RefOr(prefix, s string) string {
	if ctis.IsDocumentRef(s) {
		return s
	}
	return DocRef(prefix, s)
}

// WebURL returns s when it is an http or https URL, else "".
func WebURL(s string) string {
	s = strings.TrimSpace(s)
	if ctis.IsWebURL(s) {
		return s
	}
	return ""
}

// AddWebRefs appends the http(s) URLs among refs (bounded, distinct).
func AddWebRefs(dst []string, refs ...string) []string {
	for _, r := range refs {
		if u := WebURL(r); u != "" {
			dst = AddRefs(dst, u)
		}
	}
	return dst
}

// TokenOf lowercases the name of an advisory source into an open token
// (a-z, 0-9, '.', '_', '-'); anything else becomes '-'. It may be empty.
func TokenOf(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-':
			b.WriteRune(r)
		case b.Len() > 0:
			b.WriteByte('-')
		}
		if b.Len() >= 63 {
			break
		}
	}
	return strings.Trim(b.String(), "-")
}

// RawTextEvidence adds source text as a raw_text evidence item. The text is
// bounded; an empty text adds nothing. Callers pass text that holds no
// credential (ctis.RedactSecretFinding masks what the builder sees).
func RawTextEvidence(f *ctis.Finding, label, body, protocol string) {
	body = Text(body, CapEvidence)
	if body == "" || len(f.EvidenceItems) >= ctis.MaxEvidenceItems {
		return
	}
	if len(body) > ctis.MaxEvidenceTextBytes {
		cut := ctis.MaxEvidenceTextBytes - len(TruncMarker)
		for cut > 0 && !utf8.RuneStart(body[cut]) {
			cut--
		}
		body = body[:cut] + TruncMarker
	}
	f.EvidenceItems = append(f.EvidenceItems, ctis.EvidenceItem{
		Kind: ctis.EvidenceKindRawText, Version: 1, Label: Line(label, ctis.MaxEvidenceLabelLen),
		Text: body, Protocol: protocol,
	})
}

// MaxDependsOn bounds the depends_on list of one dependency.
const MaxDependsOn = 1000

// MaxDepProperties bounds the properties of one dependency.
const MaxDepProperties = 32

// PurlType returns the type of a package URL ("npm", "golang", "maven"), or
// "" when s is not a package URL.
func PurlType(purl string) string {
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

// CleanPURL bounds a package URL and drops one with control characters or
// whitespace (a hostile value must not reach a receiver's match keys).
func CleanPURL(purl string) string {
	purl = strings.TrimSpace(purl)
	if purl == "" || len(purl) > 2048 || PurlType(purl) == "" {
		return ""
	}
	for _, r := range purl {
		if r <= ' ' || r == 0x7f {
			return ""
		}
	}
	return purl
}

// GoodPURL returns a package URL that has a canonical form, else "".
func GoodPURL(purl string) string {
	purl = CleanPURL(purl)
	if purl == "" {
		return ""
	}
	if _, _, err := ctis.CanonicalPurl(purl); err != nil {
		return ""
	}
	return purl
}

// PurlName returns the name of a package URL with its namespace
// ("@scope/name", "group:artifact"), unescaped, or "".
func PurlName(purl string) string {
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

// PurlTypes maps OSV ecosystem names and language words to the package URL
// type.
var PurlTypes = map[string]string{
	"npm": "npm", "pypi": "pypi", "pip": "pypi", "maven": "maven", "gradle": "maven",
	"nuget": "nuget", "cargo": "cargo", "crates.io": "cargo", "golang": "golang", "go": "golang",
	"composer": "composer", "packagist": "composer", "gem": "gem", "rubygems": "gem",
	"hex": "hex", "pub": "pub", "swift": "swift", "swifturl": "swift", "cocoapods": "cocoapods",
}

// PurlOf builds a package URL from an OSV ecosystem, a name and a version;
// "" when the ecosystem has no package URL type or the result is not a
// canonical package URL.
func PurlOf(ecosystem, name, version string) string {
	typ := PurlTypes[strings.ToLower(strings.TrimSpace(ecosystem))]
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
	return GoodPURL(p)
}

// SeverityFromCVSS bands a CVSS base score (the CVSS v3/v4 qualitative
// scale).
func SeverityFromCVSS(score float64) ctis.Severity {
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

// SeverityWord maps a qualitative severity word of an advisory database
// (CRITICAL, HIGH, MODERATE, MEDIUM, LOW, NONE, INFO).
func SeverityWord(s string) (ctis.Severity, bool) {
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

// CvssVectorScore returns a CVSS score of a vector string with no value.
func CvssVectorScore(vector, source string) (ctis.Score, bool) {
	vector = Line(vector, ctis.MaxScoreVectorLen)
	ver := ctis.CVSSVersionOfVector(vector)
	if ver == "" {
		return ctis.Score{}, false
	}
	return ctis.Score{System: ctis.ScoreSystemCVSS, Version: ver, Vector: vector, Source: Line(source, ctis.MaxScoreSourceLen)}, true
}

// SubjectAssetOf chooses the asset type and value of an SBOM subject (a
// CycloneDX metadata component, an SPDX root package): a container is an
// image when its name and version make an image reference, a component with
// a package URL is that package, anything else is unclassified, named by
// name and version (or fallback).
func SubjectAssetOf(kind, purl, name, version, fallback string) (ctis.AssetType, string) {
	if strings.EqualFold(strings.TrimSpace(kind), "container") && name != "" {
		ref := name
		if strings.HasPrefix(version, "sha256:") {
			ref += "@" + version
		}
		if c, err := ctis.CanonicalImage(ref); err == nil {
			return ctis.AssetTypeContainerImage, c
		}
	}
	if purl = GoodPURL(purl); purl != "" {
		return ctis.AssetTypePackage, purl
	}
	v := NameVersion(name, version)
	if v == "" {
		v = fallback
	}
	return ctis.AssetTypeUnclassified, v
}

// CvssOrder ranks CVSS versions: the newest version wins.
func CvssOrder(version string) int {
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

// AddDepProperty sets a bounded dependency property.
func AddDepProperty(d *ctis.Dependency, key, value string) {
	value = Line(value, CapShort*4)
	if value == "" {
		return
	}
	if d.Properties == nil {
		d.Properties = ctis.Properties{}
	}
	if _, ok := d.Properties[key]; !ok && len(d.Properties) >= MaxDepProperties {
		return
	}
	d.Properties[key] = value
}

// NameVersion returns "name@version", or the name alone.
func NameVersion(name, version string) string {
	if version == "" {
		return name
	}
	return name + "@" + version
}

// FloatString formats a score for a native value.
func FloatString(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

func FirstNonEmpty(vals ...string) string {
	for _, s := range vals {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return ""
}

func AppendUnique(dst []string, s string) []string {
	for _, d := range dst {
		if d == s {
			return dst
		}
	}
	return append(dst, s)
}

// StripUserinfo removes credentials from a URL (https://user:pass@host/).
func StripUserinfo(s string) string {
	if !strings.Contains(s, "@") || !strings.Contains(s, "://") {
		return s
	}
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		return s
	}
	u.User = nil
	return u.String()
}

// RepoAsset is a repository asset with the branch and commit it was scanned
// at, and where the importer learned it (properties.source). It carries no
// criticality: that is the receiver's call (CTIS spec 4.1).
func RepoAsset(value, branch, commit, source string) ctis.Asset {
	value = Line(value, CapShort)
	if c, err := ctis.CanonicalAssetValue(ctis.AssetTypeRepository, value); err == nil {
		value = c
	}
	props := ctis.Properties{"source": source}
	if b := Line(branch, CapShort); b != "" {
		props["branch"] = b
	}
	if c := Line(commit, 128); c != "" {
		props["commit_sha"] = c
	}
	return ctis.Asset{ID: CodeAssetID, Type: ctis.AssetTypeRepository, Value: value, Name: value, Properties: props}
}

// ProbeTime is any non-zero time: Validate requires metadata.generated_at.
var ProbeTime = time.Unix(1, 0).UTC()

// ProbeID is a UUIDv7: Validate requires metadata.id.
const ProbeID = "0192f0a0-0000-7000-8000-000000000001"

// Probe is the smallest valid report, for checking one value with Validate.
func Probe() ctis.Report {
	return ctis.Report{Version: ctis.SchemaVersion, Metadata: ctis.ReportMetadata{ID: ProbeID, GeneratedAt: ProbeTime}}
}

// CodeAssetID is the id of the one asset of a code report.
const CodeAssetID = "asset-1"
