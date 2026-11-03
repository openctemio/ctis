package ctis

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Normalizers and mapping tables for the interoperability members. Each
// mapping returns ok=false for a value it does not know instead of guessing,
// so the caller keeps the native value and decides; none of them ever
// replaces the native value.

// token lower-cases s and folds spaces and hyphens to underscores, so
// "Re-Opened", "re opened" and "re_opened" compare equal.
func token(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.NewReplacer(" ", "_", "-", "_").Replace(s)
}

// nativeSeverityTables map a scheme's native severity (as a token) to a CTIS
// severity.
//
//   - nessus: plugin severity 0-4 (0 None/Info, 1 Low, 2 Medium, 3 High,
//     4 Critical) or its label.
//   - qualys: SEVERITY 1-5 (1 Minimal, 2 Medium, 3 Serious, 4 Critical,
//     5 Urgent), mapped one band each: info, low, medium, high, critical.
//   - defectdojo: the severity labels Critical, High, Medium, Low, Info.
//   - sarif: result level error, warning, note, none (the same mapping
//     FromSARIF uses).
var nativeSeverityTables = map[NativeScheme]map[string]Severity{
	NativeSchemeNessus: {
		"0": SeverityInfo, "1": SeverityLow, "2": SeverityMedium, "3": SeverityHigh, "4": SeverityCritical,
		"none": SeverityInfo, "info": SeverityInfo, "informational": SeverityInfo,
		"low": SeverityLow, "medium": SeverityMedium, "high": SeverityHigh, "critical": SeverityCritical,
	},
	NativeSchemeQualys: {
		"1": SeverityInfo, "2": SeverityLow, "3": SeverityMedium, "4": SeverityHigh, "5": SeverityCritical,
		"minimal": SeverityInfo, "serious": SeverityMedium, "urgent": SeverityCritical,
	},
	NativeSchemeDefectDojo: {
		"critical": SeverityCritical, "high": SeverityHigh, "medium": SeverityMedium, "low": SeverityLow,
		"info": SeverityInfo, "informational": SeverityInfo,
	},
	NativeSchemeSARIF: {
		"error": SeverityHigh, "warning": SeverityMedium, "note": SeverityLow, "none": SeverityInfo,
	},
}

// NormalizeNativeSeverity maps a native severity of the given scheme to a CTIS
// severity. Unknown schemes and values return ok=false.
func NormalizeNativeSeverity(scheme NativeScheme, native string) (Severity, bool) {
	sev, ok := nativeSeverityTables[scheme][token(native)]
	return sev, ok
}

// nativeStatus is one row of a status mapping table: the finding status and
// the source state a native status stands for. An empty state means the
// native value is a disposition (false positive, risk accepted), not a
// lifecycle state.
type nativeStatus struct {
	status FindingStatus
	state  SourceState
}

// nativeStatusTables map a scheme's native status (as a token).
//
//   - nessus: vulnerability states of the Tenable export APIs (new, open,
//     reopened, fixed) and of Tenable.sc (active, mitigated).
//   - qualys: detection STATUS New, Active, Re-Opened, Fixed.
//   - defectdojo: the finding flags active, verified, mitigated, inactive,
//     false_positive, risk_accepted, out_of_scope, duplicate.
//   - sarif: baselineState new, unchanged, updated, absent.
var nativeStatusTables = map[NativeScheme]map[string]nativeStatus{
	NativeSchemeNessus: {
		"new":       {FindingStatusOpen, SourceStateNew},
		"open":      {FindingStatusOpen, SourceStateActive},
		"active":    {FindingStatusOpen, SourceStateActive},
		"reopened":  {FindingStatusOpen, SourceStateReopened},
		"re_opened": {FindingStatusOpen, SourceStateReopened},
		"fixed":     {FindingStatusResolved, SourceStateFixed},
		"mitigated": {FindingStatusResolved, SourceStateFixed},
	},
	NativeSchemeQualys: {
		"new":       {FindingStatusOpen, SourceStateNew},
		"active":    {FindingStatusOpen, SourceStateActive},
		"re_opened": {FindingStatusOpen, SourceStateReopened},
		"reopened":  {FindingStatusOpen, SourceStateReopened},
		"fixed":     {FindingStatusResolved, SourceStateFixed},
	},
	NativeSchemeDefectDojo: {
		"active":         {FindingStatusOpen, SourceStateActive},
		"verified":       {FindingStatusOpen, SourceStateActive},
		"mitigated":      {FindingStatusResolved, SourceStateFixed},
		"is_mitigated":   {FindingStatusResolved, SourceStateFixed},
		"inactive":       {FindingStatusResolved, ""},
		"false_positive": {FindingStatusFalsePositive, ""},
		"risk_accepted":  {FindingStatusAcceptedRisk, ""},
		"out_of_scope":   {FindingStatusSuppressed, ""},
		"duplicate":      {FindingStatusSuppressed, ""},
	},
	NativeSchemeSARIF: {
		"new":       {FindingStatusOpen, SourceStateNew},
		"unchanged": {FindingStatusOpen, SourceStateActive},
		"updated":   {FindingStatusOpen, SourceStateActive},
		"absent":    {FindingStatusResolved, SourceStateFixed},
	},
}

// NormalizeNativeStatus maps a native status of the given scheme to a CTIS
// finding status and a source state. state is empty when the native value is
// a disposition rather than a lifecycle state. Unknown schemes and values
// return ok=false.
//
// A receiver that keeps its own lifecycle should treat status as the source's
// claim: "resolved" means the source no longer sees it, not that it is fixed.
func NormalizeNativeStatus(scheme NativeScheme, native string) (status FindingStatus, state SourceState, ok bool) {
	row, ok := nativeStatusTables[scheme][token(native)]
	return row.status, row.state, ok
}

// NormalizeDetectionType maps a native detection type (Qualys TYPE
// Confirmed / Potential / Info, "vuln", "ig", ...) to a DetectionType.
func NormalizeDetectionType(native string) (DetectionType, bool) {
	switch token(native) {
	case "confirmed", "vuln", "vulnerability":
		return DetectionTypeConfirmed, true
	case "potential", "suspected", "probable", "practice":
		return DetectionTypePotential, true
	case "info", "ig", "information", "informational", "information_gathered":
		return DetectionTypeInfo, true
	}
	return "", false
}

// NormalizeVEXStatus maps a VEX status from CSAF (product_status groups),
// OpenVEX or CycloneDX (analysis.state) to a VEXStatus. A CycloneDX
// false_positive is a disposition of the finding, not an exploitability
// statement, and is not mapped.
func NormalizeVEXStatus(native string) (VEXStatus, bool) {
	switch token(native) {
	case "not_affected", "known_not_affected":
		return VEXStatusNotAffected, true
	case "affected", "known_affected", "exploitable":
		return VEXStatusAffected, true
	case "fixed", "resolved", "resolved_with_pedigree":
		return VEXStatusFixed, true
	case "under_investigation", "in_triage":
		return VEXStatusUnderInvestigation, true
	}
	return "", false
}

// NormalizeVEXJustification maps a not-affected justification from CSAF
// flags, OpenVEX or CycloneDX (analysis.justification) to a VEXJustification.
// The CycloneDX values map to the nearest CSAF/OpenVEX value; keep the source
// word in VEX.NativeJustification.
func NormalizeVEXJustification(native string) (VEXJustification, bool) {
	t := token(native)
	if j := VEXJustification(t); j.IsValid() {
		return j, true
	}
	switch t {
	case "code_not_present":
		return VEXJustificationVulnerableCodeNotPresent, true
	case "code_not_reachable":
		return VEXJustificationVulnerableCodeNotInExecutePath, true
	case "requires_configuration", "requires_dependency", "requires_environment":
		return VEXJustificationVulnerableCodeCannotBeControlledByAdversary, true
	case "protected_by_compiler", "protected_at_runtime", "protected_at_perimeter", "protected_by_mitigating_control":
		return VEXJustificationInlineMitigationsAlreadyExist, true
	}
	return "", false
}

var (
	cvePattern      = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	ghsaPattern     = regexp.MustCompile(`^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`)
	vendorIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/+\-]*$`)
)

// osvPrefixes are id prefixes of databases that publish in the OSV format
// under their own namespace.
var osvPrefixes = []string{"PYSEC-", "GO-", "RUSTSEC-", "OSV-", "GSD-", "MAL-", "HSEC-", "BIT-"}

// NormalizeVulnerabilityID recognizes a vulnerability id and returns it in
// canonical form with its type: CVE ids upper-case, GHSA ids as
// "GHSA-" plus the lower-case body, OSV database ids with an upper-case
// prefix, anything else as a vendor id. Empty, over-long and malformed ids
// (whitespace, control characters) return ok=false.
func NormalizeVulnerabilityID(raw string) (VulnerabilityID, bool) {
	id := strings.TrimSpace(raw)
	if id == "" || len(id) > MaxVulnerabilityIDLen || !vendorIDPattern.MatchString(id) {
		return VulnerabilityID{}, false
	}
	upper := strings.ToUpper(id)
	switch {
	case strings.HasPrefix(upper, "CVE-"):
		if !cvePattern.MatchString(upper) {
			return VulnerabilityID{}, false
		}
		return VulnerabilityID{Type: VulnerabilityIDCVE, ID: upper}, true
	case strings.HasPrefix(upper, "GHSA-"):
		g := "GHSA-" + strings.ToLower(id[5:])
		if !ghsaPattern.MatchString(g) {
			return VulnerabilityID{}, false
		}
		return VulnerabilityID{Type: VulnerabilityIDGHSA, ID: g}, true
	}
	for _, p := range osvPrefixes {
		if strings.HasPrefix(upper, p) && len(id) > len(p) {
			return VulnerabilityID{Type: VulnerabilityIDOSV, ID: p + id[len(p):]}, true
		}
	}
	return VulnerabilityID{Type: VulnerabilityIDVendor, ID: id}, true
}

// canonicalTypedID canonicalizes an id that arrived with a declared type. A
// declared type that contradicts the id's shape (a "cve" that is not a CVE id)
// returns ok=false; a vendor or OSV id keeps the declared type.
func canonicalTypedID(in VulnerabilityID) (VulnerabilityID, bool) {
	n, ok := NormalizeVulnerabilityID(in.ID)
	if !ok || !in.Type.IsValid() {
		return VulnerabilityID{}, false
	}
	switch in.Type {
	case VulnerabilityIDCVE, VulnerabilityIDGHSA:
		if n.Type != in.Type {
			return VulnerabilityID{}, false
		}
	default:
		n.Type = in.Type
	}
	n.Source = strings.TrimSpace(in.Source)
	return n, true
}

// VulnerabilityIDs returns every id of a vulnerability, canonical and without
// duplicates, in the order of vulnerability.ids, at most MaxVulnerabilityIDs.
// Invalid entries are skipped.
func VulnerabilityIDs(v *VulnerabilityDetails) []VulnerabilityID {
	if v == nil {
		return nil
	}
	var out []VulnerabilityID
	seen := map[string]bool{}
	for _, raw := range v.IDs {
		id, ok := canonicalTypedID(raw)
		if !ok || len(out) >= MaxVulnerabilityIDs {
			continue
		}
		k := string(id.Type) + "\x00" + id.ID
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, id)
	}
	return out
}

// CVEs returns the CVE ids of a vulnerability, canonical, in order.
func CVEs(v *VulnerabilityDetails) []string {
	var out []string
	for _, id := range VulnerabilityIDs(v) {
		if id.Type == VulnerabilityIDCVE {
			out = append(out, id.ID)
		}
	}
	return out
}

// AddID adds a vulnerability id to v.IDs: raw is recognized (CVE, GHSA,
// OSV-style ids) by NormalizeVulnerabilityID, else kept as a vendor id of the
// given source when source is set. It skips duplicates and reports whether
// v.IDs holds the id afterwards.
func (v *VulnerabilityDetails) AddID(raw, source string) bool {
	id, ok := NormalizeVulnerabilityID(raw)
	if !ok {
		raw = strings.TrimSpace(raw)
		if raw == "" || source == "" || len(raw) > MaxVulnerabilityIDLen {
			return false
		}
		id = VulnerabilityID{Type: VulnerabilityIDVendor, ID: raw, Source: source}
	}
	for _, have := range v.IDs {
		if have.Type == id.Type && have.ID == id.ID {
			return true
		}
	}
	if len(v.IDs) >= MaxVulnerabilityIDs {
		return false
	}
	v.IDs = append(v.IDs, id)
	return true
}

// PreferredVulnerabilityID picks the one id receivers key on, so two tools
// that name the same vulnerability differently agree: the numerically
// smallest CVE (by year, then sequence number, so CVE-2021-9999 comes before
// CVE-2021-10000), else the first GHSA, else the first OSV id, else the first
// vendor id. A CVE id that does not parse sorts after every well-formed one,
// by text.
func PreferredVulnerabilityID(v *VulnerabilityDetails) (VulnerabilityID, bool) {
	ids := VulnerabilityIDs(v)
	if len(ids) == 0 {
		return VulnerabilityID{}, false
	}
	for _, typ := range []VulnerabilityIDType{VulnerabilityIDCVE, VulnerabilityIDGHSA, VulnerabilityIDOSV, VulnerabilityIDVendor} {
		var cands []VulnerabilityID
		for _, id := range ids {
			if id.Type == typ {
				cands = append(cands, id)
			}
		}
		if len(cands) == 0 {
			continue
		}
		if typ == VulnerabilityIDCVE {
			sort.SliceStable(cands, func(a, b int) bool { return cveLess(cands[a].ID, cands[b].ID) })
		}
		return cands[0], true
	}
	return VulnerabilityID{}, false
}

// parseCVE splits CVE-YYYY-N+ into its year and sequence digits (sequence
// without leading zeros). It reports false for anything else.
func parseCVE(id string) (year, seq string, ok bool) {
	rest, found := strings.CutPrefix(strings.ToUpper(strings.TrimSpace(id)), "CVE-")
	if !found {
		return "", "", false
	}
	year, seq, found = strings.Cut(rest, "-")
	if !found || year == "" || seq == "" || !allDigits(year) || !allDigits(seq) {
		return "", "", false
	}
	seq = strings.TrimLeft(seq, "0")
	if seq == "" {
		seq = "0"
	}
	return strings.TrimLeft(year, "0"), seq, true
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// numLess compares two digit strings without leading zeros as numbers, so it
// holds for sequence numbers of any length.
func numLess(a, b string) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return a < b
}

// cveLess orders CVE ids by year, then sequence number. Ids that do not parse
// come after those that do and are ordered by text, so the order is total.
func cveLess(a, b string) bool {
	ay, as, aok := parseCVE(a)
	by, bs, bok := parseCVE(b)
	switch {
	case aok && bok:
		if ay != by {
			return numLess(ay, by)
		}
		if as != bs {
			return numLess(as, bs)
		}
		return a < b
	case aok != bok:
		return aok
	default:
		return a < b
	}
}

// maxLocationKeyLen bounds LocationKey; longer keys keep a prefix and a hash.
const maxLocationKeyLen = 512

// LocationKey returns the normalized location of a finding on its asset, the
// location part of a cross-source deduplication key (asset, vulnerability,
// location). The asset is not part of it. In order of precedence:
//
//   - "pkg:<type>/<namespace>/<name>": the package URL without version,
//     qualifiers or subpath;
//   - "url:<scheme>://<host>[:port]/<path>": a web location, lower-case
//     scheme and host, default port, user info, query and fragment removed;
//   - "file:<path>": a repository-relative POSIX path (line numbers are not
//     part of it: they move when unrelated code changes);
//   - "net:<port>/<transport>" or "net:host" for a host-level network finding;
//   - "resource:<type>/<name>" for a misconfigured resource;
//   - "" when the finding names no location.
//
// It is derived, never sent: a receiver computes it so a producer cannot
// choose the key another producer's finding is merged under.
func LocationKey(f *Finding) string {
	if f == nil {
		return ""
	}
	var key string
	switch {
	case f.Vulnerability != nil && versionlessPURL(f.Vulnerability.PURL) != "":
		key = "pkg:" + versionlessPURL(f.Vulnerability.PURL)
	case f.Web != nil && webLocation(f.Web.URL) != "":
		key = "url:" + webLocation(f.Web.URL)
	case f.Location != nil && webLocation(f.Location.Path) != "":
		key = "url:" + webLocation(f.Location.Path)
	case f.Location != nil && strings.TrimSpace(f.Location.Path) != "":
		key = "file:" + repoPath(f.Location.Path)
	case f.Network != nil:
		key = "net:" + networkPort(f.Network)
	case f.Misconfiguration != nil && (f.Misconfiguration.ResourceType != "" || f.Misconfiguration.ResourceName != ""):
		key = "resource:" + strings.TrimSpace(f.Misconfiguration.ResourceType) + "/" + strings.TrimSpace(f.Misconfiguration.ResourceName)
	}
	return boundKey(key)
}

func boundKey(key string) string {
	if len(key) <= maxLocationKeyLen {
		return key
	}
	sum := sha256.Sum256([]byte(key))
	cut := maxLocationKeyLen - 1 - 2*16
	for cut > 0 && !utf8.RuneStart(key[cut]) {
		cut--
	}
	return key[:cut] + "#" + hex.EncodeToString(sum[:16])
}

// versionlessPURL returns "type/namespace/name" of a package URL, or "".
func versionlessPURL(purl string) string {
	p := strings.TrimSpace(purl)
	if !strings.HasPrefix(strings.ToLower(p), "pkg:") {
		return ""
	}
	p = p[4:]
	p = strings.TrimLeft(p, "/")
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if i := strings.LastIndex(p, "@"); i >= 0 {
		p = p[:i]
	}
	typ, rest, ok := strings.Cut(p, "/")
	if !ok || typ == "" || rest == "" {
		return ""
	}
	return strings.ToLower(typ) + "/" + strings.Trim(rest, "/")
}

// webLocation normalizes an http(s) URL to scheme://host[:port]/path, or "".
func webLocation(raw string) string {
	raw = strings.TrimSpace(raw)
	lower := strings.ToLower(raw)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		host += ":" + port
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	return scheme + "://" + host + p
}

// repoPath is a repository-relative POSIX path.
func repoPath(p string) string {
	p = strings.TrimSpace(p)
	if len(p) >= 5 && strings.EqualFold(p[:5], "file:") {
		p = strings.TrimLeft(p[5:], "/")
	}
	p = strings.ReplaceAll(p, `\`, "/")
	return strings.TrimPrefix(path.Clean("/"+p), "/")
}

func networkPort(n *NetworkLocation) string {
	if n.Port <= 0 {
		return "host"
	}
	proto := strings.ToLower(strings.TrimSpace(string(n.Transport)))
	if proto == "" {
		proto = "tcp"
	}
	return strconv.Itoa(n.Port) + "/" + proto
}

// SetSourceExtra stores one unmapped source field on f within the
// source_extra limits. The key is trimmed; a value longer than
// MaxSourceExtraValueLen characters is cut at that length. It returns false
// and stores nothing when the key is empty, too long or holds control
// characters, or when the entry would exceed MaxSourceExtraEntries or
// MaxSourceExtraBytes. Replacing an existing key is allowed within the
// limits.
func SetSourceExtra(f *Finding, key, value string) bool {
	if f == nil {
		return false
	}
	key = strings.TrimSpace(key)
	if !validExtraKey(key) {
		return false
	}
	value = truncateRunes(strings.ToValidUTF8(value, "�"), MaxSourceExtraValueLen)
	old, replacing := f.SourceExtra[key]
	if !replacing && len(f.SourceExtra) >= MaxSourceExtraEntries {
		return false
	}
	total := sourceExtraBytes(f.SourceExtra) + len(key) + len(value)
	if replacing {
		total -= len(key) + len(old)
	}
	if total > MaxSourceExtraBytes {
		return false
	}
	if f.SourceExtra == nil {
		f.SourceExtra = map[string]string{}
	}
	f.SourceExtra[key] = value
	return true
}

func validExtraKey(k string) bool {
	if k == "" || utf8.RuneCountInString(k) > MaxSourceExtraKeyLen || !utf8.ValidString(k) {
		return false
	}
	for _, r := range k {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func sourceExtraBytes(m map[string]string) int {
	n := 0
	for k, v := range m {
		n += len(k) + len(v)
	}
	return n
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	i := 0
	for pos := range s {
		if i == n {
			return s[:pos]
		}
		i++
	}
	return s
}

// CVSSVersionOfVector returns the CVSS version a vector string declares
// ("3.0", "3.1", "4.0"), "2.0" for a prefix-less v2 vector (AV:N/AC:L/...),
// or "" when it is not a CVSS vector.
func CVSSVersionOfVector(vector string) string {
	v := strings.TrimSpace(vector)
	switch {
	case strings.HasPrefix(v, "CVSS:3.0/"):
		return "3.0"
	case strings.HasPrefix(v, "CVSS:3.1/"):
		return "3.1"
	case strings.HasPrefix(v, "CVSS:4.0/"):
		return "4.0"
	case strings.HasPrefix(v, "AV:") || strings.HasPrefix(v, "(AV:"):
		return "2.0"
	}
	return ""
}

// validCVSSVersions are the CVSS versions a cvss score may declare.
var validCVSSVersions = map[string]bool{"2.0": true, "3.0": true, "3.1": true, "4.0": true}

// scoreProblem returns why s is invalid, or "".
func scoreProblem(s Score) string {
	if !s.System.IsValid() {
		return "invalid system " + strconv.Quote(string(s.System))
	}
	if n := utf8.RuneCountInString(s.Vector); n > MaxScoreVectorLen {
		return "vector longer than " + strconv.Itoa(MaxScoreVectorLen)
	}
	if utf8.RuneCountInString(s.Source) > MaxScoreSourceLen {
		return "source longer than " + strconv.Itoa(MaxScoreSourceLen)
	}
	if utf8.RuneCountInString(s.Label) > MaxScoreLabelLen {
		return "label longer than " + strconv.Itoa(MaxScoreLabelLen)
	}
	if utf8.RuneCountInString(s.Version) > MaxScoreLabelLen {
		return "version longer than " + strconv.Itoa(MaxScoreLabelLen)
	}
	if s.Value != nil && (math.IsNaN(*s.Value) || math.IsInf(*s.Value, 0)) {
		return "value is not a finite number"
	}
	val := func(lo, hi float64) string {
		if s.Value != nil && (*s.Value < lo || *s.Value > hi) {
			return "value " + strconv.FormatFloat(*s.Value, 'g', -1, 64) + " is outside " +
				strconv.FormatFloat(lo, 'g', -1, 64) + "-" + strconv.FormatFloat(hi, 'g', -1, 64)
		}
		return ""
	}
	switch s.System {
	case ScoreSystemCVSS:
		if !validCVSSVersions[s.Version] {
			return "cvss score needs version 2.0, 3.0, 3.1 or 4.0"
		}
		if s.Vector != "" {
			if got := CVSSVersionOfVector(s.Vector); got != s.Version && (got != "" || s.Version != "2.0") {
				return "vector does not match cvss version " + s.Version
			}
		}
		if s.Value == nil && s.Vector == "" {
			return "cvss score needs a value or a vector"
		}
		return val(0, 10)
	case ScoreSystemEPSS, ScoreSystemEPSSPercentile:
		return val(0, 1)
	case ScoreSystemSSVC:
		if s.Value != nil {
			return "ssvc has no numeric value"
		}
		if s.Vector == "" && s.Label == "" {
			return "ssvc needs a vector or a label"
		}
	case ScoreSystemVendor:
		if s.Value == nil && s.Label == "" {
			return "vendor score needs a value or a label"
		}
		return val(-maxVendorScoreMagnitude, maxVendorScoreMagnitude)
	}
	return ""
}

// HasThreatSignal reports whether v carries a threat signal of one of the
// types.
func HasThreatSignal(v *VulnerabilityDetails, types ...ThreatSignalType) bool {
	if v == nil {
		return false
	}
	for _, s := range v.ThreatSignals {
		for _, t := range types {
			if s.Type == t {
				return true
			}
		}
	}
	return false
}

// PrimaryCVSS returns the CVSS score of a finding receivers show first: the
// one of the highest version that has a value, else the first CVSS score.
func PrimaryCVSS(f *Finding) (Score, bool) {
	if f == nil {
		return Score{}, false
	}
	best, found := Score{}, false
	for _, s := range f.Scores {
		if s.System != ScoreSystemCVSS {
			continue
		}
		switch {
		case !found:
			best, found = s, true
		case s.Value != nil && (best.Value == nil || s.Version > best.Version):
			best = s
		}
	}
	return best, found
}
