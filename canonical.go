package ctis

import (
	"crypto/sha1" // UUIDv5 is defined over SHA-1 (RFC 9562); not a security use
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Canonical forms (spec section 5.3). Each function returns the one
// spelling of a value that receivers key on, so two producers that write
// the same thing differently agree. Receivers compute canonical values and
// asset keys themselves and never trust a producer's.
//
// Domain names use an IDNA-lite mapping: Unicode lowercase, the ideographic
// full stops read as dots, and each non-ASCII label encoded as an A-label
// with Punycode (RFC 3492). There is no UTS 46 mapping beyond lowercase and
// no Unicode normalisation (NFC): a name that differs only in composed and
// decomposed form gives two A-labels. Producers that hold a name in Unicode
// SHOULD send it NFC-normalised; the conformance vectors list what is and is
// not covered.

// ErrNotCanonicalizable is wrapped by every error of the Canonical*
// functions.
var ErrNotCanonicalizable = errors.New("ctis: value has no canonical form")

func canonErr(kind, v, why string) error {
	return fmt.Errorf("%w: %s %q: %s", ErrNotCanonicalizable, kind, truncateForError(v), why)
}

// AssetKeyNamespace is the published UUID namespace of CTIS asset keys:
// uuidv5(NAMESPACE_URL, "urn:ctis:asset-key").
const AssetKeyNamespace = "9678743b-b91d-59fa-b168-ed192fe9eed3"

var assetKeyNS = mustUUIDBytes(AssetKeyNamespace)

// AssetKey returns the deterministic key of an asset:
// uuidv5(AssetKeyNamespace, type + 0x1F + canonicalValue), lowercase. The
// value MUST already be canonical for the type; AssetKey does not
// canonicalize it.
func AssetKey(t AssetType, canonicalValue string) string {
	h := sha1.New()
	h.Write(assetKeyNS[:])
	h.Write([]byte(string(t) + "\x1f" + canonicalValue))
	sum := h.Sum(nil)
	var u [16]byte
	copy(u[:], sum[:16])
	u[6] = (u[6] & 0x0f) | 0x50 // version 5
	u[8] = (u[8] & 0x3f) | 0x80 // RFC 4122 variant
	return formatUUID(u)
}

func mustUUIDBytes(s string) [16]byte {
	var u [16]byte
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		panic("ctis: bad UUID " + s)
	}
	copy(u[:], b)
	return u
}

func formatUUID(u [16]byte) string {
	h := hex.EncodeToString(u[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// =============================================================================
// Names and addresses
// =============================================================================

const (
	maxDomainLen = 253
	maxLabelLen  = 63
)

// CanonicalDomain returns a domain name trimmed, lowercase, with no trailing
// dot, each non-ASCII label as an A-label ("xn--..."). A wildcard label, an
// empty label, a label over 63 bytes, a name over 253 bytes, and characters
// other than letters, digits, hyphen and underscore are refused.
func CanonicalDomain(s string) (string, error) {
	name := strings.TrimSpace(s)
	name = strings.NewReplacer("。", ".", "．", ".", "｡", ".").Replace(name)
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return "", canonErr("domain", s, "empty")
	}
	if !utf8.ValidString(name) {
		return "", canonErr("domain", s, "not UTF-8")
	}
	labels := strings.Split(strings.ToLower(name), ".")
	for i, l := range labels {
		if l == "" {
			return "", canonErr("domain", s, "empty label")
		}
		if l == "*" {
			return "", canonErr("domain", s, "wildcard label (a certificate attribute, not an asset)")
		}
		if !isASCII(l) {
			enc, err := punycodeEncode(l)
			if err != nil {
				return "", canonErr("domain", s, err.Error())
			}
			l = "xn--" + enc
		}
		if len(l) > maxLabelLen {
			return "", canonErr("domain", s, "label longer than 63 bytes")
		}
		for j := 0; j < len(l); j++ {
			c := l[j]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				return "", canonErr("domain", s, "invalid character")
			}
		}
		labels[i] = l
	}
	out := strings.Join(labels, ".")
	if len(out) > maxDomainLen {
		return "", canonErr("domain", s, "longer than 253 bytes")
	}
	return out, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// CanonicalIP returns an IP address in canonical form: IPv4 dotted quad
// without leading zeros, IPv6 per RFC 5952, an IPv4-mapped IPv6 address as
// IPv4, and no zone.
func CanonicalIP(s string) (string, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", canonErr("ip", s, "not an IP address")
	}
	return a.WithZone("").Unmap().String(), nil
}

// CanonicalCIDR returns an IP range as a CIDR with its network address
// ("10.0.0.0/8"), IPv6 per RFC 5952; an IPv4-mapped range of /96 or longer
// becomes the IPv4 range.
func CanonicalCIDR(s string) (string, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return "", canonErr("cidr", s, "not a CIDR range")
	}
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked().String(), nil
}

// canonicalHost returns a host as an IP address or a domain name.
func canonicalHost(h string) (string, bool, error) {
	if ip, err := CanonicalIP(strings.Trim(h, "[]")); err == nil {
		return ip, strings.Contains(ip, ":"), nil
	}
	d, err := CanonicalDomain(h)
	return d, false, err
}

// CanonicalService returns "<host>:<port>/<transport>" with the host
// canonical (an IPv6 address in brackets) and the transport tcp, udp or
// sctp.
func CanonicalService(host string, port int, transport string) (string, error) {
	h, v6, err := canonicalHost(host)
	if err != nil {
		return "", err
	}
	if port < 1 || port > 65535 {
		return "", canonErr("service", strconv.Itoa(port), "port outside 1-65535")
	}
	tr := strings.ToLower(strings.TrimSpace(transport))
	if tr != "tcp" && tr != "udp" && tr != "sctp" {
		return "", canonErr("service", transport, "transport is not tcp, udp or sctp")
	}
	if v6 {
		h = "[" + h + "]"
	}
	return h + ":" + strconv.Itoa(port) + "/" + tr, nil
}

// =============================================================================
// Web origins and URLs
// =============================================================================

// CanonicalOrigin returns the origin of an http or https URL:
// "scheme://host[:port]", scheme and host lowercase, the host canonical,
// the default port dropped.
func CanonicalOrigin(s string) (string, error) {
	u, host, err := parseWebURL(s)
	if err != nil {
		return "", err
	}
	return u.Scheme + "://" + host, nil
}

// CanonicalURL returns an http or https URL in canonical form: the origin
// (CanonicalOrigin), the path with its case kept, percent-encoding
// uppercased and unreserved characters decoded, dot segments removed, and
// the query parameter names only, sorted and without duplicates. User info,
// fragment and query values are dropped.
func CanonicalURL(s string) (string, error) {
	u, host, err := parseWebURL(s)
	if err != nil {
		return "", err
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	path = removeDotSegments(normalizePercent(path))
	out := u.Scheme + "://" + host + path
	if u.RawQuery != "" {
		seen := map[string]bool{}
		var names []string
		for _, kv := range strings.Split(u.RawQuery, "&") {
			name, _, _ := strings.Cut(kv, "=")
			name = normalizePercent(name)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			names = append(names, name)
		}
		sort.Strings(names)
		if len(names) > 0 {
			out += "?" + strings.Join(names, "&")
		}
	}
	return out, nil
}

func parseWebURL(s string) (*url.URL, string, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return nil, "", canonErr("url", s, "not a URL")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, "", canonErr("url", s, "scheme is not http or https")
	}
	h, v6, err := canonicalHost(u.Hostname())
	if err != nil {
		return nil, "", err
	}
	if v6 {
		h = "[" + h + "]"
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, "", canonErr("url", s, "bad port")
		}
		defaultPort := (u.Scheme == "http" && n == 80) || (u.Scheme == "https" && n == 443)
		if !defaultPort {
			h += ":" + strconv.Itoa(n)
		}
	}
	return u, h, nil
}

func isUnreserved(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// normalizePercent uppercases percent-encodings and decodes the unreserved
// characters (RFC 3986 section 6.2.2).
func normalizePercent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' && i+2 < len(s) {
			hi, ok1 := unhex(s[i+1])
			lo, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				v := hi<<4 | lo
				if isUnreserved(v) {
					b.WriteByte(v)
				} else {
					b.WriteString("%" + strings.ToUpper(s[i+1:i+3]))
				}
				i += 2
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

// removeDotSegments is RFC 3986 section 5.2.4 for an absolute path.
func removeDotSegments(p string) string {
	in := strings.Split(p, "/")
	var out []string
	for i, seg := range in {
		last := i == len(in)-1
		switch seg {
		case ".":
			if last {
				out = append(out, "")
			}
		case "..":
			if len(out) > 1 {
				out = out[:len(out)-1]
			}
			if last {
				out = append(out, "")
			}
		default:
			out = append(out, seg)
		}
	}
	r := strings.Join(out, "/")
	if !strings.HasPrefix(r, "/") {
		r = "/" + r
	}
	return r
}

// =============================================================================
// Packages and platforms
// =============================================================================

// purlLowercaseTypes are the purl types whose namespace and name are
// case-insensitive (purl types specification).
var purlLowercaseTypes = map[string]bool{
	"bitbucket": true, "github": true, "npm": true, "pypi": true, "composer": true, "hex": true,
}

// CanonicalPurl splits a package URL into its identity, the versionless
// purl "pkg:<type>/<namespace>/<name>" in canonical form, and its version.
// The type is lowercase; namespace and name are lowercase for the types
// whose names are case-insensitive (bitbucket, github, npm, pypi,
// composer, hex), and a pypi name has "_" replaced by "-". Segments are
// percent-encoded minimally (everything but unreserved characters).
// Qualifiers and subpath are not part of the identity.
func CanonicalPurl(s string) (identity, version string, err error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), "pkg:")
	if !ok {
		return "", "", canonErr("purl", s, "no pkg: scheme")
	}
	rest = strings.TrimLeft(rest, "/")
	rest, _, _ = strings.Cut(rest, "#")
	rest, _, _ = strings.Cut(rest, "?")
	if at := strings.LastIndex(rest, "@"); at >= 0 && !strings.Contains(rest[at:], "/") {
		v, err := url.PathUnescape(rest[at+1:])
		if err != nil {
			return "", "", canonErr("purl", s, "bad version encoding")
		}
		version, rest = v, rest[:at]
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) < 2 {
		return "", "", canonErr("purl", s, "needs a type and a name")
	}
	typ := strings.ToLower(parts[0])
	if typ == "" || strings.Trim(typ, "abcdefghijklmnopqrstuvwxyz0123456789.+-") != "" {
		return "", "", canonErr("purl", s, "bad type")
	}
	segs := make([]string, 0, len(parts)-1)
	for i, p := range parts[1:] {
		if p == "" {
			continue
		}
		d, err := url.PathUnescape(p)
		if err != nil {
			return "", "", canonErr("purl", s, "bad percent-encoding")
		}
		if purlLowercaseTypes[typ] {
			d = strings.ToLower(d)
		}
		if typ == "pypi" && i == len(parts)-2 {
			d = strings.ReplaceAll(d, "_", "-")
		}
		segs = append(segs, purlEscape(d))
	}
	if len(segs) == 0 {
		return "", "", canonErr("purl", s, "no name")
	}
	return "pkg:" + typ + "/" + strings.Join(segs, "/"), version, nil
}

func purlEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreserved(c) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// CanonicalCPE returns a CPE 2.3 formatted string binding, lowercase, with
// 13 colon-separated parts ("cpe:2.3:a:vendor:product:..."). A CPE 2.2 URI
// ("cpe:/a:vendor:product:version") without percent-encoding is bound to the
// 2.3 form, missing components as "*".
func CanonicalCPE(s string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	if uri, ok := strings.CutPrefix(v, "cpe:/"); ok {
		if strings.ContainsAny(uri, "%~") {
			return "", canonErr("cpe", s, "CPE 2.2 URI with encoding or packed edition is not supported")
		}
		comps := strings.Split(uri, ":")
		if len(comps) > 7 {
			return "", canonErr("cpe", s, "too many components")
		}
		for len(comps) < 11 {
			comps = append(comps, "*")
		}
		for i, c := range comps {
			if c == "" {
				comps[i] = "*"
			}
		}
		v = "cpe:2.3:" + strings.Join(comps, ":")
	}
	parts := splitCPE(v)
	if len(parts) != 13 || parts[0] != "cpe" || parts[1] != "2.3" {
		return "", canonErr("cpe", s, "not a CPE 2.3 formatted string")
	}
	if p := parts[2]; p != "a" && p != "o" && p != "h" && p != "*" {
		return "", canonErr("cpe", s, "part is not a, o or h")
	}
	for i, c := range parts {
		if c == "" {
			parts[i] = "*"
		}
	}
	return strings.Join(parts, ":"), nil
}

// splitCPE splits on colons not escaped by a backslash.
func splitCPE(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case ':':
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// =============================================================================
// Cloud resources and images
// =============================================================================

// CanonicalARN returns an Amazon Resource Name as issued, with partition,
// service and region lowercase ("arn:aws:s3:::bucket").
func CanonicalARN(s string) (string, error) {
	parts := strings.SplitN(strings.TrimSpace(s), ":", 6)
	if len(parts) != 6 || !strings.EqualFold(parts[0], "arn") || parts[1] == "" || parts[2] == "" || parts[5] == "" {
		return "", canonErr("arn", s, "not arn:partition:service:region:account:resource")
	}
	for i := 0; i <= 3; i++ {
		parts[i] = strings.ToLower(parts[i])
	}
	return strings.Join(parts, ":"), nil
}

// CanonicalAzureResourceID returns an Azure Resource Manager id lowercase
// (ARM ids are case-insensitive), without a trailing slash.
func CanonicalAzureResourceID(s string) (string, error) {
	v := strings.TrimRight(strings.ToLower(strings.TrimSpace(s)), "/")
	if !strings.HasPrefix(v, "/subscriptions/") && !strings.HasPrefix(v, "/providers/") {
		return "", canonErr("azure resource id", s, "does not start with /subscriptions/ or /providers/")
	}
	if strings.Contains(v, "//") {
		return "", canonErr("azure resource id", s, "empty segment")
	}
	return v, nil
}

// CanonicalGCPResourceName returns a Google Cloud full resource name
// "//<service>.googleapis.com/<path>", the service host lowercase, the path
// as given, without a trailing slash.
func CanonicalGCPResourceName(s string) (string, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), "//")
	host, path, found := strings.Cut(rest, "/")
	host = strings.ToLower(host)
	if !ok || !found || !strings.HasSuffix(host, ".googleapis.com") || len(host) == len(".googleapis.com") {
		return "", canonErr("gcp resource name", s, "not //<service>.googleapis.com/<path>")
	}
	path = strings.TrimRight(path, "/")
	if path == "" || strings.Contains(path, "//") {
		return "", canonErr("gcp resource name", s, "empty path segment")
	}
	return "//" + host + "/" + path, nil
}

// CanonicalImage returns a container image reference as
// "<registry>/<repository>@sha256:<digest>": Docker Hub names expanded to
// docker.io (and docker.io/library for an official image), the registry
// lowercase, the digest lowercase hex. The tag is an attribute, not
// identity: a reference without a digest returns "<registry>/<repository>",
// which names the repository, not one image.
func CanonicalImage(s string) (string, error) {
	ref := strings.TrimSpace(s)
	var digest string
	if name, d, ok := strings.Cut(ref, "@"); ok {
		algo, hexd, ok := strings.Cut(strings.ToLower(d), ":")
		if !ok || algo != "sha256" || len(hexd) != 64 || strings.Trim(hexd, "0123456789abcdef") != "" {
			return "", canonErr("image", s, "digest is not sha256:<64 hex>")
		}
		ref, digest = name, "sha256:"+hexd
	}
	registry, repo := "docker.io", ref
	if first, rest, ok := strings.Cut(ref, "/"); ok && (strings.ContainsAny(first, ".:") || first == "localhost") {
		registry, repo = strings.ToLower(first), rest
	}
	if registry == "index.docker.io" || registry == "registry-1.docker.io" {
		registry = "docker.io"
	}
	// The tag follows the last colon after the last slash.
	if i := strings.LastIndex(repo, ":"); i > strings.LastIndex(repo, "/") {
		repo = repo[:i]
	}
	if repo == "" || strings.Trim(repo, "abcdefghijklmnopqrstuvwxyz0123456789._-/") != "" ||
		strings.HasPrefix(repo, "/") || strings.HasSuffix(repo, "/") || strings.Contains(repo, "//") {
		return "", canonErr("image", s, "repository is not lowercase [a-z0-9._-/] path")
	}
	if registry == "docker.io" && !strings.Contains(repo, "/") {
		repo = "library/" + repo
	}
	out := registry + "/" + repo
	if digest != "" {
		out += "@" + digest
	}
	return out, nil
}

// CanonicalCertificateFingerprint returns a certificate SHA-256 fingerprint
// (of the DER) as 64 lowercase hex digits; colons and spaces are removed.
func CanonicalCertificateFingerprint(s string) (string, error) {
	v := strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(s)))
	if len(v) != 64 || strings.Trim(v, "0123456789abcdef") != "" {
		return "", canonErr("certificate fingerprint", s, "not 64 hex digits")
	}
	return v, nil
}

// =============================================================================
// Punycode (RFC 3492), encoder only
// =============================================================================

const (
	pcBase        = 36
	pcTMin        = 1
	pcTMax        = 26
	pcSkew        = 38
	pcDamp        = 700
	pcInitialBias = 72
	pcInitialN    = 128
)

func punycodeEncode(label string) (string, error) {
	runes := []rune(label)
	var out []byte
	for _, r := range runes {
		if r < 0x80 {
			out = append(out, byte(r))
		}
		if r == utf8.RuneError || unicode.Is(unicode.Cs, r) {
			return "", errors.New("invalid code point")
		}
	}
	basic := len(out)
	h := basic
	if basic > 0 {
		out = append(out, '-')
	}
	n, delta, bias := rune(pcInitialN), 0, pcInitialBias
	for h < len(runes) {
		m := rune(0x10FFFF + 1)
		for _, r := range runes {
			if r >= n && r < m {
				m = r
			}
		}
		if int(m-n) > (1<<31-1-delta)/(h+1) {
			return "", errors.New("punycode overflow")
		}
		delta += int(m-n) * (h + 1)
		n = m
		for _, r := range runes {
			if r < n {
				delta++
			}
			if r == n {
				q := delta
				for k := pcBase; ; k += pcBase {
					t := k - bias
					if t < pcTMin {
						t = pcTMin
					} else if t > pcTMax {
						t = pcTMax
					}
					if q < t {
						break
					}
					out = append(out, punyDigit(t+(q-t)%(pcBase-t)))
					q = (q - t) / (pcBase - t)
				}
				out = append(out, punyDigit(q))
				bias = punyAdapt(delta, h+1, h == basic)
				delta = 0
				h++
			}
		}
		delta++
		n++
	}
	return string(out), nil
}

func punyDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}

func punyAdapt(delta, numPoints int, first bool) int {
	if first {
		delta /= pcDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((pcBase-pcTMin)*pcTMax)/2 {
		delta /= pcBase - pcTMin
		k += pcBase
	}
	return k + (pcBase-pcTMin+1)*delta/(delta+pcSkew)
}
