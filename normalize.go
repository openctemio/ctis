package ctis

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxAssetValueLen bounds asset.value.
const MaxAssetValueLen = 2048

// CanonicalAssetValue returns value in the canonical form of asset type t
// (spec section "Canonical forms"), or an error when value has no canonical
// form for t. The asset key is AssetKey(t, canonical value). Types without a
// structured form (a web application name, an identity) are trimmed and must
// not contain control characters.
func CanonicalAssetValue(t AssetType, value string) (string, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return "", canonErr(string(t), value, "empty")
	}
	switch t {
	case AssetTypeDomainName:
		return CanonicalDomain(v)
	case AssetTypeIPAddress:
		return CanonicalIP(v)
	case AssetTypeIPRange:
		return CanonicalCIDR(v)
	case AssetTypeHost:
		h, _, err := canonicalHost(v)
		return h, err
	case AssetTypeService:
		return canonicalServiceValue(v)
	case AssetTypeWebOrigin:
		return CanonicalOrigin(v)
	case AssetTypeRepository:
		return CanonicalRepository(v)
	case AssetTypePackage:
		id, _, err := CanonicalPurl(v)
		return id, err
	case AssetTypeContainerImage:
		return CanonicalImage(v)
	case AssetTypeCertificate:
		return CanonicalCertificateFingerprint(v)
	case AssetTypeAutonomousSystem:
		return canonicalASN(v)
	case AssetTypeCloudResource, AssetTypeCloudAccount, AssetTypeStorage, AssetTypeDatabase, AssetTypeServerless:
		return canonicalCloudID(v)
	}
	if hasControlRune(v) {
		return "", canonErr(string(t), value, "control character")
	}
	return v, nil
}

// NormalizeAssetName returns the canonical value of name for type t, or the
// trimmed name when it has no canonical form (a receiver then refuses the
// asset in Validate).
func NormalizeAssetName(t AssetType, name string) string {
	if c, err := CanonicalAssetValue(t, name); err == nil {
		return c
	}
	return strings.TrimSpace(name)
}

// canonicalServiceValue parses "host:port/transport" ("[v6]:port/transport")
// and returns it canonical.
func canonicalServiceValue(v string) (string, error) {
	hp, tr, ok := strings.Cut(v, "/")
	if !ok {
		return "", canonErr("service", v, "not host:port/transport")
	}
	i := strings.LastIndex(hp, ":")
	if i <= 0 {
		return "", canonErr("service", v, "not host:port/transport")
	}
	port, err := strconv.Atoi(hp[i+1:])
	if err != nil {
		return "", canonErr("service", v, "port is not a number")
	}
	return CanonicalService(hp[:i], port, tr)
}

// canonicalASN returns "AS<number>" for "AS64500", "as64500" or "64500".
func canonicalASN(v string) (string, error) {
	n := strings.TrimPrefix(strings.TrimPrefix(v, "AS"), "as")
	if n == "" || len(n) > 10 || !allDigits(n) || (len(n) > 1 && n[0] == '0') {
		return "", canonErr("autonomous system", v, "not AS<number>")
	}
	x, err := strconv.ParseUint(n, 10, 32)
	if err != nil {
		return "", canonErr("autonomous system", v, "number outside 0-4294967295")
	}
	return "AS" + strconv.FormatUint(x, 10), nil
}

// canonicalCloudID returns an ARN, an Azure resource id or a GCP full
// resource name in canonical form; another provider id is kept as given.
func canonicalCloudID(v string) (string, error) {
	switch {
	case strings.HasPrefix(strings.ToLower(v), "arn:"):
		return CanonicalARN(v)
	case strings.HasPrefix(v, "/"):
		if strings.HasPrefix(v, "//") {
			return CanonicalGCPResourceName(v)
		}
		return CanonicalAzureResourceID(v)
	}
	if hasControlRune(v) {
		return "", canonErr("cloud id", v, "control character")
	}
	return v, nil
}

// caseInsensitiveSCMHosts are source-code hosts whose owner and repository
// names are case-insensitive, so their canonical form is lowercase.
var caseInsensitiveSCMHosts = map[string]bool{
	"github.com": true, "gitlab.com": true, "bitbucket.org": true, "codeberg.org": true,
}

// CanonicalRepository returns a repository as "<host>/<owner path>/<name>":
// no scheme, user info, port-less host lowercase, no ".git", no trailing
// slash. scp-style "git@host:owner/name" is accepted. The owner path and
// name are lowercase on hosts known to be case-insensitive and kept as given
// elsewhere.
func CanonicalRepository(s string) (string, error) {
	v := strings.TrimSpace(s)
	if i := strings.Index(v, "://"); i > 0 {
		v = v[i+3:]
	} else if at := strings.Index(v, "@"); at >= 0 && strings.Contains(v[at:], ":") && !strings.Contains(v[:at], "/") {
		// scp-like: user@host:owner/name
		rest := v[at+1:]
		h, p, _ := strings.Cut(rest, ":")
		v = h + "/" + p
	}
	if at := strings.LastIndex(v, "@"); at >= 0 && at < strings.Index(v+"/", "/") {
		v = v[at+1:]
	}
	v = strings.TrimRight(v, "/")
	v = strings.TrimSuffix(v, ".git")
	host, path, ok := strings.Cut(v, "/")
	if !ok || path == "" {
		return "", canonErr("repository", s, "not host/owner/name")
	}
	if h, _, found := strings.Cut(host, ":"); found {
		host = h
	}
	host, err := CanonicalDomain(host)
	if err != nil {
		return "", err
	}
	if strings.Contains(path, "//") || hasControlRune(path) || strings.ContainsAny(path, " ?#") {
		return "", canonErr("repository", s, "invalid owner path or name")
	}
	if caseInsensitiveSCMHosts[host] {
		path = strings.ToLower(path)
	}
	return host + "/" + path, nil
}

// truncateUTF8 cuts s to at most maxBytes bytes on a character boundary.
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
