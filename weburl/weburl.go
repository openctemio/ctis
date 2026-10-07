// Package weburl is the one URL library of the web attack surface: the
// sensor, the SDK and the platform parse, normalise and template web URLs
// the same way, so an endpoint found by one tool and one found by another
// land on the same row.
//
//   - Parse is strict: an absolute http(s) URL, no user info, at most
//     MaxURLBytes, valid UTF-8, no control or white-space characters. It
//     returns the normalised URL: lowercase scheme and ASCII host (Punycode
//     for internationalized labels, trailing dot removed, IPv6 in canonical
//     form), the default port dropped, the path normalised (unreserved
//     percent-escapes decoded and the others upper-cased, dot segments
//     resolved, empty segments collapsed, no trailing slash except the root,
//     ";jsessionid=" removed; case kept: paths are case-sensitive), the
//     query reduced to its sorted parameter NAMES (values are never kept)
//     and no fragment.
//   - Template replaces the path segments that are identifiers with a typed
//     variable ({int}, {uuid}, {date}, {email}, {hex}, {token}, {id}; see
//     TemplatePath), so /orders/42 and /orders/43 are one endpoint.
//   - RedactURL removes what a URL must not carry into a report, a log or a
//     database: the user info, every query value and the fragment. It never
//     fails.
//   - PathHash is the dedup key of an endpoint: a hash of its method and
//     template.
//
// Every function is deterministic, uses no network and no regular
// expression that can backtrack (Go's regexp is RE2).
package weburl

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits of a web URL.
const (
	// MaxURLBytes bounds a URL, a path and a template.
	MaxURLBytes = 2048
	// MaxParamNameBytes bounds a query parameter name; a longer one is
	// dropped.
	MaxParamNameBytes = 128
	// MaxParams bounds the parameter names kept from one query.
	MaxParams    = 100
	maxHostBytes = 253
)

// ErrInvalid is the error of every URL Parse refuses.
var ErrInvalid = errors.New("weburl: invalid URL")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
}

// URL is a normalised web URL.
type URL struct {
	// Scheme is "http" or "https".
	Scheme string
	// Host is the ASCII host: a lowercase DNS name or an IP address
	// (IPv6 without brackets).
	Host string
	// Port is the port when it is not the scheme's default, else "".
	Port string
	// Path is the normalised path, "/" for the root.
	Path string
	// Params are the sorted, unique query parameter names.
	Params []string
}

// Parse parses and normalises a web URL (see the package documentation).
func Parse(raw string) (*URL, error) {
	if len(raw) > MaxURLBytes {
		return nil, invalid("longer than %d bytes", MaxURLBytes)
	}
	if !utf8.ValidString(raw) {
		return nil, invalid("not valid UTF-8")
	}
	for _, r := range raw {
		if unicode.IsControl(r) || unicode.IsSpace(r) || unicode.Is(unicode.Bidi_Control, r) {
			return nil, invalid("contains a control or white-space character")
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, invalid("does not parse")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, invalid("not an http or https URL")
	}
	if u.Opaque != "" || u.Host == "" {
		return nil, invalid("not an absolute URL with a host")
	}
	if u.User != nil {
		return nil, invalid("carries user info")
	}
	host, err := normalizeHost(u.Hostname())
	if err != nil {
		return nil, err
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || port[0] == '0' {
			return nil, invalid("port %q", port)
		}
		if (scheme == "http" && n == 80) || (scheme == "https" && n == 443) {
			port = ""
		}
	}
	path, err := NormalizePath(u.EscapedPath())
	if err != nil {
		return nil, err
	}
	out := &URL{Scheme: scheme, Host: host, Port: port, Path: path, Params: QueryNames(u.RawQuery)}
	// Escaping can make the normalised form longer than the input: the
	// limit holds for what is stored, so Parse(u.String()) never fails.
	if len(out.String()) > MaxURLBytes {
		return nil, invalid("longer than %d bytes once normalised", MaxURLBytes)
	}
	return out, nil
}

// normalizeHost is the ASCII form of a host name or an IP address.
func normalizeHost(h string) (string, error) {
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return "", invalid("empty host")
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.String(), nil
	}
	if strings.ContainsAny(h, ":%[]") {
		return "", invalid("host %q", h)
	}
	labels := strings.Split(strings.ToLower(h), ".")
	for i, l := range labels {
		a, err := punycodeLabel(l)
		if err != nil {
			return "", invalid("host label cannot be made ASCII")
		}
		if !validLabel(a) {
			return "", invalid("host label %q", a)
		}
		labels[i] = a
	}
	// A name whose last label is numeric ("2130706433", "0x7f.0.0.1") is
	// an address in another notation for some resolvers: refused rather
	// than treated as a name.
	if last := labels[len(labels)-1]; isNumericLabel(last) {
		return "", invalid("ambiguous numeric host")
	}
	out := strings.Join(labels, ".")
	if len(out) > maxHostBytes {
		return "", invalid("host longer than %d bytes", maxHostBytes)
	}
	return out, nil
}

// isNumericLabel reports whether a label is digits only or a 0x number.
func isNumericLabel(l string) bool {
	if strings.HasPrefix(l, "0x") {
		return true
	}
	for i := 0; i < len(l); i++ {
		if l[i] < '0' || l[i] > '9' {
			return false
		}
	}
	return true
}

// validLabel accepts letters, digits, '-' and '_' (seen in real host
// names), 1 to 63 bytes, not starting or ending with '-'.
func validLabel(l string) bool {
	if l == "" || len(l) > maxLabelBytes || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// Origin is "scheme://host[:port]", the IPv6 host in brackets.
func (u *URL) Origin() string {
	host := u.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if u.Port != "" {
		host += ":" + u.Port
	}
	return u.Scheme + "://" + host
}

// String is the origin and the path: the URL without its query and
// fragment.
func (u *URL) String() string { return u.Origin() + u.Path }

// Template is the path with its identifier segments replaced (TemplatePath).
func (u *URL) Template() string { return TemplatePath(u.Path) }

// Normalize is Parse(raw).String().
func Normalize(raw string) (string, error) {
	u, err := Parse(raw)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// Template parses raw and returns its origin, its path template and its
// query parameter names.
func Template(raw string) (origin, template string, params []string, err error) {
	u, err := Parse(raw)
	if err != nil {
		return "", "", nil, err
	}
	return u.Origin(), u.Template(), u.Params, nil
}

// NormalizePath normalises an escaped URL path: unreserved
// percent-escapes decoded and the others upper-cased (a malformed escape is
// an error), ";jsessionid=..." removed from each segment, dot segments
// resolved, empty segments collapsed, the trailing slash removed except for
// the root. An empty path is "/".
func NormalizePath(p string) (string, error) {
	if len(p) > MaxURLBytes {
		return "", invalid("path longer than %d bytes", MaxURLBytes)
	}
	segs := strings.Split(p, "/")
	out := make([]string, 0, len(segs))
	for _, s := range segs {
		s = stripJSessionID(s)
		s, err := normalizeEscapes(s)
		if err != nil {
			return "", err
		}
		switch s {
		case "", ".":
			continue
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			continue
		}
		out = append(out, s)
	}
	return "/" + strings.Join(out, "/"), nil
}

// stripJSessionID removes every ";jsessionid=..." matrix parameter.
func stripJSessionID(s string) string {
	for {
		i := strings.Index(strings.ToLower(s), ";jsessionid=")
		if i < 0 {
			return s
		}
		rest := s[i+1:]
		if j := strings.IndexByte(rest, ';'); j >= 0 {
			s = s[:i] + rest[j:]
		} else {
			s = s[:i]
		}
	}
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

// normalizeEscapes decodes the percent-escapes of unreserved characters and
// upper-cases the others.
func normalizeEscapes(s string) (string, error) {
	if !strings.Contains(s, "%") {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", invalid("malformed percent-escape")
		}
		hi, ok1 := unhex(s[i+1])
		lo, ok2 := unhex(s[i+2])
		if !ok1 || !ok2 {
			return "", invalid("malformed percent-escape")
		}
		c := hi<<4 | lo
		if c < 0x20 || c == 0x7f {
			return "", invalid("percent-encoded control character")
		}
		if isUnreserved(c) {
			b.WriteByte(c)
		} else {
			b.WriteString("%" + strings.ToUpper(s[i+1:i+3]))
		}
		i += 2
	}
	return b.String(), nil
}

// QueryNames returns the sorted, unique parameter names of a raw query
// ("a=1&b=2&a=3" gives [a b]). Values are never read. A name that does not
// unescape is kept escaped; empty names and names longer than
// MaxParamNameBytes are dropped; at most MaxParams names are kept.
func QueryNames(rawQuery string) []string {
	if rawQuery == "" {
		return nil
	}
	seen := map[string]bool{}
	var names []string
	for _, part := range strings.Split(rawQuery, "&") {
		name, _, _ := strings.Cut(part, "=")
		if n, err := url.QueryUnescape(name); err == nil {
			name = n
		}
		name = strings.TrimSpace(name)
		if name == "" || len(name) > MaxParamNameBytes || !utf8.ValidString(name) || hasControl(name) || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > MaxParams {
		names = names[:MaxParams]
	}
	return names
}

func hasControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// RedactURL returns raw without what must not be stored: the user info,
// every query value (the names are kept, "?a=&b="), and the fragment. A
// value that does not parse as a URL is cut at its first '?' or '#' and its
// user info removed. It never fails and never adds content.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return redactRaw(raw)
	}
	u.User = nil
	u.Fragment, u.RawFragment = "", ""
	if u.RawQuery != "" || u.ForceQuery {
		var parts []string
		for _, p := range strings.Split(u.RawQuery, "&") {
			name, _, _ := strings.Cut(p, "=")
			if name != "" {
				parts = append(parts, name+"=")
			}
		}
		u.RawQuery = strings.Join(parts, "&")
		u.ForceQuery = false
	}
	return u.String()
}

func redactRaw(s string) string {
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "://"); i >= 0 {
		rest := s[i+3:]
		end := strings.IndexAny(rest, "/")
		if end < 0 {
			end = len(rest)
		}
		if at := strings.LastIndex(rest[:end], "@"); at >= 0 {
			s = s[:i+3] + rest[at+1:]
		}
	}
	return s
}

// Methods of an endpoint. MethodAny is an endpoint seen without a method
// (a link of unknown use is GET; ANY is "not known").
const MethodAny = "ANY"

var methods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true,
	"OPTIONS": true, "TRACE": true, "CONNECT": true, MethodAny: true,
}

// NormalizeMethod returns the upper-case method, MethodAny for "", and
// ok false for a method outside the closed set.
func NormalizeMethod(m string) (string, bool) {
	m = strings.ToUpper(strings.TrimSpace(m))
	if m == "" {
		return MethodAny, true
	}
	return m, methods[m]
}

// PathHash is the dedup key of an endpoint within its origin: the hex
// SHA-256 of the normalised method, a newline and the path template.
func PathHash(method, template string) string {
	m, _ := NormalizeMethod(method)
	sum := sha256.Sum256([]byte(m + "\n" + template))
	return hex.EncodeToString(sum[:])
}
