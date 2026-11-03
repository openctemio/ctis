package ctis

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The HTTP posture of an origin: the response headers that state a security
// policy, and the names and flags of the cookies it sets. It is
// technical.http.security_headers of the web_origin asset. A scanned server
// chooses every byte, so the converter applies the allow-list itself, whatever
// the producer sent: a header outside it, and any cookie value, never reach
// the report.

// Bounds on posture values.
const (
	MaxPostureValueLen = 4096
	MaxPostureCookies  = 20
	maxCookieNameLen   = 128
	maxCNAMEs          = 8
)

// ResponseHeadersInput is the posture subset of a response's headers, as a
// producer reports it.
type ResponseHeadersInput struct {
	// Values maps a header name to its value; names outside the allow-list
	// are ignored.
	Values  map[string]string
	Cookies []CookieFlagsInput
}

// CookieFlagsInput is what a Set-Cookie header says about a cookie, without
// its value.
type CookieFlagsInput struct {
	Name       string
	Secure     bool
	HTTPOnly   bool
	SameSite   string
	Persistent bool
}

// httpPosture builds the security headers of an origin, or nil when
// nothing passes the allow-list.
func httpPosture(in *ResponseHeadersInput) *SecurityHeaders {
	if in == nil {
		return nil
	}
	out := &SecurityHeaders{}
	set := false
	for name, v := range in.Values {
		v = strings.TrimSpace(v)
		if v == "" || len(v) > MaxPostureValueLen || !plainText(v) {
			continue
		}
		var dst *string
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "strict-transport-security":
			dst = &out.StrictTransportSecurity
		case "content-security-policy":
			dst = &out.ContentSecurityPolicy
		case "x-frame-options":
			dst = &out.XFrameOptions
		case "x-content-type-options":
			dst = &out.XContentTypeOptions
		case "referrer-policy":
			dst = &out.ReferrerPolicy
		case "permissions-policy":
			dst = &out.PermissionsPolicy
		case "access-control-allow-origin":
			dst = &out.AccessControlAllowOrigin
		case "access-control-allow-credentials":
			dst = &out.AccessControlAllowCredentials
		default:
			continue
		}
		*dst = v
		set = true
	}
	seen := map[string]bool{}
	for _, c := range in.Cookies {
		if len(out.Cookies) >= MaxPostureCookies {
			break
		}
		if !validCookieToken(c.Name) || seen[c.Name] {
			continue
		}
		seen[c.Name] = true
		cf := CookieFlags{Name: c.Name, IsSecure: c.Secure, IsHTTPOnly: c.HTTPOnly, IsPersistent: c.Persistent}
		switch ss := strings.ToLower(strings.TrimSpace(c.SameSite)); ss {
		case "strict", "lax", "none":
			cf.SameSite = ss
		}
		out.Cookies = append(out.Cookies, cf)
	}
	if len(out.Cookies) > 0 {
		sort.Slice(out.Cookies, func(i, j int) bool { return out.Cookies[i].Name < out.Cookies[j].Name })
		set = true
	}
	if !set {
		return nil
	}
	return out
}

// plainText reports whether s is valid UTF-8 with no control or bidi
// formatting character (CR, LF and NUL included).
func plainText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || r == '\u202e' {
			return false
		}
	}
	return true
}

// validCookieToken accepts an RFC 6265 token of at most 128 bytes.
func validCookieToken(n string) bool {
	if n == "" || len(n) > maxCookieNameLen {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if c <= 0x20 || c >= 0x7f || strings.IndexByte("()<>@,;:\\\"/[]?={}", c) >= 0 {
			return false
		}
	}
	return true
}

// boundCNAMEs keeps the valid host names of an alias chain, lower-cased.
func boundCNAMEs(in []string) []string {
	var out []string
	for _, c := range in {
		c = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(c), "."))
		if !validCNAME(c) {
			continue
		}
		out = append(out, c)
		if len(out) == maxCNAMEs {
			break
		}
	}
	return out
}

func validCNAME(h string) bool {
	if h == "" || len(h) > 253 || h[0] == '.' || strings.Contains(h, "..") {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '.' && c != '_' {
			return false
		}
	}
	return true
}
