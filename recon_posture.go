package ctis

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The HTTP posture of an origin: the response headers that state a security
// policy, and the names and flags of the cookies it sets. It is an attribute
// of the http_service asset (Properties["http_posture"]). A scanned server
// chooses every byte, so the converter applies the allow-list itself, whatever
// the producer sent: a header outside it, and any cookie value, never reach
// the report.

// HTTPPostureProperty is the asset property that holds the posture.
const HTTPPostureProperty = "http_posture"

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

// postureKeys maps an allow-listed header (lower case) to its property key.
var postureKeys = map[string]string{
	"strict-transport-security":        "strict_transport_security",
	"content-security-policy":          "content_security_policy",
	"x-frame-options":                  "x_frame_options",
	"x-content-type-options":           "x_content_type_options",
	"referrer-policy":                  "referrer_policy",
	"permissions-policy":               "permissions_policy",
	"access-control-allow-origin":      "access_control_allow_origin",
	"access-control-allow-credentials": "access_control_allow_credentials",
}

// PostureKeys returns the keys a posture attribute can hold besides
// "cookies", sorted.
func PostureKeys() []string {
	keys := make([]string, 0, len(postureKeys))
	for _, k := range postureKeys {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// httpPosture builds the http_posture attribute, or nil when nothing passes.
func httpPosture(in *ResponseHeadersInput) map[string]any {
	if in == nil {
		return nil
	}
	out := map[string]any{}
	for name, v := range in.Values {
		key, ok := postureKeys[strings.ToLower(strings.TrimSpace(name))]
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if v == "" || len(v) > MaxPostureValueLen || !plainText(v) {
			continue
		}
		out[key] = v
	}
	var cookies []map[string]any
	seen := map[string]bool{}
	for _, c := range in.Cookies {
		if len(cookies) >= MaxPostureCookies {
			break
		}
		if !validCookieToken(c.Name) || seen[c.Name] {
			continue
		}
		seen[c.Name] = true
		m := map[string]any{"name": c.Name, "secure": c.Secure, "http_only": c.HTTPOnly, "persistent": c.Persistent}
		switch ss := strings.ToLower(strings.TrimSpace(c.SameSite)); ss {
		case "strict", "lax", "none":
			m["same_site"] = ss
		}
		cookies = append(cookies, m)
	}
	if len(cookies) > 0 {
		sort.Slice(cookies, func(i, j int) bool { return cookies[i]["name"].(string) < cookies[j]["name"].(string) })
		out["cookies"] = cookies
	}
	if len(out) == 0 {
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
