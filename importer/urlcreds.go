package importer

import (
	"net/url"
	"regexp"
	"strings"
)

// credentialParamRE names a URL query or fragment parameter that carries a
// credential: keys, tokens, secrets, passwords, sessions, signatures, OAuth
// codes. A match is masked, never kept.
var credentialParamRE = regexp.MustCompile(`(?i)(^|[_.-])(api[_-]?key|apikey|key|token|access[_-]?token|refresh[_-]?token|id[_-]?token|auth|authorization|secret|client[_-]?secret|password|passwd|pwd|pass|session|session[_-]?id|sessionid|sid|signature|sig|credential|credentials|code|jwt|bearer)($|[_.-])`)

// redactedValue replaces a credential in a URL.
const redactedValue = "REDACTED"

// redactURLCredentials removes the credentials a URL can carry: the user
// info (https://user:pass@host/) and the values of query and fragment
// parameters named like a credential (?api_key=..., #access_token=...).
// A value that does not parse as a URL is returned with its user info
// removed when it has one, and is otherwise unchanged.
func redactURLCredentials(s string) string {
	s = stripUserinfo(s)
	if strings.Contains(s, "@") && strings.Contains(s, "://") {
		s = rawUserinfoRE.ReplaceAllString(s, "${1}")
	}
	if !strings.ContainsAny(s, "?#") {
		return s
	}
	u, err := url.Parse(s)
	if err != nil {
		return redactRawURL(s)
	}
	changed := false
	if u.RawQuery != "" {
		if q, ok := redactParams(u.RawQuery); ok {
			u.RawQuery, changed = q, true
		}
	}
	if frag := u.EscapedFragment(); frag != "" && strings.Contains(frag, "=") {
		if f, ok := redactParams(frag); ok {
			decoded, err := url.PathUnescape(f)
			if err != nil {
				decoded = f
			}
			u.Fragment, u.RawFragment, changed = decoded, f, true
		}
	}
	if !changed {
		return s
	}
	return u.String()
}

// redactParams masks the values of credential-named parameters of an
// encoded "a=b&c=d" list, keeping the order and every other byte. ok is
// false when nothing was masked.
func redactParams(raw string) (string, bool) {
	parts := strings.Split(raw, "&")
	masked := false
	for i, p := range parts {
		k, v, hasValue := strings.Cut(p, "=")
		if !hasValue || v == "" {
			continue
		}
		name, err := url.QueryUnescape(k)
		if err != nil {
			name = k
		}
		if credentialParamRE.MatchString(name) {
			parts[i] = k + "=" + redactedValue
			masked = true
		}
	}
	return strings.Join(parts, "&"), masked
}

// rawUserinfoRE is the user info of a URL that does not parse.
var rawUserinfoRE = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]*://)[^/?#@]*@`)

// rawParamRE is one parameter of a query or fragment that does not parse.
var rawParamRE = regexp.MustCompile(`([?&#;])([^=&#;]+)=([^&#;]*)`)

// redactRawURL masks credential-named parameters of a string url.Parse
// refuses (an invalid escape), by pattern.
func redactRawURL(s string) string {
	return rawParamRE.ReplaceAllStringFunc(s, func(m string) string {
		sub := rawParamRE.FindStringSubmatch(m)
		if sub[3] == "" || !credentialParamRE.MatchString(sub[2]) {
			return m
		}
		return sub[1] + sub[2] + "=" + redactedValue
	})
}
