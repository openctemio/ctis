package weburl

import (
	"net/url"
	"regexp"
	"strings"
)

// Typed variables of a path template.
const (
	VarInt   = "{int}"
	VarUUID  = "{uuid}"
	VarDate  = "{date}"
	VarEmail = "{email}"
	VarHex   = "{hex}"
	VarToken = "{token}"
	VarID    = "{id}"
)

// Segment rules, checked in this order on the unescaped segment. RE2: no
// backtracking.
var (
	intRE   = regexp.MustCompile(`^[0-9]+$`)
	uuidRE  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	dateRE  = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	emailRE = regexp.MustCompile(`^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}$`)
	hexRE   = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	jwtRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}$`)
	b64RE   = regexp.MustCompile(`^[A-Za-z0-9_-]{20,}$`)
	idRE    = regexp.MustCompile(`^[A-Za-z0-9]{12,}$`)
)

// TemplateSegment returns the typed variable an identifier segment becomes,
// or the segment itself:
//
//   - {int}: digits only ("42");
//   - {uuid}: an RFC 4122 UUID;
//   - {date}: an ISO date ("2026-10-07");
//   - {email}: an e-mail address;
//   - {hex}: 16 or more hexadecimal digits (hashes, object ids);
//   - {token}: a JWT-like value (three base64url parts) or 20 or more
//     base64url characters with an upper-case letter, a lower-case letter
//     and a digit (random tokens; lowercase slugs never match);
//   - {id}: 12 or more letters and digits with at least one of each
//     ("a1b2c3d4e5f6").
//
// The segment is matched unescaped, so "user%40example.com" is an e-mail.
func TemplateSegment(seg string) string {
	s := seg
	if strings.Contains(s, "%") {
		if d, err := url.PathUnescape(s); err == nil {
			s = d
		}
	}
	switch {
	case s == "":
		return seg
	case intRE.MatchString(s):
		return VarInt
	case uuidRE.MatchString(s):
		return VarUUID
	case dateRE.MatchString(s):
		return VarDate
	case emailRE.MatchString(s):
		return VarEmail
	case hexRE.MatchString(s):
		return VarHex
	case jwtRE.MatchString(s) && len(s) >= 20:
		return VarToken
	case b64RE.MatchString(s) && mixedCase(s) && hasDigit(s):
		return VarToken
	case idRE.MatchString(s) && hasDigit(s) && hasLetter(s):
		return VarID
	}
	return seg
}

// TemplatePath replaces the identifier segments of a normalised path
// (TemplateSegment).
func TemplatePath(path string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		segs[i] = TemplateSegment(s)
	}
	return strings.Join(segs, "/")
}

func hasDigit(s string) bool { return strings.ContainsAny(s, "0123456789") }

func hasLetter(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
}

func mixedCase(s string) bool {
	upper, lower := false, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		}
	}
	return upper && lower
}
