package engine

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// Paths
//
// A field path names members of a source document the way the importers
// record them: JSON as "/member/array[]/member" (the elements of a
// top-level array are "/[]"), XML as "/Root/Child/@attr". In a pattern a
// "*" matches any run of characters inside one segment and a "**" segment
// matches zero or more segments.
//
// A pointer is an RFC 6901 JSON Pointer to one concrete value
// ("/runs/0/results/3/message/text"). PointerPath turns a pointer into the
// path the patterns match.

// MaxPathSegments and MaxPathBytes bound a path or a pointer.
const (
	MaxPathSegments = 64
	MaxPathBytes    = 1024
)

// MatchPath reports whether the path p matches the pattern.
func MatchPath(pattern, p string) bool {
	if pattern == p {
		return true
	}
	return segmentsMatch(strings.Split(pattern, "/"), strings.Split(p, "/"))
}

// matchBelow reports whether the pattern can match a path strictly below p:
// p is a proper prefix of some path the pattern matches.
func matchBelow(pattern, p string) bool {
	return prefixMatch(strings.Split(pattern, "/"), strings.Split(p, "/"))
}

// segmentsMatch matches path segments; a "**" segment matches zero or more
// segments, anywhere in the pattern.
func segmentsMatch(pat, segs []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			for k := 0; k <= len(segs); k++ {
				if segmentsMatch(pat[1:], segs[k:]) {
					return true
				}
			}
			return false
		}
		if len(segs) == 0 || !wildcard(pat[0], segs[0]) {
			return false
		}
		pat, segs = pat[1:], segs[1:]
	}
	return len(segs) == 0
}

// prefixMatch reports whether segs, followed by at least one more segment,
// can be matched by pat.
func prefixMatch(pat, segs []string) bool {
	for len(segs) > 0 {
		if len(pat) == 0 {
			return false
		}
		if pat[0] == "**" {
			// "**" swallows any number of the remaining segments and can
			// always continue below.
			return true
		}
		if !wildcard(pat[0], segs[0]) && !arrayPrefix(pat[0], segs[0]) {
			return false
		}
		if arrayPrefix(pat[0], segs[0]) && !wildcard(pat[0], segs[0]) {
			// "results" (the array member itself) is below "results[]":
			// an element path continues the same segment.
			return true
		}
		pat, segs = pat[1:], segs[1:]
	}
	return len(pat) > 0
}

// arrayPrefix reports whether the pattern segment names the elements of the
// array that the path segment names ("results[]" below "results").
func arrayPrefix(pattern, seg string) bool {
	return strings.HasSuffix(pattern, "[]") && wildcard(strings.TrimRight(pattern, "[]"), seg) && !strings.HasSuffix(seg, "[]")
}

// wildcard matches s against a pattern where "*" is any run of characters.
func wildcard(pattern, s string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for i := 1; i < len(parts)-1; i++ {
		j := strings.Index(s, parts[i])
		if j < 0 {
			return false
		}
		s = s[j+len(parts[i]):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}

// PathKey is the path segment of a member name: control characters, '/',
// '[' and ']' become '_', and the name is cut to 128 bytes on a character
// boundary.
func PathKey(v string) string {
	v = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '/' || r == '[' || r == ']' {
			return '_'
		}
		return r
	}, v)
	if len(v) > 128 {
		v = v[:128]
		for !utf8.ValidString(v) {
			v = v[:len(v)-1]
		}
	}
	return v
}

// parsePointer splits an RFC 6901 pointer into steps; ok is false for a
// malformed or over-long pointer. Numeric tokens are indexes when the parent
// is an array; parsePointer keeps both readings (key and index).
func parsePointer(p string) ([]string, bool) {
	if p == "" {
		return nil, true
	}
	if !strings.HasPrefix(p, "/") || len(p) > MaxPathBytes || !utf8.ValidString(p) {
		return nil, false
	}
	toks := strings.Split(p[1:], "/")
	if len(toks) > MaxPathSegments {
		return nil, false
	}
	for i, t := range toks {
		if strings.Contains(strings.ReplaceAll(strings.ReplaceAll(t, "~0", ""), "~1", ""), "~") {
			return nil, false
		}
		toks[i] = strings.ReplaceAll(strings.ReplaceAll(t, "~1", "/"), "~0", "~")
	}
	return toks, true
}

// escapeToken escapes one pointer token.
func escapeToken(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

// isIndex reports whether a token is an array index (no sign, no leading
// zero).
func isIndex(t string) (int, bool) {
	if t == "" || (len(t) > 1 && t[0] == '0') {
		return 0, false
	}
	for _, c := range t {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(t)
	return n, err == nil
}
