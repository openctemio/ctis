package ctis

import (
	"reflect"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Secret redaction over a whole finding.
//
// A secret scanner's raw match can reach more than the snippet: a scanner
// message that names the match becomes the title, a rule description can
// repeat it, a commit message or a property can hold it. Masking only the
// snippet left the live credential in the title of the stored finding.
// RedactSecretFinding masks every known raw value in every free-text field
// of the finding, with the masking FromSARIF uses (MaskSecretMatch: at most
// the first 4 characters of a secret of 16 or more, which is never more
// than a quarter of it).

// minRedactLen is the shortest raw value masked inside other text. Shorter
// values would mangle ordinary words and are no secret on their own.
const minRedactLen = 4

// minSecretTokenLen is the shortest word of a match taken for the secret
// itself (see secretTokens).
const minSecretTokenLen = 8

// maxRedactDepth bounds the walk over nested values.
const maxRedactDepth = 32

// RedactSecretFinding masks raw secret values everywhere in f: the title,
// description, message, snippet, evidence, remediation, fingerprints, tags,
// properties and every other plain string field.
//
// The values masked are the known raw values passed in and, for a secret
// finding (type secret), the location snippet and secret.masked_value when
// they are not already masked. A value is masked as a whole, and so is
// each secret-looking word in it: a snippet holding a whole code line
// (key = "AKIA...") still has the bare secret masked where the title
// repeats it alone. Values already masked (asterisks, REDACTED) are left as
// they are, so the call is idempotent and a producer's masking is kept.
//
// Receivers call it on every finding they store, as defence in depth; the
// converters of this module call it on every secret finding they emit.
func RedactSecretFinding(f *Finding, known ...string) {
	redactSecrets(f, f != nil && f.Type == FindingTypeSecret, isMasked, known...)
}

// redactSecrets is RedactSecretFinding with the decision whether the snippet
// and masked value hold the secret made by the caller (FromSARIF decides by
// the tool too, not only by the finding type), and with the test that says
// a snippet is already masked: FromSARIF keeps only a fully redacted
// snippet, a receiver keeps any masked one.
func redactSecrets(f *Finding, isSecret bool, snippetMasked func(string) bool, known ...string) {
	if f == nil {
		return
	}
	c := candidates{}
	for _, k := range known {
		if !isMasked(k) {
			c.addWhole(k)
		}
		c.addTokens(k)
	}
	if isSecret {
		if loc := f.Location; loc != nil && strings.TrimSpace(loc.Snippet) != "" {
			s := loc.Snippet
			if !snippetMasked(s) {
				c.addWhole(s)
				loc.Snippet = maskSecret(s)
			}
			c.addTokens(s)
		}
		if sd := f.Secret; sd != nil && strings.TrimSpace(sd.MaskedValue) != "" && !isMasked(sd.MaskedValue) {
			c.addWhole(sd.MaskedValue)
			c.addTokens(sd.MaskedValue)
			sd.MaskedValue = maskSecret(sd.MaskedValue)
		}
	}
	if len(c) == 0 {
		return
	}
	r := c.replacer()
	redactValue(reflect.ValueOf(f).Elem(), r, 0)
}

// ContainsSecret reports whether s holds one of the raw values, the check a
// test or a receiver uses to prove a value never reached storage.
func ContainsSecret(s string, raw ...string) bool {
	for _, v := range raw {
		v = strings.TrimSpace(v)
		if utf8.RuneCountInString(v) >= minRedactLen && strings.Contains(s, v) {
			return true
		}
	}
	return false
}

// candidates maps each raw value to its masked form.
type candidates map[string]string

func (c candidates) addWhole(s string) {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) < minRedactLen {
		return
	}
	c[s] = maskSecret(s)
}

func (c candidates) addTokens(s string) {
	for _, t := range secretTokens(s) {
		if _, ok := c[t]; !ok {
			c[t] = maskSecret(t)
		}
	}
}

// replacer replaces the longest values first, so a whole line is masked as
// one before any of its words.
func (c candidates) replacer() *strings.Replacer {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] < keys[j]
	})
	pairs := make([]string, 0, 2*len(keys))
	for _, k := range keys {
		pairs = append(pairs, k, c[k])
	}
	return strings.NewReplacer(pairs...)
}

// isMasked reports whether a value is already masked: it holds a run of
// asterisks or bullets, or a REDACTED marker. gitleaks --redact writes
// REDACTED, trivy and the SDK mask with asterisks.
func isMasked(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" || strings.Trim(t, "*•") == "" {
		return true
	}
	return strings.Contains(t, "***") || strings.Contains(t, "•••") || strings.Contains(strings.ToLower(t), "redacted")
}

// secretTokens returns the words of s that look like a secret: at least
// minSecretTokenLen characters with a letter and a digit, or at least 20
// characters, and not masked. Words are split at white space, quotes and
// the separators of assignments and structured text, so the value of
// key = "AKIA..." or {"token":"ghp_..."} is one word.
func secretTokens(s string) []string {
	words := strings.FieldsFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune("\"'`=:;,()[]{}<>", r)
	})
	var out []string
	for _, w := range words {
		if looksSecret(w) {
			out = append(out, w)
		}
	}
	return out
}

func looksSecret(w string) bool {
	n := utf8.RuneCountInString(w)
	if n < minSecretTokenLen || strings.ContainsAny(w, "*•") {
		return false
	}
	if n >= 20 {
		return true
	}
	var letter, digit bool
	for _, r := range w {
		switch {
		case unicode.IsLetter(r):
			letter = true
		case unicode.IsDigit(r):
			digit = true
		}
	}
	return letter && digit
}

var plainString = reflect.TypeOf("")

// redactValue applies r to every plain string reachable from v: exported
// struct fields, pointers, slices, arrays, map values and interface values.
// Named string types (enums such as FindingType) are vocabulary, not text,
// and are left alone, as are map keys and byte slices.
func redactValue(v reflect.Value, r *strings.Replacer, depth int) {
	if depth > maxRedactDepth {
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			redactValue(v.Elem(), r, depth+1)
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if t.Field(i).IsExported() {
				redactValue(v.Field(i), r, depth+1)
			}
		}
	case reflect.String:
		if v.Type() == plainString && v.CanSet() {
			if s := v.String(); s != "" {
				v.SetString(r.Replace(s))
			}
		}
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return
		}
		for i := 0; i < v.Len(); i++ {
			redactValue(v.Index(i), r, depth+1)
		}
	case reflect.Interface:
		if v.IsNil() || !v.CanSet() {
			return
		}
		cp := reflect.New(v.Elem().Type()).Elem()
		cp.Set(v.Elem())
		redactValue(cp, r, depth+1)
		v.Set(cp)
	case reflect.Map:
		if v.IsNil() {
			return
		}
		iter := v.MapRange()
		type kv struct{ k, v reflect.Value }
		var updates []kv
		for iter.Next() {
			cp := reflect.New(iter.Value().Type()).Elem()
			cp.Set(iter.Value())
			redactValue(cp, r, depth+1)
			updates = append(updates, kv{iter.Key(), cp})
		}
		for _, u := range updates {
			v.SetMapIndex(u.k, u.v)
		}
	}
}
