package ctis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// A small JSON Schema (draft-07) validator for the tests. The module has no
// dependencies, test dependencies included, so it cannot import one. It
// implements exactly the keywords schemas/v1 uses; TestSchemaKeywords fails
// if a schema starts using a keyword this validator would silently ignore.
// CI also validates the examples with the reference Python implementation
// (scripts/validate_schemas.py), which cross-checks this one.

const schemaDir = "schemas/v1"

// supportedKeywords are the schema keywords the validator evaluates or that
// are pure annotations.
var supportedKeywords = map[string]bool{
	"$schema": true, "$id": true, "$ref": true, "$defs": true,
	"title": true, "description": true, "default": true, "examples": true,
	"type": true, "required": true, "properties": true, "additionalProperties": true,
	"items": true, "enum": true, "const": true, "pattern": true,
	"minimum": true, "maximum": true, "minLength": true, "maxLength": true,
	"format": true,
}

var annotationKeywords = map[string]bool{
	"title": true, "description": true, "default": true, "examples": true,
}

type schemaSet struct {
	docs     map[string]map[string]any
	patterns map[string]*regexp.Regexp
}

func loadSchemaSet(t testing.TB) *schemaSet {
	t.Helper()
	entries, err := os.ReadDir(schemaDir)
	if err != nil {
		t.Fatal(err)
	}
	s := &schemaSet{docs: map[string]map[string]any{}, patterns: map[string]*regexp.Regexp{}}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(schemaDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		s.docs[e.Name()] = doc
	}
	return s
}

// pointer resolves a JSON pointer fragment ("/$defs/X") inside a document.
func (s *schemaSet) pointer(file, frag string) (map[string]any, error) {
	doc, ok := s.docs[file]
	if !ok {
		return nil, fmt.Errorf("unknown schema file %q", file)
	}
	node := doc
	for _, part := range strings.Split(strings.TrimPrefix(frag, "/"), "/") {
		if part == "" {
			continue
		}
		next, ok := node[part].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s#%s: no member %q", file, frag, part)
		}
		node = next
	}
	return node, nil
}

// deref follows $ref chains; refs are relative file names with an optional
// pointer, or local pointers.
func (s *schemaSet) deref(node map[string]any, file string) (map[string]any, string, error) {
	for i := 0; i < 16; i++ {
		ref, ok := node["$ref"].(string)
		if !ok {
			return node, file, nil
		}
		target, frag, _ := strings.Cut(ref, "#")
		if target != "" {
			file = target
		}
		next, err := s.pointer(file, frag)
		if err != nil {
			return nil, "", err
		}
		node = next
	}
	return nil, "", fmt.Errorf("$ref chain too deep in %s", file)
}

// validateJSON validates a JSON document against a schema file.
func (s *schemaSet) validateJSON(raw []byte, file string) []string {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return []string{"invalid JSON: " + err.Error()}
	}
	var errs []string
	s.validate(v, s.docs[file], file, "", &errs)
	return errs
}

// validateValue marshals v and validates it against a schema file.
func (s *schemaSet) validateValue(t testing.TB, v any, file string) []string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return s.validateJSON(raw, file)
}

func (s *schemaSet) validate(v any, node map[string]any, file, path string, errs *[]string) {
	node, file, err := s.deref(node, file)
	if err != nil {
		*errs = append(*errs, path+": "+err.Error())
		return
	}
	fail := func(format string, args ...any) {
		p := path
		if p == "" {
			p = "/"
		}
		*errs = append(*errs, p+": "+fmt.Sprintf(format, args...))
	}

	if typ, ok := node["type"].(string); ok && !jsonTypeMatches(v, typ) {
		fail("want %s, got %s", typ, jsonTypeOf(v))
		return
	}
	if c, ok := node["const"]; ok && !jsonEqual(v, c) {
		fail("want const %v, got %v", c, v)
	}
	if enum, ok := node["enum"].([]any); ok {
		found := false
		for _, e := range enum {
			if jsonEqual(v, e) {
				found = true
				break
			}
		}
		if !found {
			fail("%v is not one of %v", v, enum)
		}
	}

	switch val := v.(type) {
	case string:
		if p, ok := node["pattern"].(string); ok {
			re := s.patterns[p]
			if re == nil {
				re = regexp.MustCompile(p)
				s.patterns[p] = re
			}
			if !re.MatchString(val) {
				fail("%q does not match %s", val, p)
			}
		}
		n := len([]rune(val))
		if m, ok := numberOf(node["minLength"]); ok && float64(n) < m {
			fail("shorter than %v", m)
		}
		if m, ok := numberOf(node["maxLength"]); ok && float64(n) > m {
			fail("longer than %v", m)
		}
		if f, ok := node["format"].(string); ok {
			if msg := checkFormat(f, val); msg != "" {
				fail("%q: %s", val, msg)
			}
		}
	case json.Number:
		f, _ := val.Float64()
		if m, ok := numberOf(node["minimum"]); ok && f < m {
			fail("%v is below minimum %v", f, m)
		}
		if m, ok := numberOf(node["maximum"]); ok && f > m {
			fail("%v is above maximum %v", f, m)
		}
	case []any:
		if items, ok := node["items"].(map[string]any); ok {
			for i, item := range val {
				s.validate(item, items, file, fmt.Sprintf("%s/%d", path, i), errs)
			}
		}
	case map[string]any:
		if req, ok := node["required"].([]any); ok {
			for _, r := range req {
				if _, ok := val[r.(string)]; !ok {
					fail("missing required member %q", r)
				}
			}
		}
		props, _ := node["properties"].(map[string]any)
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child := path + "/" + k
			if ps, ok := props[k].(map[string]any); ok {
				s.validate(val[k], ps, file, child, errs)
				continue
			}
			switch ap := node["additionalProperties"].(type) {
			case bool:
				if !ap {
					fail("unknown member %q", k)
				}
			case map[string]any:
				s.validate(val[k], ap, file, child, errs)
			}
		}
	}
}

func checkFormat(format, v string) string {
	switch format {
	case "date-time":
		if _, err := time.Parse(time.RFC3339Nano, v); err != nil {
			return "not an RFC 3339 date-time"
		}
	case "uri":
		u, err := url.Parse(v)
		if err != nil || u.Scheme == "" {
			return "not an absolute URI"
		}
	case "uri-reference":
		if _, err := url.Parse(v); err != nil {
			return "not a URI reference"
		}
	case "email":
		if !strings.Contains(v, "@") {
			return "not an email address"
		}
	default:
		return "unsupported format " + format
	}
	return ""
}

func numberOf(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil
}

func jsonTypeOf(v any) string {
	switch val := v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case json.Number:
		f, _ := val.Float64()
		if f == math.Trunc(f) {
			return "integer"
		}
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("%T", v)
}

func jsonTypeMatches(v any, typ string) bool {
	got := jsonTypeOf(v)
	return got == typ || (typ == "number" && got == "integer")
}

func jsonEqual(a, b any) bool {
	an, aok := a.(json.Number)
	bn, bok := b.(json.Number)
	if aok && bok {
		af, _ := an.Float64()
		bf, _ := bn.Float64()
		return af == bf
	}
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return bytes.Equal(ab, bb)
}

// assertReportValid fails the test when r does not validate against
// report.json.
func assertReportValid(t testing.TB, s *schemaSet, r *Report) {
	t.Helper()
	if errs := s.validateValue(t, r, "report.json"); len(errs) > 0 {
		t.Fatalf("report does not validate against schemas/v1/report.json:\n  %s", strings.Join(errs, "\n  "))
	}
}

func TestSchemaValidatorSelfCheck(t *testing.T) {
	s := loadSchemaSet(t)
	ok := `{"version":"1.3","metadata":{"timestamp":"2026-10-02T00:00:00Z"},
		"assets":[{"type":"host","value":"h"}],
		"findings":[{"type":"secret","title":"t","severity":"high","vulnerability":{"cvss_score":9.8}}]}`
	if errs := s.validateJSON([]byte(ok), "report.json"); len(errs) > 0 {
		t.Fatalf("valid document rejected: %v", errs)
	}
	bad := map[string]string{
		"unknown member":   `{"version":"1.3","metadata":{"timestamp":"2026-10-02T00:00:00Z"},"sevrity":1}`,
		"missing required": `{"version":"1.3"}`,
		"bad enum":         `{"version":"1.3","metadata":{"timestamp":"2026-10-02T00:00:00Z"},"assets":[{"type":"other","value":"h"}]}`,
		"bad pattern":      `{"version":"2.0","metadata":{"timestamp":"2026-10-02T00:00:00Z"}}`,
		"above maximum":    `{"version":"1.3","metadata":{"timestamp":"2026-10-02T00:00:00Z"},"findings":[{"type":"secret","title":"t","severity":"high","vulnerability":{"cvss_score":99}}]}`,
		"bad date-time":    `{"version":"1.3","metadata":{"timestamp":"yesterday"}}`,
		"wrong type":       `{"version":1,"metadata":{"timestamp":"2026-10-02T00:00:00Z"}}`,
		"not an integer":   `{"version":"1.3","metadata":{"timestamp":"2026-10-02T00:00:00Z","duration_ms":1.5}}`,
		"nested unknown":   `{"version":"1.3","metadata":{"timestamp":"2026-10-02T00:00:00Z"},"findings":[{"type":"secret","title":"t","severity":"high","suppression":{"state":"accepted"}}]}`,
	}
	for name, doc := range bad {
		if errs := s.validateJSON([]byte(doc), "report.json"); len(errs) == 0 {
			t.Errorf("%s: invalid document accepted", name)
		}
	}
}
