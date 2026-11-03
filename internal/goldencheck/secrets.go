// Package goldencheck holds checks on golden report files that package
// importer and the adapters share (it must not import importer).
package goldencheck

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"
)

// NoSecretsInOutput checks the golden and result files of dirs: no raw secret, credential in a URL, cookie or extracted target data
// reaches any golden output of the code formats, but typed evidence (spec
// 4.8): an evidence item may hold the exchange as captured (target data
// that proves the finding included), with every credential inside a span
// it marks.
func NoSecretsInOutput(t *testing.T, dirs ...string) {
	t.Helper()
	credentials := []string{"AKIAEXAMPLEEXAMPLE00", "ghp_0000EXAMPLE", "not-a-token", "user:secret", "session=abc", "admin:hunter2"}
	targetData := []string{"root:x:0"}
	for _, dir := range dirs {
		files, _ := filepath.Glob(filepath.Join(dir, "*.golden.json"))
		res, _ := filepath.Glob(filepath.Join(dir, "*.result.json"))
		for _, f := range append(files, res...) {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Findings []map[string]json.RawMessage `json:"findings"`
			}
			_ = json.Unmarshal(b, &doc)
			var items []ctis.EvidenceItem
			for _, fd := range doc.Findings {
				if raw, ok := fd["evidence_items"]; ok {
					var ev []ctis.EvidenceItem
					if err := json.Unmarshal(raw, &ev); err != nil {
						t.Fatalf("%s: %v", f, err)
					}
					items = append(items, ev...)
					b = bytes.Replace(b, raw, nil, 1)
				}
			}
			for _, s := range append(append([]string(nil), credentials...), targetData...) {
				if bytes.Contains(b, []byte(s)) {
					t.Errorf("%s holds %q outside evidence items", f, s)
				}
			}
			for i := range items {
				for _, s := range credentials {
					if ptrs := UnmarkedIn(&items[i], s); len(ptrs) > 0 {
						t.Errorf("%s: evidence holds %q unmarked at %v", f, s, ptrs)
					}
				}
			}
		}
	}
}

// UnmarkedIn returns the JSON pointers of the item's strings that hold s
// outside every marked span.
func UnmarkedIn(it *ctis.EvidenceItem, s string) []string {
	raw, _ := json.Marshal(it)
	var doc any
	_ = json.Unmarshal(raw, &doc)
	var out []string
	var walk func(v any, ptr string)
	walk = func(v any, ptr string) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				if ptr == "" && k == "sensitive" {
					continue
				}
				walk(e, ptr+"/"+strings.ReplaceAll(strings.ReplaceAll(k, "~", "~0"), "/", "~1"))
			}
		case []any:
			for i, e := range x {
				walk(e, ptr+"/"+strconv.Itoa(i))
			}
		case string:
			for from := 0; ; {
				i := strings.Index(x[from:], s)
				if i < 0 {
					return
				}
				start, end := from+i, from+i+len(s)
				covered := false
				for _, sp := range it.Sensitive {
					lo, hi := 0, len(x)
					if sp.Start != nil {
						lo = *sp.Start
					}
					if sp.End != nil {
						hi = *sp.End
					}
					covered = covered || (sp.Pointer == ptr && lo <= start && end <= hi)
				}
				if !covered {
					out = append(out, ptr)
				}
				from = end
			}
		}
	}
	walk(doc, "")
	return out
}

// EvidenceSecretsMarked checks one golden report: every secret is inside a
// marked span of an evidence item and nowhere else in the report. A file
// with secrets must have evidence items.
func EvidenceSecretsMarked(t *testing.T, file string, secrets []string) {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []map[string]json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	n := 0
	rest := b
	for _, fd := range doc.Findings {
		raw, ok := fd["evidence_items"]
		if !ok {
			continue
		}
		var items []ctis.EvidenceItem
		if err := json.Unmarshal(raw, &items); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		for i := range items {
			n++
			for _, s := range secrets {
				if ptrs := UnmarkedIn(&items[i], s); len(ptrs) > 0 {
					t.Errorf("%s: %q unmarked at %v", file, s, ptrs)
				}
			}
		}
		rest = bytes.Replace(rest, raw, nil, 1)
	}
	if len(secrets) > 0 && n == 0 {
		t.Errorf("%s: no evidence items", file)
	}
	for _, s := range secrets {
		if bytes.Contains(rest, []byte(s)) {
			t.Errorf("%s: %q outside evidence items", file, s)
		}
	}
}
