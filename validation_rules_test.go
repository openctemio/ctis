package ctis_test

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

// ruleHeadingRE matches the heading of one rule of docs/validation-rules.md.
var ruleHeadingRE = regexp.MustCompile(`^### (V-[A-Z]+-[0-9]{3})\b`)

// ruleIDRE is the form of a rule id.
var ruleIDRE = regexp.MustCompile(`^V-[A-Z]+-[0-9]{3}$`)

// vectorRE matches a document a rule cites in its Vectors line.
var vectorRE = regexp.MustCompile("`([^`]+\\.json)`")

// TestValidationRules keeps docs/validation-rules.md and the documents
// manifest in step: every rule is documented once and has at least one
// invalid document, every rule a manifest entry names is documented, and the
// documents a rule cites carry its id.
func TestValidationRules(t *testing.T) {
	raw, err := os.ReadFile("docs/validation-rules.md")
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	cited := map[string][]string{}
	current := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if m := ruleHeadingRE.FindStringSubmatch(line); m != nil {
			current = m[1]
			if documented[current] {
				t.Errorf("docs/validation-rules.md: %s is documented twice", current)
			}
			documented[current] = true
			continue
		}
		if strings.HasPrefix(line, "## ") {
			current = ""
		}
		if current != "" && strings.HasPrefix(line, "- **Vectors.**") {
			for _, m := range vectorRE.FindAllStringSubmatch(line, -1) {
				cited[current] = append(cited[current], m[1])
			}
		}
	}
	if len(documented) == 0 {
		t.Fatal("docs/validation-rules.md documents no rule")
	}

	mraw, err := os.ReadFile("conformance/v2/documents/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Documents []struct {
			File        string `json:"file"`
			Result      string `json:"result"`
			SchemaLevel *bool  `json:"schema_level"`
			Rule        string `json:"rule"`
		} `json:"documents"`
	}
	if err := json.Unmarshal(mraw, &m); err != nil {
		t.Fatal(err)
	}
	vectors := map[string]int{}
	ruleOf := map[string]string{}
	for _, d := range m.Documents {
		if d.Rule == "" {
			continue
		}
		ruleOf[d.File] = d.Rule
		switch {
		case !ruleIDRE.MatchString(d.Rule):
			t.Errorf("manifest %s: rule %q is not V-<AREA>-<NNN>", d.File, d.Rule)
		case !documented[d.Rule]:
			t.Errorf("manifest %s: rule %s is not documented in docs/validation-rules.md", d.File, d.Rule)
		}
		if d.Result != "invalid" {
			t.Errorf("manifest %s: carries rule %s but is not invalid", d.File, d.Rule)
			continue
		}
		if d.SchemaLevel == nil || *d.SchemaLevel {
			t.Errorf("manifest %s: carries rule %s but is not marked schema_level false", d.File, d.Rule)
		}
		vectors[d.Rule]++
	}
	for id := range documented {
		if vectors[id] == 0 {
			t.Errorf("%s has no invalid document in conformance/v2/documents/manifest.json", id)
		}
		if len(cited[id]) == 0 {
			t.Errorf("docs/validation-rules.md: %s cites no document", id)
		}
		for _, f := range cited[id] {
			if got := ruleOf[f]; got != id {
				t.Errorf("docs/validation-rules.md: %s cites %s, whose manifest rule is %q", id, f, got)
			}
		}
	}
}
