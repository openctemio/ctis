package ctis

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// docs/spec.md carries a field reference generated from schemas/v1 between
// two markers. This test regenerates it and fails when the committed text is
// stale; run `go test -run TestSpecFieldReference -update` to refresh it.

const (
	specPath        = "docs/spec.md"
	specBeginMarker = "<!-- BEGIN GENERATED FIELD REFERENCE: go test -run TestSpecFieldReference -update -->"
	specEndMarker   = "<!-- END GENERATED FIELD REFERENCE -->"
)

var specFileOrder = []string{"report.json", "asset.json", "finding.json", "dependency.json", "web3-asset.json", "web3-finding.json"}

func TestSpecFieldReference(t *testing.T) {
	s := loadSchemaSet(t)
	generated := generateFieldReference(s)

	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	begin := strings.Index(doc, specBeginMarker)
	end := strings.Index(doc, specEndMarker)
	if begin < 0 || end < begin {
		t.Fatalf("%s: generated-section markers missing", specPath)
	}
	updated := doc[:begin+len(specBeginMarker)] + "\n\n" + generated + "\n" + doc[end:]
	if updated == doc {
		return
	}
	if *updateGolden {
		if err := os.WriteFile(specPath, []byte(updated), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Errorf("%s field reference is stale; run go test -run TestSpecFieldReference -update", specPath)
}

func generateFieldReference(s *schemaSet) string {
	var b strings.Builder
	for _, file := range specFileOrder {
		doc := s.docs[file]
		title, _ := doc["title"].(string)
		fmt.Fprintf(&b, "### %s (`%s`)\n\n", title, file)
		if d, ok := doc["description"].(string); ok {
			b.WriteString(oneLine(d) + "\n\n")
		}
		writeObjectTable(&b, doc)
		defs, _ := doc["$defs"].(map[string]any)
		for _, name := range sortedKeys(defs) {
			def := defs[name].(map[string]any)
			fmt.Fprintf(&b, "#### %s\n\n", name)
			if d, ok := def["description"].(string); ok {
				b.WriteString(oneLine(d) + "\n\n")
			}
			if _, ok := def["properties"]; ok {
				writeObjectTable(&b, def)
			} else {
				fmt.Fprintf(&b, "Type: %s. %s\n\n", typeOf(def), constraintsOf(def))
			}
		}
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}

func writeObjectTable(b *strings.Builder, node map[string]any) {
	props, _ := node["properties"].(map[string]any)
	required := map[string]bool{}
	if req, ok := node["required"].([]any); ok {
		for _, r := range req {
			required[r.(string)] = true
		}
	}
	b.WriteString("| Field | Type | Required | Constraints | Description |\n|---|---|---|---|---|\n")
	for _, name := range sortedKeys(props) {
		p := props[name].(map[string]any)
		req := ""
		if required[name] {
			req = "yes"
		}
		desc, _ := p["description"].(string)
		fmt.Fprintf(b, "| `%s` | %s | %s | %s | %s |\n", name, typeOf(p), req, cell(constraintsOf(p)), cell(desc))
	}
	b.WriteString("\n")
}

func typeOf(p map[string]any) string {
	if ref, ok := p["$ref"].(string); ok {
		return refName(ref)
	}
	t, _ := p["type"].(string)
	switch t {
	case "array":
		if items, ok := p["items"].(map[string]any); ok {
			return "array of " + typeOf(items)
		}
	case "object":
		if ap, ok := p["additionalProperties"].(map[string]any); ok {
			return "map of " + typeOf(ap)
		}
		if p["properties"] == nil {
			return "object (free-form)"
		}
	}
	if f, ok := p["format"].(string); ok {
		return t + " (" + f + ")"
	}
	return t
}

func refName(ref string) string {
	file, frag, _ := strings.Cut(ref, "#")
	if frag != "" {
		return "`" + frag[strings.LastIndex(frag, "/")+1:] + "`"
	}
	return "`" + file + "`"
}

func constraintsOf(p map[string]any) string {
	var parts []string
	if enum, ok := p["enum"].([]any); ok {
		vals := make([]string, len(enum))
		for i, v := range enum {
			vals[i] = fmt.Sprint(v)
		}
		parts = append(parts, "one of: "+strings.Join(vals, ", "))
	}
	if pat, ok := p["pattern"].(string); ok {
		parts = append(parts, "pattern `"+pat+"`")
	}
	for _, k := range []string{"minimum", "maximum", "minLength", "maxLength"} {
		if v, ok := p[k].(json.Number); ok {
			parts = append(parts, k+" "+v.String())
		}
	}
	if items, ok := p["items"].(map[string]any); ok {
		if c := constraintsOf(items); c != "" {
			parts = append(parts, "items: "+c)
		}
	}
	return strings.Join(parts, "; ")
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func cell(s string) string {
	return strings.ReplaceAll(oneLine(s), "|", "\\|")
}
