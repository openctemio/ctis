package importer

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/ctis"
)

// Evidence items carry the HTTP exchange as captured: every credential in
// them is inside a marked span, and none is anywhere else in the report.
func TestEvidenceSecretsMarked(t *testing.T) {
	cases := map[string][]string{
		"zap/report.golden.json":             {"fake-session-cookie-value", "fake-bearer-token"},
		"zap/api.golden.json":                {"fake-xml-session"},
		"sarif/web.sarif.golden.json":        {"EXAMPLEKEY0123456789", "EXAMPLEBEARER0123456789", "EXAMPLEPASS0123", "EXAMPLESESSION0123"},
		"nuclei/all-fields.golden.json":      {"session=abc"},
		"nuclei/dast.golden.json":            {"s3cr3t-session"},
		"sarif/all-fields.sarif.golden.json": nil,
	}
	for file, secrets := range cases {
		b, err := os.ReadFile(filepath.Join(fixtureRoot, file))
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
					if ptrs := unmarkedIn(&items[i], s); len(ptrs) > 0 {
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
}

// Hostile messages: oversized bodies, header floods, extracted floods and
// control characters still give items within every cap.
func TestEvidenceHostileCaps(t *testing.T) {
	var hdr bytes.Buffer
	for i := 0; i < 400; i++ {
		hdr.WriteString("X-Flood-" + strings.Repeat("h", i%40) + ": " + strings.Repeat("v", 3000) + "\x1b[2J\r\n")
	}
	body := strings.Repeat("<script>\"", 30000)
	var ext []string
	for i := 0; i < 60; i++ {
		ext = append(ext, strings.Repeat("e", 4000))
	}
	rec := map[string]any{
		"template-id": "flood", "info": map[string]any{"name": "flood", "severity": "low"},
		"host": "https://a.example", "matched-at": "https://a.example/x",
		"request":      "GET /x HTTP/1.1\r\n" + hdr.String() + "\r\n" + body,
		"response":     "HTTP/1.1 200 OK\r\n" + hdr.String() + "\r\n" + body,
		"curl-command": strings.Repeat("curl ", 30000), "extracted-results": ext,
	}
	line, _ := json.Marshal(rec)
	res, err := Parse(context.Background(), bytes.NewReader(line), Options{Format: FormatNuclei})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Findings) != 1 {
		t.Fatalf("findings %d, issues %+v", len(res.Report.Findings), res.Issues)
	}
	if err := res.Report.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, it := range res.Report.Findings[0].EvidenceItems {
		raw, _ := json.Marshal(it)
		if len(raw) > ctis.MaxEvidenceItemBytes {
			t.Errorf("%s item is %d bytes", it.Kind, len(raw))
		}
		if bytes.Contains(raw, []byte(`\u001b`)) {
			t.Errorf("%s item holds a control character", it.Kind)
		}
	}
	if n := len(res.Report.Findings[0].EvidenceItems[0].Extracted); n != ctis.MaxEvidenceExtracted {
		t.Errorf("extracted %d", n)
	}
}
