package sarif

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/importer"
	"github.com/openctemio/ctis/v2/interop/engine"
)

// A hostile log cannot use the passthrough to smuggle unbounded data: every
// object keeps at most the passthrough limits, the report stays valid, and
// the members a document repeats per result are bounded per document.
func TestPassthroughHostile(t *testing.T) {
	big := strings.Repeat("x", 40<<10)
	var results []any
	for i := 0; i < 300; i++ {
		res := map[string]any{"ruleId": "r", "message": map[string]any{"text": "m"}, "big": big, "rank": i}
		for k := 0; k < 100; k++ {
			res["extra"+strings.Repeat("k", k)] = k
		}
		results = append(results, res)
	}
	deep := any("leaf")
	for i := 0; i < 50; i++ {
		deep = map[string]any{"d": deep}
	}
	log := map[string]any{"version": "2.1.0", "runs": []any{map[string]any{
		"tool": map[string]any{"driver": map[string]any{"name": "t"}}, "results": results,
		"deep": deep, "environment": map[string]any{"AWS_SECRET_ACCESS_KEY": "x"}, "apiKey": "k",
	}}}
	data, _ := json.Marshal(log)
	res, err := importer.Parse(context.Background(), bytes.NewReader(data), importer.Options{Format: importer.FormatSARIF, Repository: "github.com/example/app"})
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Report.Validate(); err != nil {
		t.Fatalf("report not valid: %v", err)
	}
	total := 0
	for _, f := range res.Report.Findings {
		raw, _ := json.Marshal(f.Extensions)
		if len(raw) > engine.HardLimits.MaxBytes+1024 {
			t.Fatalf("a finding keeps %d bytes", len(raw))
		}
		un, _ := f.Extensions[Namespace]["unmapped"].(map[string]any)
		if len(un) > engine.DefaultLimits.MaxEntries {
			t.Fatalf("a finding keeps %d members", len(un))
		}
		if _, ok := un["/big"]; ok {
			t.Fatal("a member over the size limit was kept")
		}
		total += len(raw)
	}
	if total > engine.DefaultLimits.MaxTotalBytes {
		t.Fatalf("document keeps %d bytes", total)
	}
	doc, _ := json.Marshal(res.Report.Extensions)
	for _, s := range []string{"AWS_SECRET_ACCESS_KEY", "apiKey", `"leaf"`} {
		if strings.Contains(string(doc), s) {
			t.Errorf("document passthrough holds %s: %s", s, doc)
		}
	}
	// The passthrough is data only: a kept member never lands in a core
	// member, and a kept member that names a core place is not written back
	// over what the exporter writes.
	r := ctis.NewReport()
	r.Metadata.ID = "0192f0a0-0000-7000-8000-000000000001"
	r.Assets = []ctis.Asset{{ID: "a", Type: ctis.AssetTypeRepository, Value: "github.com/example/app"}}
	r.Findings = []ctis.Finding{{ID: "f", Type: ctis.FindingTypeWeakness, Title: "real title", Severity: ctis.SeverityHigh, RuleID: "R1", AssetRef: "a",
		Extensions: ctis.Extensions{Namespace: {"version": "2.1.0", "unmapped": map[string]any{"/message": map[string]any{"text": "forged"}, "/level": "none", "/hostedViewerUri": "javascript:alert(1)", "/rank": 5}}}}}
	r.Extensions = ctis.Extensions{Namespace: {"version": "2.1.0", "unmapped": map[string]any{"/version": "9.9", "/runs/0/tool/driver/name": "forged", "/runs/0/language": "en"}}}
	out, err := Export(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"forged", "javascript:", `"9.9"`, `"level": "none"`} {
		if strings.Contains(string(out), s) {
			t.Errorf("export holds %s", s)
		}
	}
	for _, s := range []string{`"rank": 5`, `"language": "en"`} {
		if !strings.Contains(string(out), s) {
			t.Errorf("export lacks the kept member %s", s)
		}
	}
	plain, err := Export(r, &ExportOptions{NoPassthrough: true})
	if err != nil || strings.Contains(string(plain), `"rank"`) {
		t.Fatalf("NoPassthrough wrote kept members: %v", err)
	}
	back, err := Import(data, &Options{NoPassthrough: true, DefaultConfidence: 90})
	if err != nil || len(back.Extensions) != 0 || len(back.Findings[0].Extensions) != 0 {
		t.Fatalf("Import NoPassthrough kept members: %v", err)
	}
	if _, err := Import([]byte(`{"version":"2.0.0","runs":[]}`), nil); err == nil {
		t.Fatal("an unsupported SARIF version was read")
	}
}
