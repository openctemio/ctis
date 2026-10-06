package importer

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/openctemio/ctis"
)

// ToolType decides the finding type and the tool capabilities of a SARIF
// log; DefaultConfidence is the confidence of results whose rule states no
// precision. Unknown tool types and out-of-range confidences keep the
// defaults.
func TestSARIF_ToolTypeAndConfidence(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(fixtureRoot, "sarif", "semgrep.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	parse := func(o Options) *Result {
		t.Helper()
		o.Repository = "github.com/example/app"
		res, err := Parse(context.Background(), bytes.NewReader(data), o)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Report.Findings) == 0 {
			t.Fatal("no findings")
		}
		return res
	}

	base := parse(Options{})
	if base.Report.Findings[0].Type == ctis.FindingTypeMisconfiguration {
		t.Fatal("fixture already misconfiguration; pick another")
	}

	res := parse(Options{ToolType: "iac", DefaultConfidence: 40})
	for _, f := range res.Report.Findings {
		if f.Type != ctis.FindingTypeMisconfiguration {
			t.Errorf("type = %q, want misconfiguration", f.Type)
		}
	}
	if !slices.Equal(res.Report.Tool.Capabilities, []string{"misconfiguration"}) {
		t.Errorf("capabilities = %v", res.Report.Tool.Capabilities)
	}

	// A named tool keeps the capabilities of its type.
	res = parse(Options{ToolName: "custom", ToolType: "secret"})
	if res.Report.Tool.Name != "custom" || !slices.Equal(res.Report.Tool.Capabilities, []string{"secret"}) {
		t.Errorf("tool = %+v", res.Report.Tool)
	}

	// Unknown values are ignored.
	res = parse(Options{ToolType: "rootkit", DefaultConfidence: 500})
	for i, f := range res.Report.Findings {
		if f.Type != base.Report.Findings[i].Type || f.Confidence != base.Report.Findings[i].Confidence {
			t.Errorf("finding %d changed: %q/%d, want %q/%d", i, f.Type, f.Confidence, base.Report.Findings[i].Type, base.Report.Findings[i].Confidence)
		}
	}
}

func TestSARIF_DefaultConfidence(t *testing.T) {
	log := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"scan","rules":[{"id":"r1"}]}},"results":[{"ruleId":"r1","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]}]}]}`
	for _, c := range []struct{ in, want int }{{0, 90}, {40, 40}, {101, 90}} {
		res, err := Parse(context.Background(), bytes.NewReader([]byte(log)), Options{Repository: "github.com/example/app", DefaultConfidence: c.in})
		if err != nil {
			t.Fatal(err)
		}
		if got := res.Report.Findings[0].Confidence; got != c.want {
			t.Errorf("DefaultConfidence %d: confidence = %d, want %d", c.in, got, c.want)
		}
	}
}
