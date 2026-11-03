package sarif

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/openctemio/ctis/v2"

	"testing"
)

func FuzzImport(f *testing.F) {
	addTestdataSeeds(f, "sarif/*.sarif")
	addTestdataSeeds(f, "importers/codeflows.sarif.json")
	f.Add([]byte(`{"runs":[{"tool":{"driver":{"rules":[{"id":"r"}]}},"results":[{"ruleIndex":-1,"rule":{"index":99},"message":{"text":""}}]}]}`))
	f.Add([]byte(`{"runs":[{"originalUriBaseIds":{"R":{"uri":"file:///w/"}},"results":[{"message":{"text":"t"},"codeFlows":[{"threadFlows":[{"locations":[{"kinds":["source"],"location":{"physicalLocation":{"artifactLocation":{"uri":"file:///w/a.js"},"region":{"startLine":1,"snippet":{"text":"password = \"hunter2hunter2\""}}}}},{"location":{"physicalLocation":{"artifactLocation":{"uri":"../x"}}}}]}]}]}]}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := Import(data, nil)
		if err != nil {
			return
		}
		if r.Version != ctis.SchemaVersion {
			t.Fatalf("version %q", r.Version)
		}
		_ = r.Validate()
		// A secret finding never carries a snippet other than a redaction.
		for _, fd := range r.Findings {
			if fd.Type != ctis.FindingTypeSecret || fd.Location == nil || fd.Location.Snippet == "" {
				continue
			}
			s := fd.Location.Snippet
			if !isRedacted(s) && !strings.HasSuffix(s, "********") {
				t.Fatalf("secret finding snippet not redacted: %q", s)
			}
		}
		for _, fd := range r.Findings {
			checkDataFlow(t, fd.DataFlow)
		}
	})
}

func checkDataFlow(t *testing.T, df *ctis.DataFlow) {
	t.Helper()
	if df == nil {
		return
	}
	steps := append(df.GetFullPath(), df.Sanitizers...)
	if len(steps) == 0 || len(steps) > ctis.MaxDataFlowSteps {
		t.Fatalf("steps %d", len(steps))
	}
	seen := make([]bool, len(steps))
	for _, l := range steps {
		if l.Index < 0 || l.Index >= len(steps) || seen[l.Index] {
			t.Fatalf("index %d of %d", l.Index, len(steps))
		}
		seen[l.Index] = true
		if strings.HasPrefix(l.Path, "/") || strings.HasPrefix(l.Path, "../") || l.Path == ".." || strings.Contains(l.Path, "://") {
			t.Fatalf("path not repository-relative: %q", l.Path)
		}
		if utf8.RuneCountInString(l.Path) > ctis.MaxDataFlowPathLen || utf8.RuneCountInString(l.Content) > ctis.MaxDataFlowContentLen || utf8.RuneCountInString(l.Label) > ctis.MaxDataFlowLabelLen {
			t.Fatalf("text not bounded: %+v", l)
		}
		if l.Line < 0 || l.Column < 0 || l.EndLine < 0 || l.EndColumn < 0 {
			t.Fatalf("negative position: %+v", l)
		}
		if ctis.RedactCodeSecrets(l.Content) != l.Content {
			t.Fatalf("content not redacted: %q", l.Content)
		}
	}
}

func TestFromSARIF_CodeFlows(t *testing.T) {
	type step struct {
		Kinds   []string `json:"kinds,omitempty"`
		Message string   `json:"-"`
		Path    string   `json:"-"`
		Line    int      `json:"-"`
	}
	build := func(steps ...step) string {
		var locs []map[string]any
		for _, s := range steps {
			loc := map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": s.Path},
				"region":           map[string]any{"startLine": s.Line},
			}}
			if s.Message != "" {
				loc["message"] = map[string]any{"text": s.Message}
			}
			tfl := map[string]any{"location": loc}
			if s.Kinds != nil {
				tfl["kinds"] = s.Kinds
			}
			locs = append(locs, tfl)
		}
		b, _ := json.Marshal([]any{map[string]any{"threadFlows": []any{map[string]any{"locations": locs}}}})
		return string(b)
	}
	roles := func(df *ctis.DataFlow) string {
		if df == nil {
			return "<nil>"
		}
		out := make([]string, len(df.GetFullPath())+len(df.Sanitizers))
		for _, l := range append(df.GetFullPath(), df.Sanitizers...) {
			out[l.Index] = string(l.Type)
		}
		return strings.Join(out, ",")
	}
	cases := []struct {
		name, flows, want string
	}{
		{"position", build(step{Path: "a", Line: 1}, step{Path: "a", Line: 2}, step{Path: "a", Line: 3}), "source,propagator,sink"},
		{"one step is the sink", build(step{Path: "a", Line: 1}), "sink"},
		{"kinds win over position", build(step{Path: "a", Line: 1, Kinds: []string{"sink"}}, step{Path: "a", Line: 2, Kinds: []string{"source"}}), "sink,source"},
		{"kinds sanitizer", build(step{Path: "a", Line: 1}, step{Path: "a", Line: 2, Kinds: []string{"taint", "sanitizer"}}, step{Path: "a", Line: 3}), "source,sanitizer,sink"},
		{"message sanitized", build(step{Path: "a", Line: 1}, step{Path: "a", Line: 2, Message: "value is sanitized here"}, step{Path: "a", Line: 3}), "source,sanitizer,sink"},
		{"semgrep messages", build(step{Path: "a", Line: 1, Message: "Source: 'x' @ 'a:1'"}, step{Path: "a", Line: 2, Message: "Propagator : 'y' @ 'a:2'"}, step{Path: "a", Line: 3, Message: "Sink: 'z' @ 'a:3'"}), "source,propagator,sink"},
		{"word prefix only", build(step{Path: "a", Line: 1, Message: "sourceFile"}, step{Path: "a", Line: 2, Message: "sinkhole"}), "source,sink"},
		{"empty locations skipped", `[{"threadFlows":[{"locations":[{"location":{}},{"location":{"physicalLocation":{"artifactLocation":{"uri":"a"},"region":{"startLine":4}}}}]}]}]`, "sink"},
		{"first non-empty thread flow", `[{"threadFlows":[{"locations":[]}]},{"threadFlows":[{"locations":[{"location":{"message":{"text":"m"}}}]}]}]`, "sink"},
		{"malformed trace", `[{"threadFlows":"nope"}]`, "<nil>"},
		{"malformed kinds", `[{"threadFlows":[{"locations":[{"kinds":"source","location":{"message":{"text":"m"}}}]}]}]`, "<nil>"},
		{"not an array", `{"a":1}`, "<nil>"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"codeql"}},"results":[{"ruleId":"r","message":{"text":"t"},"codeFlows":` + c.flows + `}]}]}`
			rep, err := Import([]byte(doc), nil)
			if err != nil {
				t.Fatalf("a trace never fails the log: %v", err)
			}
			if len(rep.Findings) != 1 {
				t.Fatalf("findings %d", len(rep.Findings))
			}
			if got := roles(rep.Findings[0].DataFlow); got != c.want {
				t.Errorf("roles %s, want %s", got, c.want)
			}
		})
	}
}

// The data flow is context: the finding's fingerprint is the same with and
// without it, and a changed trace does not change the identity.
func TestFromSARIF_CodeFlowsNotInFingerprint(t *testing.T) {
	base := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[{"ruleId":"r","message":{"text":"t"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{"startLine":3}}}]%s}]}]}`
	flow := `,"codeFlows":[{"threadFlows":[{"locations":[{"location":{"physicalLocation":{"artifactLocation":{"uri":"%s"},"region":{"startLine":1}}}}]}]}]`
	var fps []string
	for _, extra := range []string{"", strings.Replace(flow, "%s", "a.py", 1), strings.Replace(flow, "%s", "b.py", 1)} {
		rep, err := Import([]byte(strings.Replace(base, "%s", extra, 1)), nil)
		if err != nil || len(rep.Findings) != 1 {
			t.Fatalf("%v %+v", err, rep)
		}
		f := rep.Findings[0]
		if (extra == "") != (f.DataFlow == nil) {
			t.Fatalf("data flow presence: %+v", f.DataFlow)
		}
		fps = append(fps, f.Fingerprint+"|"+ctis.LocationKey(&f))
	}
	if fps[0] != fps[1] || fps[1] != fps[2] {
		t.Errorf("fingerprints differ with the trace: %q", fps)
	}
}

// A secret finding's raw match is masked in its data flow too.
func TestFromSARIF_CodeFlowsSecretMasked(t *testing.T) {
	const raw = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[{"ruleId":"github-pat","message":{"text":"secret"},
	"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.env"},"region":{"startLine":1,"snippet":{"text":"` + raw + `"}}}}],
	"codeFlows":[{"threadFlows":[{"locations":[{"location":{"physicalLocation":{"artifactLocation":{"uri":"a.env"},"region":{"startLine":1,"snippet":{"text":"T=` + raw + `"}}},"message":{"text":"` + raw + `"}}}]}]}]}]}]}`
	rep, err := Import([]byte(doc), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(rep.Findings[0].DataFlow)
	if ctis.ContainsSecret(string(b), raw) || rep.Findings[0].DataFlow == nil {
		t.Errorf("raw secret in data flow: %s", b)
	}
}

// A SARIF result with no result-level "level" must inherit the rule's
// defaultConfiguration.level (SARIF spec) instead of collapsing to medium.
func TestFromSARIF_RuleLevelSeverityFallback(t *testing.T) {
	sarif := []byte(`{
	  "version": "2.1.0",
	  "runs": [{
	    "tool": {"driver": {"name": "demo", "rules": [
	      {"id": "RULE-CRIT", "defaultConfiguration": {"level": "error"}},
	      {"id": "RULE-NOTE", "defaultConfiguration": {"level": "note"}}
	    ]}},
	    "results": [
	      {"ruleId": "RULE-CRIT", "message": {"text": "no result level → use rule error"}},
	      {"ruleId": "RULE-NOTE", "message": {"text": "no result level → use rule note"}},
	      {"ruleId": "RULE-CRIT", "level": "warning", "message": {"text": "result level wins"}}
	    ]
	  }]
	}`)

	report, err := Import(sarif, nil)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if len(report.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(report.Findings))
	}
	if report.Findings[0].Severity != ctis.SeverityHigh {
		t.Errorf("rule error → High, got %s", report.Findings[0].Severity)
	}
	if report.Findings[1].Severity != ctis.SeverityLow {
		t.Errorf("rule note → Low, got %s", report.Findings[1].Severity)
	}
	if report.Findings[2].Severity != ctis.SeverityMedium {
		t.Errorf("result warning overrides rule → Medium, got %s", report.Findings[2].Severity)
	}
}

func addTestdataSeeds(f *testing.F, glob string) {
	files, _ := filepath.Glob(filepath.Join("testdata", glob))
	for _, name := range files {
		if b, err := os.ReadFile(name); err == nil {
			f.Add(b)
		}
	}
}

// The SARIF level table of the mapping agrees with the native severity
// table of the core (ctis.NormalizeNativeSeverity).
func TestLevelTableMatchesNativeSeverity(t *testing.T) {
	for _, lvl := range []string{"error", "warning", "note", "none"} {
		got, _ := ctis.NormalizeNativeSeverity(ctis.NativeSchemeSARIF, lvl)
		want, _ := imp.Lookup("level_severity", lvl)
		if string(got) != want {
			t.Errorf("sarif %s: core table %s, mapping %s", lvl, got, want)
		}
	}
}
