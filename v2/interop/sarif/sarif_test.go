package sarif

import (
	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/internal/interoptest"

	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var fixedTime = time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// checkGolden compares v, as indented JSON, with testdata/<name>, or rewrites
// the file under -update.
func checkGolden(t *testing.T, name string, v any) {
	t.Helper()
	got, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", name)
	if *interoptest.Update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -run %s -update to create it)", err, t.Name())
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from the converter output; rerun with -update after checking the change.\n got:\n%s", path, got)
	}
}

func TestFromSARIFGolden(t *testing.T) {
	for _, tool := range []string{"semgrep", "codeql", "trivy", "kinds", "betterleaks", "semgrep-suppressed"} {
		t.Run(tool, func(t *testing.T) {
			opts := DefaultOptions()
			opts.AssetValue = "github.com/example/shop"
			opts.AssetID = "repo"
			opts.BranchInfo = &ctis.BranchInfo{Name: "main", IsDefaultBranch: true, CommitSHA: "0123456789abcdef0123456789abcdef01234567"}
			report, err := Import(readTestdata(t, "sarif/"+tool+".sarif"), opts)
			if err != nil {
				t.Fatal(err)
			}
			report.Metadata.GeneratedAt = fixedTime
			report.Metadata.ID = interoptest.ReportID
			if err := report.Validate(); err != nil {
				t.Fatalf("not valid CTIS: %v", err)
			}
			if err := report.Validate(); err != nil {
				t.Fatalf("converter output fails Validate: %v", err)
			}
			checkGolden(t, "sarif/"+tool+".golden.json", report)
		})
	}
}

func TestFromSARIFSemgrep(t *testing.T) {
	r, err := Import(readTestdata(t, "sarif/semgrep.sarif"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Tool.Techniques; len(got) != 1 || got[0] != ctis.TechniqueSAST {
		t.Errorf("semgrep techniques = %v, want [sast]", got)
	}
	sqli := r.Findings[0]
	if sqli.Vulnerability == nil || len(sqli.Vulnerability.CWEIDs) == 0 || sqli.Vulnerability.CWEIDs[0] != "CWE-89" {
		t.Fatalf("semgrep CWE tag not read: %+v", sqli.Vulnerability)
	}
	if got := strings.Join(sqli.Vulnerability.OWASPIDs, ","); got != "A01:2017,A03:2021" {
		t.Errorf("OWASP ids = %q", got)
	}
	if sqli.Severity != ctis.SeverityMedium {
		t.Errorf("rule default level warning should give medium, got %s", sqli.Severity)
	}
	if len(sqli.Fingerprint) != 64 {
		t.Errorf("long fingerprint should be hashed to 64 hex chars, got %q", sqli.Fingerprint)
	}
	if len(r.Assets) != 1 || r.Assets[0].Type != ctis.AssetTypeUnclassified || sqli.AssetRef != r.Assets[0].ID {
		t.Errorf("without a configured asset the findings go on an unclassified one: %v", r.Assets)
	}
	if sqli.Type != ctis.FindingTypeWeakness {
		t.Errorf("a SAST result without an advisory id is a weakness, got %s", sqli.Type)
	}
}

func TestFromSARIFCodeQL(t *testing.T) {
	r, err := Import(readTestdata(t, "sarif/codeql.sarif"), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		rule string
		sev  ctis.Severity
		cwes string
	}{
		{"js/reflected-xss", ctis.SeverityHigh, "CWE-79,CWE-116"},
		{"js/sql-injection", ctis.SeverityHigh, "CWE-89,CWE-90,CWE-943"},
		// Found through rule.index: the result has no ruleId.
		{"js/command-line-injection", ctis.SeverityCritical, "CWE-78,CWE-88"},
	}
	if len(r.Findings) != len(want) {
		t.Fatalf("got %d findings", len(r.Findings))
	}
	for i, w := range want {
		f := r.Findings[i]
		if f.RuleID != w.rule || f.Severity != w.sev {
			t.Errorf("finding %d: rule %q severity %s, want %q %s", i, f.RuleID, f.Severity, w.rule, w.sev)
		}
		if f.Vulnerability == nil || strings.Join(f.Vulnerability.CWEIDs, ",") != w.cwes {
			t.Errorf("finding %d: CWEs %+v, want %s", i, f.Vulnerability, w.cwes)
		}
		if f.PartialFingerprints["primaryLocationLineHash"] == "" {
			t.Errorf("finding %d: partialFingerprints not carried", i)
		}
		if f.Fingerprint != "" {
			t.Errorf("finding %d: no fingerprints in the log, got %q", i, f.Fingerprint)
		}
	}
	if ll := r.Findings[0].Location.LogicalLocation; ll == nil || ll.Name != "handleSearch" {
		t.Errorf("logical location not read: %+v", ll)
	}
}

func TestFromSARIFTrivy(t *testing.T) {
	r, err := Import(readTestdata(t, "sarif/trivy.sarif"), &Options{ToolType: ""})
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		typ ctis.FindingType
		sev ctis.Severity
		cve string
	}{
		{ctis.FindingTypeVulnerability, ctis.SeverityCritical, "CVE-2021-44228"},
		{ctis.FindingTypeVulnerability, ctis.SeverityMedium, ""},
		{ctis.FindingTypeMisconfiguration, ctis.SeverityHigh, ""},
		{ctis.FindingTypeSecret, ctis.SeverityCritical, ""},
	}
	for i, w := range want {
		f := r.Findings[i]
		if f.Type != w.typ || f.Severity != w.sev {
			t.Errorf("finding %d (%s): %s/%s, want %s/%s", i, f.RuleID, f.Type, f.Severity, w.typ, w.sev)
		}
		cve := ""
		if c := ctis.CVEs(f.Vulnerability); len(c) > 0 {
			cve = c[0]
		}
		if cve != w.cve {
			t.Errorf("finding %d: cve %q, want %q", i, cve, w.cve)
		}
	}

	// ToolType sca forces vulnerability, whatever the tool name says.
	r, err = Import(readTestdata(t, "sarif/trivy.sarif"), &Options{ToolType: "sca"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range r.Findings {
		if f.Type != ctis.FindingTypeVulnerability {
			t.Errorf("ToolType sca: %s typed %s", f.RuleID, f.Type)
		}
	}
	if r.Tool.Techniques[0] != ctis.TechniqueSCA {
		t.Errorf("ToolType sca techniques = %v", r.Tool.Techniques)
	}
}

// The same log must convert to the same fingerprints every time; the old
// code picked whichever key Go's map iteration returned first.
func TestFromSARIFFingerprintDeterministic(t *testing.T) {
	log := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[
	  {"ruleId":"r","message":{"text":"m"},"fingerprints":{"c/v1":"cccccccccccccccc","a/v1":"aaaaaaaaaaaaaaaa","b/v1":"bbbbbbbbbbbbbbbb","d/v1":"dddddddddddddddd"}}]}]}`)
	seen := map[string]int{}
	for i := 0; i < 200; i++ {
		r, err := Import(log, nil)
		if err != nil {
			t.Fatal(err)
		}
		seen[r.Findings[0].Fingerprint]++
	}
	if len(seen) != 1 || seen["aaaaaaaaaaaaaaaa"] != 200 {
		t.Fatalf("fingerprints over 200 conversions: %v; want the lowest key every time", seen)
	}
}

func TestFromSARIFAllRuns(t *testing.T) {
	log := []byte(`{"version":"2.1.0","runs":[
	  {"tool":{"driver":{"name":"gitleaks"}},"results":[{"ruleId":"aws","message":{"text":"key"}}]},
	  {"tool":{"driver":{"name":"semgrep"}},"results":[{"ruleId":"r1","message":{"text":"a"}},{"ruleId":"r2","message":{"text":"b"}}]}]}`)
	r, err := Import(log, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 3 {
		t.Fatalf("want 3 findings from 2 runs, got %d", len(r.Findings))
	}
	ids := map[string]bool{}
	for _, f := range r.Findings {
		if ids[f.ID] {
			t.Errorf("duplicate finding id %s", f.ID)
		}
		ids[f.ID] = true
	}
	if r.Findings[0].Type != ctis.FindingTypeSecret || r.Findings[1].Type != ctis.FindingTypeWeakness {
		t.Errorf("type per run: %s, %s", r.Findings[0].Type, r.Findings[1].Type)
	}
	if r.Findings[2].Tool == nil || r.Findings[2].Tool.Name != "semgrep" {
		t.Errorf("multi-run finding does not name its tool: %+v", r.Findings[2].Tool)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestFromSARIFEdgeCases(t *testing.T) {
	if _, err := Import([]byte("{"), nil); err == nil {
		t.Error("broken JSON must fail")
	}
	r, err := Import([]byte(`{"version":"2.1.0","runs":[]}`), nil)
	if err != nil || len(r.Findings) != 0 || r.Version != ctis.SchemaVersion {
		t.Errorf("empty log: %v %+v", err, r)
	}
	// Out-of-range rule index and security-severity are ignored, not trusted.
	log := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x","rules":[
	  {"id":"r","properties":{"security-severity":"99"}}]}},"results":[
	  {"ruleIndex":7,"message":{"text":"m"}},
	  {"ruleId":"r","level":"note","message":{"text":"n"}},
	  {"ruleId":"r","message":{"text":""},"properties":{"security-severity":3.1}}]}]}`)
	r, err = Import(log, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Findings[0].RuleID != "" || r.Findings[0].Severity != ctis.SeverityMedium {
		t.Errorf("bad index: %+v", r.Findings[0])
	}
	if r.Findings[1].Severity != ctis.SeverityLow {
		t.Errorf("invalid security-severity must fall back to the level: %s", r.Findings[1].Severity)
	}
	if r.Findings[2].Severity != ctis.SeverityLow || r.Findings[2].Title != "r" {
		t.Errorf("result security-severity 3.1: %+v", r.Findings[2])
	}
	if got := detectTechniques("unknown-tool", ""); len(got) != 0 {
		t.Errorf("unknown tool techniques = %v", got)
	}
}

// opengrep SARIF (driver "Opengrep OSS") is code analysis, as semgrep's is.
func TestDetectTechniques_Opengrep(t *testing.T) {
	got := detectTechniques("Opengrep OSS", "")
	if len(got) == 0 || got[0] != ctis.TechniqueSAST {
		t.Errorf("opengrep techniques = %v", got)
	}
}
