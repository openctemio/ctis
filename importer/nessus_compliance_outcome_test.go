package importer

import (
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"
)

// ERROR (the check could not run) and SKIPPED are both kind not_applicable,
// told apart by extensions["io.openctem"].compliance_outcome; every other
// result carries no outcome.
func TestNessus_ComplianceOutcome(t *testing.T) {
	for _, tc := range []struct{ native, kind, outcome string }{
		{"PASSED", "pass", ""},
		{"FAILED", "fail", ""},
		{"WARNING", "review", ""},
		{"ERROR", "not_applicable", "error"},
		{"SKIPPED", "not_applicable", "skipped"},
	} {
		item := `<ReportItem port="0" protocol="tcp" severity="2" pluginID="21157" pluginName="Unix Compliance Checks"><cm:compliance-check-name>c</cm:compliance-check-name><cm:compliance-result>` +
			tc.native + `</cm:compliance-result><cm:compliance-error>audit could not run</cm:compliance-error></ReportItem>`
		res := parseNessusString(t, nessusHostXML("", item), Options{})
		f := res.Report.Findings[0]
		if f.Kind != tc.kind {
			t.Errorf("%s: kind %q, want %q", tc.native, f.Kind, tc.kind)
		}
		v, ok := f.Extensions.Get(ctis.OpenCTEMNamespace, ComplianceOutcomeKey)
		if (tc.outcome == "") == ok || (ok && v != tc.outcome) {
			t.Errorf("%s: outcome %v (%v), want %q", tc.native, v, ok, tc.outcome)
		}
		if f.SourceExtra["compliance-result"] != tc.native {
			t.Errorf("%s: native result not kept: %q", tc.native, f.SourceExtra["compliance-result"])
		}
	}
}

// A sub-check that could not run keeps result error.
func TestNessus_SubCheckError(t *testing.T) {
	actual := strings.Join([]string{"------", "ERROR - first", "detail", "------", "PASSED - second", "------", "WARNING - third", ""}, "\n")
	subs := nessusSubChecks(actual)
	if len(subs) != 3 || subs[0].Result != "error" || subs[1].Result != "pass" || subs[2].Result != "review" {
		t.Fatalf("sub-checks = %+v", subs)
	}
}
