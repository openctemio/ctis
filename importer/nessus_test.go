package importer

import (
	"context"
	"strings"
	"testing"
)

// Values at the edges of the CTIS limits still give a valid report.
func TestNessus_EdgeValuesStayValid(t *testing.T) {
	long := strings.Repeat("A", 300)
	in := nessusHead + "<NessusClientData_v2><Report><ReportHost name=\"192.0.2.1\">" +
		"<ReportItem pluginID=\"1\" severity=\"2\" pluginName=\"t\">" +
		"<exploit_code_maturity>Unproven</exploit_code_maturity>" +
		"<msft>" + long + "</msft><xref>IAVA:" + long + "</xref><xref>" + long + ":1</xref>" +
		"<cve>CVE-2024-0001</cve><cve>not-a-cve</cve>" +
		"</ReportItem></ReportHost></Report></NessusClientData_v2>"
	res, err := Parse(context.Background(), strings.NewReader(in), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Report.Validate(); err != nil {
		t.Fatalf("invalid report: %v", err)
	}
	if got := res.Report.Findings[0].Vulnerability.ExploitMaturity; got != "none" {
		t.Fatalf("exploit_maturity = %q", got)
	}
}
