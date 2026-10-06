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

// A host-level result (port 0, service general) is located on its host like
// a port result, so a receiver keys it by host and plugin, not by its title.
func TestNessus_HostLevelResultHasNetworkLocation(t *testing.T) {
	in := nessusHead + "<NessusClientData_v2><Report><ReportHost name=\"192.0.2.1\">" +
		"<HostProperties><tag name=\"host-ip\">192.0.2.1</tag></HostProperties>" +
		"<ReportItem port=\"0\" svc_name=\"general\" protocol=\"TCP\" pluginID=\"57582\" severity=\"2\" pluginName=\"Self-signed\"></ReportItem>" +
		"<ReportItem port=\"443\" svc_name=\"www\" protocol=\"tcp\" pluginID=\"1\" severity=\"2\" pluginName=\"t\"></ReportItem>" +
		"<ReportItem port=\"99999\" svc_name=\"x\" protocol=\"udp\" pluginID=\"2\" severity=\"2\" pluginName=\"u\"></ReportItem>" +
		"</ReportHost></Report></NessusClientData_v2>"
	res, err := Parse(context.Background(), strings.NewReader(in), Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		port      int
		proto, sv string
	}{{0, "tcp", ""}, {443, "tcp", "www"}, {0, "udp", "x"}}
	if len(res.Report.Findings) != len(want) {
		t.Fatalf("findings = %d", len(res.Report.Findings))
	}
	for i, w := range want {
		n := res.Report.Findings[i].Network
		if n == nil || n.Host != "192.0.2.1" || n.Port != w.port || n.Protocol != w.proto || n.Service != w.sv {
			t.Errorf("finding %d network = %+v, want host 192.0.2.1 %+v", i, n, w)
		}
	}
}
