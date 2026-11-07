package importer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func parseNessusString(t *testing.T, in string, opts Options) *Result {
	t.Helper()
	res, err := Parse(context.Background(), strings.NewReader(nessusHead+in), opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Report.Validate(); err != nil {
		t.Fatalf("invalid report: %v", err)
	}
	return res
}

func nessusHostXML(props, items string) string {
	return "<NessusClientData_v2><Report><ReportHost name=\"192.0.2.1\"><HostProperties>" +
		"<tag name=\"host-ip\">192.0.2.1</tag><tag name=\"operating-system\">Linux Kernel 6.8 on Ubuntu 24.04</tag>" + props +
		"</HostProperties>" + items + "</ReportHost></Report></NessusClientData_v2>"
}

// The package list of one host is bounded; the rest is cut with an issue and
// the import goes on.
func TestNessus_PackagesBoundedPerHost(t *testing.T) {
	var out strings.Builder
	for i := 0; i < nessusMaxPackagesPerHost+50; i++ {
		fmt.Fprintf(&out, "  ii  pkg%d  1.0-%d  amd64  made-up\n", i, i)
	}
	res := parseNessusString(t, nessusHostXML("", `<ReportItem port="0" protocol="tcp" severity="0" pluginID="22869" pluginName="Software Enumeration (SSH)"><description>x</description><plugin_output>`+out.String()+`</plugin_output></ReportItem>`), Options{})
	if n := len(res.Report.Dependencies); n != nessusMaxPackagesPerHost {
		t.Fatalf("components = %d, want %d", n, nessusMaxPackagesPerHost)
	}
	if !hasIssue(res, "installed packages, the rest left out") {
		t.Fatalf("no cut issue: %v", res.Issues)
	}
}

// The global component limit cuts the inventory with an issue, never fails
// the import.
func TestNessus_PackagesStopAtComponentLimit(t *testing.T) {
	out := "  ii  pkga  1.0  amd64  x\n  ii  pkgb  1.0  amd64  x\n  ii  pkgc  1.0  amd64  x\n"
	res := parseNessusString(t, nessusHostXML("", `<ReportItem port="0" protocol="tcp" severity="0" pluginID="22869" pluginName="Software Enumeration (SSH)"><description>x</description><plugin_output>`+out+`</plugin_output></ReportItem>`), Options{Limits: Limits{MaxComponents: 2}})
	if len(res.Report.Dependencies) != 2 || !hasIssue(res, "more than 2 components") {
		t.Fatalf("components = %d issues = %v", len(res.Report.Dependencies), res.Issues)
	}
}

// Hostile package lines never become a component or a purl that points
// elsewhere.
func TestNessus_HostilePackageLines(t *testing.T) {
	out := strings.Join([]string{
		"  ii  good  1.0  amd64  fine",
		"  ii  evil@1.0?x=y  1.0  amd64  injected name",
		"  ii  evil2  1.0/../../x  amd64  injected version",
		"  ii  evil3  1.0#frag  amd64  injected version",
		"  ii  " + strings.Repeat("a", 2000) + "  1.0  amd64  long",
		"  ii  ctl\u00e9name  1.0  amd64  not ascii",
	}, "\n")
	res := parseNessusString(t, nessusHostXML("", `<ReportItem port="0" protocol="tcp" severity="0" pluginID="22869" pluginName="Software Enumeration (SSH)"><description>x</description><plugin_output>`+out+`</plugin_output></ReportItem>`), Options{})
	if len(res.Report.Dependencies) != 1 || res.Report.Dependencies[0].Name != "good" {
		t.Fatalf("components = %+v", res.Report.Dependencies)
	}
	if p := res.Report.Dependencies[0].PURL; p != "pkg:deb/ubuntu/good@1.0?arch=amd64&distro=ubuntu-24.04" {
		t.Fatalf("purl = %q", p)
	}
	if res.Report.Dependencies[0].AssetRef == "" {
		t.Fatal("component without its host")
	}
}

// A plugin that is not a software enumeration plugin gives no components,
// even when its output looks like a package list.
func TestNessus_OnlyEnumerationPluginsGiveComponents(t *testing.T) {
	res := parseNessusString(t, nessusHostXML("", `<ReportItem port="0" protocol="tcp" severity="2" pluginID="99999" pluginName="Other"><description>x</description><plugin_output>  ii  pkga  1.0  amd64  x</plugin_output></ReportItem>`), Options{})
	if len(res.Report.Dependencies) != 0 {
		t.Fatalf("components = %+v", res.Report.Dependencies)
	}
}

// Loopback-only sockets are not services; any-address and specific binds
// are, marked as seen from inside the host.
func TestNessus_NetstatLocalView(t *testing.T) {
	props := `<tag name="netstat-listen-tcp4-0">127.0.0.53:53</tag>` +
		`<tag name="netstat-listen-tcp6-0">[::1]:631</tag>` +
		`<tag name="netstat-listen-tcp4-1">0.0.0.0:3306</tag>` +
		`<tag name="netstat-listen-udp6-0">[fe80::1%eth0]:546</tag>` +
		`<tag name="netstat-listen-tcp4-2">bogus</tag>` +
		`<tag name="netstat-listen-tcp4-3">0.0.0.0:70000</tag>` +
		`<tag name="netstat-established-tcp4-0">192.0.2.1:22-198.51.100.2:5000</tag>`
	res := parseNessusString(t, nessusHostXML(props, ""), Options{})
	var services []string
	for _, a := range res.Report.Assets {
		if a.Type == "service" {
			d := a.Technical.Service.Details
			if d["observed_from"] != "host" || d["bind_address"] == "" {
				t.Errorf("%s details = %v", a.Value, d)
			}
			services = append(services, a.Value)
		}
	}
	if strings.Join(services, ",") != "192.0.2.1:3306/tcp,192.0.2.1:546/udp" {
		t.Fatalf("services = %v", services)
	}
	if !hasIssue(res, "2 listening sockets bound to loopback only") {
		t.Fatalf("issues = %v", res.Issues)
	}
}

// Fingerprints: only key-type lines with a fingerprint shape are kept, at
// most nessusMaxSSHKeys.
func TestNessus_SSHFingerprintBounds(t *testing.T) {
	var lines []string
	for i := 0; i < 20; i++ {
		lines = append(lines, fmt.Sprintf("ssh-rsa %02x:1b:2c:3d:4e:5f:60:71:82:93:a4:b5:c6:d7:e8:f9", i))
	}
	lines = append(lines, "ssh-rsa not-a-fingerprint", "<script> 0a:1b:2c:3d:4e:5f:60:71:82:93:a4:b5:c6:d7:e8:f9")
	got := nessusSSHFingerprints(strings.Join(lines, "\n"))
	if len(got) != nessusMaxSSHKeys {
		t.Fatalf("keys = %v", got)
	}
	for _, k := range got {
		if !strings.HasPrefix(k, "ssh-rsa MD5:") {
			t.Fatalf("key %q", k)
		}
	}
}

// More cpe tags than the technology bound are cut with an issue.
func TestNessus_CPETechnologiesBounded(t *testing.T) {
	var props strings.Builder
	for i := 0; i < 150; i++ {
		fmt.Fprintf(&props, `<tag name="cpe-%d">cpe:/a:examplevendor:product%d:1.%d -> Product %d</tag>`, i, i, i, i)
	}
	res := parseNessusString(t, nessusHostXML(props.String(), ""), Options{})
	if n := len(res.Report.Assets[0].Technologies); n != 100 {
		t.Fatalf("technologies = %d", n)
	}
	if !hasIssue(res, "technologies from cpe tags") {
		t.Fatalf("issues = %v", res.Issues)
	}
}

// The no-details issue is kept even when Issues is full, and a file with
// details never gets it.
func TestNessus_NoDetailsIssueSurvivesFullIssues(t *testing.T) {
	var items strings.Builder
	for i := 0; i < 10; i++ {
		items.WriteString(`<ReportItem port="1" protocol="tcp" severity="0" pluginName="x"></ReportItem>`) // no pluginID: an issue each
	}
	items.WriteString(`<ReportItem port="22" protocol="tcp" severity="0" pluginID="10267" pluginName="SSH"></ReportItem>`)
	res := parseNessusString(t, nessusHostXML("", items.String()), Options{Limits: Limits{MaxIssues: 3}})
	if len(res.Issues) != 3 || !strings.HasPrefix(res.Issues[2].Message, NessusNoDetailsMessage) {
		t.Fatalf("issues = %v", res.Issues)
	}
	res = parseNessusString(t, nessusHostXML("", `<ReportItem port="22" protocol="tcp" severity="0" pluginID="10267" pluginName="SSH"><synopsis>s</synopsis></ReportItem>`), Options{})
	if hasIssue(res, NessusNoDetailsMessage) {
		t.Fatalf("issues = %v", res.Issues)
	}
}

// Sub-checks are bounded in count and size; the JSON stays within the
// source_extra value limit.
func TestNessus_SubChecksBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("The command script with multiple expectations returned :\n\n")
	for i := 0; i < 80; i++ {
		fmt.Fprintf(&b, "----------\nFAILED - check %d %s\nFile: /etc/example\nRegex: %s\n", i, strings.Repeat("t", 300), strings.Repeat("r", 500))
	}
	subs := nessusSubChecks(b.String())
	if len(subs) != nessusMaxSubChecks {
		t.Fatalf("sub-checks = %d", len(subs))
	}
	item := `<ReportItem port="0" protocol="tcp" severity="2" pluginID="21157" pluginName="Unix Compliance Checks"><cm:compliance-check-name>c</cm:compliance-check-name><cm:compliance-result>FAILED</cm:compliance-result><cm:compliance-actual-value>` + b.String() + `</cm:compliance-actual-value></ReportItem>`
	res := parseNessusString(t, nessusHostXML("", item), Options{})
	f := res.Report.Findings[0]
	var got []nessusSubCheck
	if err := json.Unmarshal([]byte(f.SourceExtra["compliance-subchecks"]), &got); err != nil || len(got) == 0 || len(f.SourceExtra["compliance-subchecks"]) > nessusSubChecksExtraKB {
		t.Fatalf("subchecks = %d %v", len(got), err)
	}
	if f.SourceExtra["compliance-subcheck-counts"] != "fail=32" {
		t.Fatalf("counts = %q", f.SourceExtra["compliance-subcheck-counts"])
	}
}

// A description without the repeated sections is kept whole; credentials in
// the original text are redacted.
func TestNessus_ComplianceDescription(t *testing.T) {
	if d, cut := nessusComplianceDescription("Only prose."); cut || d != "Only prose." {
		t.Fatalf("%q %v", d, cut)
	}
	if d, cut := nessusComplianceDescription("Reference: 800-53|AC-1"); cut || d == "" {
		t.Fatalf("%q %v", d, cut)
	}
	item := `<ReportItem port="0" protocol="tcp" severity="2" pluginID="21157" pluginName="Unix Compliance Checks"><description>Prose.

Policy Value: expect x
Actual Value: password=hunter2-not-real</description><cm:compliance-check-name>c</cm:compliance-check-name><cm:compliance-result>FAILED</cm:compliance-result></ReportItem>`
	res := parseNessusString(t, nessusHostXML("", item), Options{})
	f := res.Report.Findings[0]
	if f.Description != "Prose." || strings.Contains(f.SourceExtra["compliance-description-original"], "hunter2") {
		t.Fatalf("description %q original %q", f.Description, f.SourceExtra["compliance-description-original"])
	}
}

func TestNessus_ComplianceMappings(t *testing.T) {
	got := nessusComplianceMappings("800-53r5|AC-2, CSCv7|16.1,bad,|x,PCI-DSSv4.0|8.2.1,CSF|PR.AC-1,Example-Framework|E.1,800-53r5|AC-2")
	want := "nist_800_53|5|AC-2\ncis|controls v7|16.1\npci_dss|4.0|8.2.1\nnist_csf||PR.AC-1\nexample-framework||E.1"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}
