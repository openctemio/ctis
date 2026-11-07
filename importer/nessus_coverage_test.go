package importer

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func coverageFixture(t *testing.T) *Result {
	t.Helper()
	f, err := os.Open("../testdata/importers/nessus/coverage.nessus")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	res, err := Parse(context.Background(), f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// What a re-scan may close: a finished host, a plugin that ran, a local
// check only where local checks ran, never compliance, never a finding seen
// after the scan.
func TestImportCoverage_Covers(t *testing.T) {
	c := coverageFixture(t).Coverage
	if c == nil || !c.Complete {
		t.Fatalf("coverage = %+v", c)
	}
	before := time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC)
	after := time.Date(2025, 11, 7, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name              string
		host, plugin, fam string
		local, compliance bool
		seen              *time.Time
		want              bool
	}{
		{"plugin in plugin_set, finished host", "ip_address-192.0.2.71", "51192", "General", false, false, &before, true},
		{"individually enabled plugin", "ip_address-192.0.2.71", "57582", "General", false, false, nil, true},
		{"local family that ran, local checks ran", "ip_address-192.0.2.71", "123456", "Ubuntu Local Security Checks", true, false, nil, true},
		{"individually disabled plugin of a mixed family", "ip_address-192.0.2.71", "99999", "General", false, false, nil, false},
		{"family not run", "ip_address-192.0.2.71", "400001", "Windows", false, false, nil, false},
		{"seen after the host's scan", "ip_address-192.0.2.71", "51192", "General", false, false, &after, false},
		{"compliance never closes by absence", "ip_address-192.0.2.71", "21157", "Policy Compliance", true, true, nil, false},
		{"auth failure: local check stays", "ip_address-192.0.2.72", "123456", "Ubuntu Local Security Checks", true, false, nil, false},
		{"auth failure: network check closes", "ip_address-192.0.2.72", "51192", "General", false, false, nil, true},
		{"unfinished host proves nothing", "ip_address-192.0.2.73", "10267", "Service detection", false, false, nil, false},
		{"host missing from the file", "ip_address-192.0.2.99", "51192", "General", false, false, nil, false},
		{"no plugin id", "ip_address-192.0.2.71", "", "General", false, false, nil, false},
	}
	for _, tc := range cases {
		if got := c.Covers(tc.host, tc.plugin, tc.fam, tc.local, tc.compliance, tc.seen); got != tc.want {
			t.Errorf("%s: Covers = %v, want %v", tc.name, got, tc.want)
		}
	}
	var nilCov *ImportCoverage
	if nilCov.Covers("ip_address-192.0.2.71", "51192", "General", false, false, nil) {
		t.Fatal("nil coverage closed a finding")
	}
}

// A file without a plugin selection or without plugin details proves
// nothing.
func TestImportCoverage_IncompleteFiles(t *testing.T) {
	host := `<ReportHost name="192.0.2.1"><HostProperties><tag name="host-ip">192.0.2.1</tag><tag name="HOST_END_TIMESTAMP">1762416000</tag></HostProperties>` +
		`<ReportItem port="443" protocol="tcp" severity="2" pluginID="51192" pluginName="c" pluginFamily="General">%s</ReportItem></ReportHost>`
	policy := `<Policy><Preferences><ServerPreferences><preference><name>plugin_set</name><value>51192</value></preference></ServerPreferences></Preferences></Policy>`
	for _, tc := range []struct {
		name, doc string
		reasons   string
	}{
		{"no policy", `<NessusClientData_v2><Report>` + strings.Replace(host, "%s", "<synopsis>s</synopsis>", 1) + `</Report></NessusClientData_v2>`, CoverageNoPolicy},
		{"no plugin details", `<NessusClientData_v2>` + policy + `<Report>` + strings.Replace(host, "%s", "", 1) + `</Report></NessusClientData_v2>`, CoverageNoPluginDetails},
		{"no hosts", `<NessusClientData_v2>` + policy + `<Report></Report></NessusClientData_v2>`, CoverageNoHosts},
	} {
		res, err := Parse(context.Background(), strings.NewReader(nessusHead+tc.doc), Options{})
		if err != nil {
			t.Fatal(err)
		}
		c := res.Coverage
		if c == nil || c.Complete || strings.Join(c.Reasons, ",") != tc.reasons {
			t.Errorf("%s: coverage = %+v", tc.name, c)
		}
		if c.Covers("ip_address-192.0.2.1", "51192", "General", false, false, nil) {
			t.Errorf("%s: an incomplete file closed a finding", tc.name)
		}
	}
}

// Reading the plugin selection never lets a policy value other than the
// plugin set into the result; a hostile plugin set is bounded to digits.
func TestImportCoverage_PolicyNeverLeaksPreferences(t *testing.T) {
	doc := `<NessusClientData_v2><Policy><Preferences><ServerPreferences>` +
		`<preference><name>plugin_set</name><value>51192;evil;../x;1 2;` + strings.Repeat("7", 40) + `</value></preference>` +
		`<preference><name>TARGET</name><value>secret-target.example.com</value></preference>` +
		`</ServerPreferences><PluginsPreferences><item><preferenceName>SSH password :</preferenceName><selectedValue>Pol1cy-S3cret</selectedValue></item></PluginsPreferences></Preferences>` +
		`<FamilySelection><FamilyItem><FamilyName>General</FamilyName><Status>mixed</Status></FamilyItem></FamilySelection></Policy>` +
		`<Report><ReportHost name="192.0.2.1"><HostProperties><tag name="host-ip">192.0.2.1</tag></HostProperties>` +
		`<ReportItem port="443" protocol="tcp" severity="2" pluginID="51192" pluginName="c"><synopsis>s</synopsis></ReportItem></ReportHost></Report></NessusClientData_v2>`
	res, err := Parse(context.Background(), strings.NewReader(nessusHead+doc), Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	for _, s := range []string{"Pol1cy-S3cret", "secret-target", "evil", "../x"} {
		if strings.Contains(string(b), s) {
			t.Errorf("result holds %q", s)
		}
	}
	if got := strings.Join(res.Coverage.Plugins, ","); got != "51192" {
		t.Fatalf("plugins = %q", got)
	}
	if len(res.Coverage.Families) != 0 {
		t.Fatalf("a mixed family counted as run whole: %v", res.Coverage.Families)
	}
}
