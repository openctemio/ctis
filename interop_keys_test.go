package ctis

import "testing"

func TestLocationKeyWeb(t *testing.T) {
	cases := []struct {
		name string
		f    Finding
		want string
	}{
		{"web url", Finding{Web: &WebLocation{URL: "HTTPS://Example.COM:443/Admin/Login"}}, "url:https://example.com/Admin/Login"},
		{"web url wins over location path", Finding{
			Web:      &WebLocation{URL: "https://example.com/a"},
			Location: &FindingLocation{Path: "https://other.example/b"},
		}, "url:https://example.com/a"},
		{"web url wins over file path", Finding{
			Web:      &WebLocation{URL: "https://example.com/a"},
			Location: &FindingLocation{Path: "src/app.py"},
		}, "url:https://example.com/a"},
		{"package wins over web", Finding{
			Web:           &WebLocation{URL: "https://example.com/a"},
			Vulnerability: &VulnerabilityDetails{Package: "lodash", Ecosystem: "npm"},
		}, "pkg:npm/lodash"},
		{"unusable web url falls back to location", Finding{
			Web:      &WebLocation{URL: "ftp://example.com/a"},
			Location: &FindingLocation{Path: "src/app.py"},
		}, "file:src/app.py"},
		{"web url wins over network", Finding{
			Web:     &WebLocation{URL: "http://example.com:8080/x"},
			Network: &NetworkLocation{Port: 8080},
		}, "url:http://example.com:8080/x"},
	}
	for _, c := range cases {
		if got := LocationKey(&c.f); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestPreferredVulnerabilityIDNumeric(t *testing.T) {
	cve := func(ids ...string) *VulnerabilityDetails { return &VulnerabilityDetails{CVEIDs: ids} }
	cases := []struct {
		name string
		v    *VulnerabilityDetails
		want string
	}{
		{"sequence length", cve("CVE-2021-10000", "CVE-2021-9999"), "CVE-2021-9999"},
		{"year first", cve("CVE-2022-0001", "CVE-2021-99999"), "CVE-2021-99999"},
		{"leading zeros", cve("CVE-2021-00100", "CVE-2021-0099"), "CVE-2021-0099"},
		{"order independent", cve("CVE-2021-9999", "CVE-2021-10000"), "CVE-2021-9999"},
		{"long sequence", cve("CVE-2021-1234567890123", "CVE-2021-999999"), "CVE-2021-999999"},
	}
	for _, c := range cases {
		got, ok := PreferredVulnerabilityID(c.v)
		if !ok || got.ID != c.want {
			t.Errorf("%s: %+v, want %s", c.name, got, c.want)
		}
	}
}

func TestCVELessMalformed(t *testing.T) {
	// A malformed id sorts after every well-formed one and the order is total.
	if !cveLess("CVE-2021-1", "CVE-X") || cveLess("CVE-X", "CVE-2021-1") {
		t.Error("well-formed must come first")
	}
	if !cveLess("CVE-A", "CVE-B") || cveLess("CVE-B", "CVE-A") || cveLess("CVE-A", "CVE-A") {
		t.Error("malformed ids order by text")
	}
	if cveLess("CVE-2021-1", "CVE-2021-1") {
		t.Error("equal ids are not less")
	}
}

func TestLocationKeyEcosystemToPURLType(t *testing.T) {
	cases := map[string]string{
		"pip": "pypi", "PyPI": "pypi", "python": "pypi",
		"go": "golang", "golang": "golang",
		"npm": "npm", "node": "npm",
		"maven": "maven", "java": "maven",
		"nuget": "nuget", "gem": "gem", "rubygems": "gem",
		"cargo": "cargo", "crates.io": "cargo", "rust": "cargo",
		"composer": "composer", "packagist": "composer",
		" Hex ":      "hex",
		"unheard-of": "unheard-of",
	}
	for eco, typ := range cases {
		f := &Finding{Vulnerability: &VulnerabilityDetails{Package: "p", Ecosystem: eco}}
		if got, want := LocationKey(f), "pkg:"+typ+"/p"; got != want {
			t.Errorf("ecosystem %q: %q, want %q", eco, got, want)
		}
	}
	// One package, one key, whichever way it is named.
	a := LocationKey(&Finding{Vulnerability: &VulnerabilityDetails{Package: "requests", Ecosystem: "pip"}})
	b := LocationKey(&Finding{Vulnerability: &VulnerabilityDetails{Package: "requests", PURL: "pkg:pypi/requests@2.0"}})
	if a != b {
		t.Errorf("pip and purl keys differ: %q vs %q", a, b)
	}
}

func TestNormalizeAssetNameURLCase(t *testing.T) {
	cases := []struct {
		t    AssetType
		in   string
		want string
	}{
		{AssetTypeHTTPService, "HTTPS://Example.COM:8443/", "https://example.com:8443"},
		{AssetTypeHTTPService, "https://Example.com", "https://example.com"},
		{AssetTypeDiscoveredURL, "https://Example.COM/Admin/Login?Next=/Home", "https://example.com/Admin/Login?Next=/Home"},
		{AssetTypeDiscoveredURL, "https://Example.com?A=B", "https://example.com?A=B"},
		{AssetTypeDiscoveredURL, "https://User:Pw@Example.com/P", "https://User:Pw@example.com/P"},
		{AssetTypeDiscoveredURL, "https://[2001:DB8::1]:8080/X", "https://[2001:db8::1]:8080/X"},
		{AssetTypeDiscoveredURL, "Example.com/Path/", "example.com/Path"},
	}
	for _, c := range cases {
		got := NormalizeAssetName(c.t, c.in)
		if got != c.want {
			t.Errorf("%s %q = %q, want %q", c.t, c.in, got, c.want)
		}
		if again := NormalizeAssetName(c.t, got); again != got {
			t.Errorf("not idempotent: %q -> %q", got, again)
		}
	}
}
