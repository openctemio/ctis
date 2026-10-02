package ctis

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func reconFixtures() map[string]*ReconToCTISInput {
	return map[string]*ReconToCTISInput{
		"subdomain": {
			ScannerName: "subfinder", ScannerVersion: "2.6.6", ReconType: "subdomain", Target: "example.com", DurationMs: 1200,
			Subdomains: []SubdomainInput{
				{Host: "example.com", Domain: "example.com", Source: "crtsh", IPs: []string{"93.184.216.34"}},
				{Host: "api.example.com", Domain: "example.com", Source: "dnsdumpster", IPs: []string{"93.184.216.35", "2606:2800:220:1::248", "not-an-ip"}},
				{Host: "api.example.com", Domain: "example.com"}, // duplicate
				{Host: ""},
				// Normalises to the same ID as api.example.com.
				{Host: "api-example.com", Domain: "example.com"},
			},
		},
		"dns": {
			ScannerName: "dnsx", ReconType: "dns", Target: "example.com",
			DNSRecords: []DNSRecordInput{
				{Host: "example.com", RecordType: "a", Values: []string{"1.1.1.1", "2.2.2.2"}, TTL: 300},
				{Host: "example.com", RecordType: "ns", Values: []string{"ns1.example.net."}},
				{Host: "example.com", RecordType: "HINFO", Values: []string{"x86 linux"}},
				{Host: "mail.example.com", RecordType: "MX", Values: []string{"10 mx.example.com", ""}, TTL: -5},
			},
		},
		"port": {
			ScannerName: "naabu", ReconType: "port", Target: "10.0.0.0/30",
			OpenPorts: []OpenPortInput{
				{IP: "10.0.0.1", Host: "web.internal", Port: 443, Protocol: "TCP", Service: "https"},
				{IP: "10.0.0.1", Port: 22, Protocol: "tcp"},
				{Host: "example.com", Port: 80}, // no IP: a hostname
				{IP: "2001:db8::1", Port: 8443, Protocol: "sctp"},
				{IP: "10.0.0.2", Port: 0}, // out of range, dropped
			},
		},
		"http_probe": {
			ScannerName: "httpx", ReconType: "http_probe", Target: "example.com",
			LiveHosts: []LiveHostInput{
				{URL: "https://example.com", Host: "example.com", Port: 443, Scheme: "https", StatusCode: 200, Title: "Example", Technologies: []string{"nginx"}, IP: "93.184.216.34", TLSVersion: "tls13"},
				{URL: "http://admin.example.com", Host: "admin.example.com", Port: 80, Scheme: "http", StatusCode: 503, Redirect: "https://admin.example.com/login", CDN: "cloudflare"},
			},
		},
		"url_crawl": {
			ScannerName: "katana", ReconType: "url_crawl", Target: "https://example.com",
			URLs: []DiscoveredURLInput{
				{URL: "https://example.com/login?next=/", Method: "GET", Source: "href", Depth: 1, Type: "form", StatusCode: 200, Parent: "https://example.com"},
				{URL: "https://example.com/" + strings.Repeat("a", 300)},
			},
		},
		"mixed": {
			ScannerName: "custom-recon", ReconType: "",
			Subdomains: []SubdomainInput{{Host: "a.example.com", Domain: "example.com"}},
			OpenPorts:  []OpenPortInput{{IP: "10.1.1.1", Port: 8080}},
			LiveHosts:  []LiveHostInput{{URL: "http://a.example.com"}},
			URLs:       []DiscoveredURLInput{{URL: "http://a.example.com/x"}},
			DNSRecords: []DNSRecordInput{{Host: "a.example.com", RecordType: "CNAME", Values: []string{"b.example.com"}}},
			Technologies: []TechnologyInput{
				{Name: "nginx", Version: "1.25"},
			},
		},
	}
}

// Every converter output must validate against the published schema and
// pass Validate; this is what api ingests.
func TestReconConverterOutputIsSchemaValid(t *testing.T) {
	s := loadSchemaSet(t)
	for name, in := range reconFixtures() {
		for _, group := range []bool{true, false} {
			opts := DefaultReconConverterOptions()
			opts.GroupByIP = group
			r, err := ConvertReconToCTIS(in, opts)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			assertReportValid(t, s, r)
			if err := r.Validate(); err != nil {
				t.Errorf("%s (group=%v): %v", name, group, err)
			}
			if r.Version != SchemaVersion || r.Schema != SchemaURL {
				t.Errorf("%s: version %q schema %q", name, r.Version, r.Schema)
			}
		}
	}
	// The merged pipeline report too.
	var all []*Report
	for _, in := range reconFixtures() {
		r, _ := ConvertReconToCTIS(in, nil)
		all = append(all, r)
	}
	merged := MergeReconReports(all)
	assertReportValid(t, s, merged)
	if err := merged.Validate(); err != nil {
		t.Error(err)
	}
}

func assetsByValue(r *Report) map[string]Asset {
	out := map[string]Asset{}
	for _, a := range r.Assets {
		out[a.Value] = a
	}
	return out
}

func TestReconScopeCapabilityVendor(t *testing.T) {
	want := map[string]struct{ scope, capability, vendor string }{
		"subdomain":  {"domain", "subdomain", "projectdiscovery"},
		"dns":        {"domain", "dns", "projectdiscovery"},
		"port":       {"network", "portscan", "projectdiscovery"},
		"http_probe": {"domain", "http_probe", "projectdiscovery"},
		"url_crawl":  {"domain", "crawler", "projectdiscovery"},
		"mixed":      {"domain", "easm", ""},
	}
	for name, in := range reconFixtures() {
		r, err := ConvertReconToCTIS(in, nil)
		if err != nil {
			t.Fatal(err)
		}
		w := want[name]
		if r.Metadata.Scope.Type != w.scope || r.Tool.Capabilities[0] != w.capability || r.Tool.Vendor != w.vendor {
			t.Errorf("%s: scope %q capability %v vendor %q, want %+v", name, r.Metadata.Scope.Type, r.Tool.Capabilities, r.Tool.Vendor, w)
		}
	}
}

func TestReconSubdomains(t *testing.T) {
	r, _ := ConvertReconToCTIS(reconFixtures()["subdomain"], nil)
	if len(r.Assets) != 3 {
		t.Fatalf("want 3 assets (duplicate and empty dropped), got %d", len(r.Assets))
	}
	if r.Assets[0].Type != AssetTypeDomain || r.Assets[1].Type != AssetTypeSubdomain {
		t.Errorf("types %s %s", r.Assets[0].Type, r.Assets[1].Type)
	}
	recs := r.Assets[1].Technical.Domain.DNSRecords
	if len(recs) != 2 || recs[0].Type != "A" || recs[1].Type != "AAAA" {
		t.Errorf("resolved IPs as records: %+v", recs)
	}
	if r.Assets[1].ID == r.Assets[2].ID {
		t.Errorf("colliding asset ids: %s", r.Assets[1].ID)
	}
}

func TestReconDNS(t *testing.T) {
	r, _ := ConvertReconToCTIS(reconFixtures()["dns"], nil)
	if len(r.Assets) != 2 || r.Assets[0].Value != "example.com" {
		t.Fatalf("assets: %+v", r.Assets)
	}
	d := r.Assets[0].Technical.Domain
	var a []string
	for _, rec := range d.DNSRecords {
		if rec.Type == "A" {
			a = append(a, rec.Value)
		}
	}
	if strings.Join(a, ",") != "1.1.1.1,2.2.2.2" {
		t.Errorf("A records must be upper-cased and split per value: %+v", d.DNSRecords)
	}
	if len(d.Nameservers) != 1 || d.Nameservers[0] != "ns1.example.net" {
		t.Errorf("nameservers %v", d.Nameservers)
	}
	if _, ok := r.Assets[0].Properties["other_dns_records"]; !ok {
		t.Error("HINFO must be kept in other_dns_records")
	}
	mx := r.Assets[1].Technical.Domain.DNSRecords
	if len(mx) != 1 || mx[0].TTL != 0 {
		t.Errorf("mx: %+v", mx)
	}
}

func TestReconPorts(t *testing.T) {
	r, _ := ConvertReconToCTIS(reconFixtures()["port"], nil)
	by := assetsByValue(r)
	ip := by["10.0.0.1"]
	if ip.Type != AssetTypeIPAddress || ip.Technical.IPAddress.Version != 4 || ip.Technical.IPAddress.Hostname != "web.internal" {
		t.Errorf("ip asset: %+v %+v", ip, ip.Technical.IPAddress)
	}
	if p := ip.Technical.IPAddress.Ports; len(p) != 2 || p[0].Protocol != "tcp" {
		t.Errorf("ports %+v", p)
	}
	host := by["example.com"]
	if host.Type != AssetTypeHost || host.Technical.IPAddress.Version != 0 || host.Technical.IPAddress.Hostname != "example.com" {
		t.Errorf("a hostname must be a host asset without an IP version: %+v %+v", host, host.Technical.IPAddress)
	}
	v6 := by["2001:db8::1"]
	if v6.Technical.IPAddress.Version != 6 || v6.Technical.IPAddress.Ports[0].Protocol != "" {
		t.Errorf("v6: %+v", v6.Technical.IPAddress)
	}
	if _, ok := by["10.0.0.2"]; ok {
		t.Error("port 0 must be dropped")
	}

	opts := DefaultReconConverterOptions()
	opts.GroupByIP = false
	r, _ = ConvertReconToCTIS(reconFixtures()["port"], opts)
	by = assetsByValue(r)
	if _, ok := by["[2001:db8::1]:8443"]; !ok {
		t.Errorf("IPv6 host:port must be bracketed: %v", by)
	}
}

func TestReconHTTPProbeTypeDoesNotDependOnStatus(t *testing.T) {
	r, _ := ConvertReconToCTIS(reconFixtures()["http_probe"], nil)
	for _, a := range r.Assets {
		if a.Type != AssetTypeHTTPService {
			t.Errorf("%s: type %s, want http_service for every status", a.Value, a.Type)
		}
	}
	if svc := r.Assets[0].Technical.Service; !svc.TLS || svc.Port != 443 || svc.Transport != "tcp" {
		t.Errorf("service: %+v", svc)
	}
}

func TestReconURLs(t *testing.T) {
	r, _ := ConvertReconToCTIS(reconFixtures()["url_crawl"], nil)
	if len(r.Assets) != 2 || r.Assets[0].Properties["host"] != "example.com" {
		t.Fatalf("assets %+v", r.Assets)
	}
	if n := len(r.Assets[1].Name); n != 255 || !strings.HasSuffix(r.Assets[1].Name, "...") {
		t.Errorf("long URL name must be truncated to 255, got %d", n)
	}
}

func TestReconNilAndOptions(t *testing.T) {
	if _, err := ConvertReconToCTIS(nil, nil); err == nil {
		t.Error("nil input must fail")
	}
	opts := &ReconConverterOptions{DefaultCriticality: CriticalityLow, GroupByIP: true}
	if _, err := ConvertReconToCTIS(reconFixtures()["port"], opts); err != nil {
		t.Fatal(err)
	}
	if opts.DiscoveryTool != "" {
		t.Error("the converter must not write to the caller's options")
	}
	r, _ := ConvertReconToCTIS(&ReconToCTISInput{ScannerName: "x", DurationMs: -1}, nil)
	if r.Metadata.DurationMs != 0 {
		t.Error("negative duration must clamp to 0")
	}
}

func TestMergeReconReports(t *testing.T) {
	if MergeReconReports(nil) != nil {
		t.Error("no reports, no result")
	}
	fx := reconFixtures()
	sub, _ := ConvertReconToCTIS(fx["subdomain"], nil)
	dns, _ := ConvertReconToCTIS(fx["dns"], nil)
	port, _ := ConvertReconToCTIS(fx["port"], nil)
	before, _ := json.Marshal([]*Report{sub, dns, port})

	m := MergeReconReports([]*Report{sub, nil, dns, port})
	after, _ := json.Marshal([]*Report{sub, dns, port})
	if string(before) != string(after) {
		t.Error("MergeReconReports modified its input")
	}

	// example.com is in the subdomain and the dns report (and the port
	// report as a host): one asset, records combined.
	by := assetsByValue(m)
	ex := by["example.com"]
	if ex.Technical.Domain == nil || len(ex.Technical.Domain.DNSRecords) < 3 {
		t.Errorf("records not merged: %+v", ex.Technical.Domain)
	}
	if ex.Technical.IPAddress == nil || len(ex.Technical.IPAddress.Ports) != 1 {
		t.Errorf("ports not merged: %+v", ex.Technical.IPAddress)
	}
	if m.Assets[0].Value != sub.Assets[0].Value {
		t.Error("merged assets must keep first-seen order")
	}
	wantCaps := []string{"subdomain", "dns", "portscan"}
	if !reflect.DeepEqual(m.Tool.Capabilities, wantCaps) {
		t.Errorf("capabilities %v, want %v", m.Tool.Capabilities, wantCaps)
	}
	if tools := m.Properties["tools_used"].([]string); len(tools) != 3 {
		t.Errorf("tools_used %v", tools)
	}
	if m.Metadata.DurationMs != 1200 {
		t.Errorf("duration %d", m.Metadata.DurationMs)
	}

	// Deterministic: same input, same asset order.
	for i := 0; i < 20; i++ {
		again := MergeReconReports([]*Report{sub, dns, port})
		for j := range again.Assets {
			if again.Assets[j].Value != m.Assets[j].Value || again.Assets[j].ID != m.Assets[j].ID {
				t.Fatalf("order differs at %d", j)
			}
		}
	}

	// A single report still yields a new report.
	single := MergeReconReports([]*Report{sub})
	if single == sub || len(single.Assets) != len(sub.Assets) {
		t.Error("single report must be copied, not aliased")
	}
}

func TestReconHelpers(t *testing.T) {
	cases := map[string]string{
		"Sub.Example.COM": "sub-example-com",
		"--a//b--":        "a-b",
		"":                "",
	}
	for in, want := range cases {
		if got := normalizeAssetID(in); got != want {
			t.Errorf("normalizeAssetID(%q) = %q, want %q", in, got, want)
		}
	}
	if got := len(normalizeAssetID(strings.Repeat("x", 300))); got != 100 {
		t.Errorf("normalizeAssetID length %d", got)
	}
	// Regression for the truncateString panic fixed in 3b9671e.
	for _, n := range []int{-1, 0, 1, 2, 3, 4} {
		got := truncateString("abcdefgh", n)
		if n <= 0 && got != "" || n > 0 && len(got) != n {
			t.Errorf("truncateString(_, %d) = %q", n, got)
		}
	}
	if truncateString("ab", 10) != "ab" {
		t.Error("short strings are unchanged")
	}
}
