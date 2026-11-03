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
		r, err := ConvertReconToCTIS(in, DefaultReconConverterOptions())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		assertReportValid(t, s, r)
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if r.Version != SchemaVersion || r.Schema != SchemaURL {
			t.Errorf("%s: version %q schema %q", name, r.Version, r.Schema)
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

func TestReconTechniqueVendor(t *testing.T) {
	for name, in := range reconFixtures() {
		r, err := ConvertReconToCTIS(in, nil)
		if err != nil {
			t.Fatal(err)
		}
		wantVendor := "projectdiscovery"
		if name == "mixed" {
			wantVendor = ""
		}
		if !reflect.DeepEqual(r.Tool.Techniques, []Technique{TechniqueEASM}) || r.Tool.Vendor != wantVendor {
			t.Errorf("%s: techniques %v vendor %q", name, r.Tool.Techniques, r.Tool.Vendor)
		}
		if r.Metadata.Channel != ChannelScanner || !IsReportID(r.Metadata.ID) {
			t.Errorf("%s: metadata %+v", name, r.Metadata)
		}
	}
}

func TestReconSubdomains(t *testing.T) {
	r, _ := ConvertReconToCTIS(reconFixtures()["subdomain"], nil)
	if len(r.Assets) != 3 {
		t.Fatalf("want 3 assets (duplicate and empty dropped), got %d", len(r.Assets))
	}
	for _, a := range r.Assets {
		if a.Type != AssetTypeDomainName {
			t.Errorf("%s: type %s", a.Value, a.Type)
		}
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
	hinfo := false
	for _, rec := range d.DNSRecords {
		switch rec.Type {
		case "A":
			a = append(a, rec.Value)
		case "HINFO":
			hinfo = true
		}
	}
	if strings.Join(a, ",") != "1.1.1.1,2.2.2.2" {
		t.Errorf("A records must be upper-cased and split per value: %+v", d.DNSRecords)
	}
	if !hinfo {
		t.Error("every RR type is kept verbatim")
	}
	if len(d.Nameservers) != 1 || d.Nameservers[0] != "ns1.example.net" {
		t.Errorf("nameservers %v", d.Nameservers)
	}
	mx := r.Assets[1].Technical.Domain.DNSRecords
	if len(mx) != 1 || mx[0].TTL != 0 {
		t.Errorf("mx: %+v", mx)
	}
}

func relationshipsOf(r *Report, typ RelationshipType) map[string]string {
	idValue := map[string]string{}
	for _, a := range r.Assets {
		idValue[a.ID] = a.Value
	}
	out := map[string]string{}
	for _, rel := range r.Relationships {
		if rel.Type == typ {
			out[idValue[rel.ToRef]] = idValue[rel.FromRef]
		}
	}
	return out
}

func TestReconPorts(t *testing.T) {
	r, _ := ConvertReconToCTIS(reconFixtures()["port"], nil)
	by := assetsByValue(r)
	ip := by["10.0.0.1"]
	if ip.Type != AssetTypeIPAddress || ip.Technical.IPAddress.Version != 4 || ip.Technical.IPAddress.Hostname != "web.internal" {
		t.Errorf("ip asset: %+v %+v", ip, ip.Technical.IPAddress)
	}
	https := by["10.0.0.1:443/tcp"]
	if https.Type != AssetTypeService || https.Technical.Service.AppProtocol != "https" || https.Technical.Service.Transport != TransportTCP || https.Technical.Service.State != PortOpen {
		t.Errorf("service: %+v", https.Technical)
	}
	if _, ok := by["10.0.0.1:22/tcp"]; !ok {
		t.Error("ssh service missing")
	}
	host := by["example.com"]
	if host.Type != AssetTypeHost {
		t.Errorf("a hostname must be a host asset: %+v", host)
	}
	if _, ok := by["example.com:80/tcp"]; !ok {
		t.Error("a port without a protocol is tcp")
	}
	if _, ok := by["[2001:db8::1]:8443/sctp"]; !ok {
		t.Errorf("IPv6 service must be bracketed: %v", keys(by))
	}
	if _, ok := by["10.0.0.2"]; ok {
		t.Error("port 0 must be dropped")
	}
	exposes := relationshipsOf(r, RelExposes)
	for svc, h := range map[string]string{"10.0.0.1:443/tcp": "10.0.0.1", "10.0.0.1:22/tcp": "10.0.0.1", "example.com:80/tcp": "example.com", "[2001:db8::1]:8443/sctp": "2001:db8::1"} {
		if exposes[svc] != h {
			t.Errorf("%s exposed by %q, want %q", svc, exposes[svc], h)
		}
	}
}

func TestReconHTTPProbe(t *testing.T) {
	r, _ := ConvertReconToCTIS(reconFixtures()["http_probe"], nil)
	by := assetsByValue(r)
	ex := by["https://example.com"]
	if ex.Type != AssetTypeWebOrigin || ex.Technical.HTTP.StatusCode != 200 || ex.Technical.HTTP.Title != "Example" || ex.Technical.HTTP.TLSVersion != TLSVersionTLS13 {
		t.Errorf("origin: %+v", ex.Technical)
	}
	if len(ex.Technologies) != 1 || ex.Technologies[0].Name != "nginx" {
		t.Errorf("technologies: %+v", ex.Technologies)
	}
	admin := by["http://admin.example.com"]
	if admin.Type != AssetTypeWebOrigin || admin.Technical.HTTP.StatusCode != 503 || admin.Technical.HTTP.CDN != "cloudflare" || admin.Technical.HTTP.RedirectURL != "https://admin.example.com/login" {
		t.Errorf("an origin is a web_origin whatever its status: %+v", admin.Technical.HTTP)
	}
	if relationshipsOf(r, RelResolvesTo)["93.184.216.34"] != "example.com" {
		t.Errorf("resolves_to: %+v", r.Relationships)
	}
}

func TestReconURLs(t *testing.T) {
	r, _ := ConvertReconToCTIS(reconFixtures()["url_crawl"], nil)
	if len(r.Assets) != 1 || r.Assets[0].Type != AssetTypeWebOrigin || r.Assets[0].Value != "https://example.com" {
		t.Fatalf("assets %+v", r.Assets)
	}
	if len(r.Endpoints) != 2 || r.Endpoints[0].OriginRef != r.Assets[0].ID {
		t.Fatalf("endpoints %+v", r.Endpoints)
	}
}

func TestReconNilAndOptions(t *testing.T) {
	if _, err := ConvertReconToCTIS(nil, nil); err == nil {
		t.Error("nil input must fail")
	}
	opts := &ReconConverterOptions{DefaultCriticality: CriticalityLow}
	if _, err := ConvertReconToCTIS(reconFixtures()["port"], opts); err != nil {
		t.Fatal(err)
	}
	if opts.DiscoveryTool != "" {
		t.Error("the converter must not write to the caller's options")
	}
	r, _ := ConvertReconToCTIS(&ReconToCTISInput{ScannerName: "x", DurationMs: -1, StartedAt: 1700000000, FinishedAt: 1700000060}, nil)
	if r.Metadata.DurationMs != 0 {
		t.Error("negative duration must clamp to 0")
	}
	if r.Metadata.StartedAt == nil || r.Metadata.EndedAt == nil || r.Metadata.EndedAt.Sub(*r.Metadata.StartedAt).Seconds() != 60 {
		t.Errorf("started/ended: %v %v", r.Metadata.StartedAt, r.Metadata.EndedAt)
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
	probe, _ := ConvertReconToCTIS(fx["http_probe"], nil)
	before, _ := json.Marshal([]*Report{sub, dns, port, probe})

	m := MergeReconReports([]*Report{sub, nil, dns, port, probe})
	after, _ := json.Marshal([]*Report{sub, dns, port, probe})
	if string(before) != string(after) {
		t.Error("MergeReconReports modified its input")
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}

	// example.com is a domain_name in the subdomain, dns and probe reports:
	// one asset, records combined. The port report's host example.com is
	// another type, so another asset.
	n := 0
	for _, a := range m.Assets {
		if a.Value == "example.com" {
			n++
			if a.Type == AssetTypeDomainName && len(a.Technical.Domain.DNSRecords) < 3 {
				t.Errorf("records not merged: %+v", a.Technical.Domain)
			}
		}
	}
	if n != 2 {
		t.Errorf("example.com assets: %d, want domain_name and host", n)
	}
	if m.Assets[0].Value != sub.Assets[0].Value {
		t.Error("merged assets must keep first-seen order")
	}
	if !reflect.DeepEqual(m.Tool.Techniques, []Technique{TechniqueEASM}) {
		t.Errorf("techniques %v", m.Tool.Techniques)
	}
	if m.Metadata.DurationMs != 1200 {
		t.Errorf("duration %d", m.Metadata.DurationMs)
	}
	if len(relationshipsOf(m, RelExposes)) != 4 || relationshipsOf(m, RelResolvesTo)["93.184.216.34"] != "example.com" {
		t.Errorf("relationships not re-pointed: %+v", m.Relationships)
	}

	// Deterministic: same input, same asset order and ids.
	for i := 0; i < 20; i++ {
		again := MergeReconReports([]*Report{sub, dns, port, probe})
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
