package ctis

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReconCrawlEndpoints(t *testing.T) {
	in := &ReconToCTISInput{ScannerName: "katana", ReconType: "url_crawl", Target: "https://shop.example.com",
		URLs: []DiscoveredURLInput{
			{URL: "https://shop.example.com/products/42?ref=s3cr3t-ref&utm=x", Method: "GET", Source: "href", StatusCode: 200,
				Parent: "https://u:pw@shop.example.com/?sid=s3cr3t-sid#frag", ContentType: "text/html"},
			{URL: "https://shop.example.com/products/43?page=2", Source: "href"},
			{URL: "https://shop.example.com/app.js", Source: "script"},
			{URL: "https://shop.example.com/robots-listed", Source: "robotstxt"},
			{URL: "https://shop.example.com/sitemap-page", Source: "sitemapxml"},
			{URL: "https://shop.example.com/old", Source: "wayback"},
			{URL: "https://shop.example.com/logo.png", Source: "href"},
			{URL: "https://shop.example.com/cart", Method: "post", Type: "form",
				Params: []EndpointParam{{Location: ParamLocationForm, Name: "qty"}, {Location: "bogus", Name: "x"}, {Location: ParamLocationForm, Name: ""}}},
			{URL: "https://shop.example.com/cart", Method: "BREW"},
			{URL: "ftp://shop.example.com/file"},
			{URL: "https://0x7f.1/"},
		}}
	r, err := ConvertReconToCTIS(in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	assertReportValid(t, loadSchemaSet(t), r)
	raw, _ := json.Marshal(r)
	for _, secret := range []string{"s3cr3t", "pw@", "frag", "page=2", "utm=x"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("%q is in the output", secret)
		}
	}
	by := map[string]Endpoint{}
	for _, e := range r.Endpoints {
		by[e.Method+" "+e.Template] = e
	}
	if len(r.Endpoints) != 7 {
		t.Fatalf("endpoints: %+v", r.Endpoints)
	}
	p := by["GET /products/{int}"]
	if p.Path != "/products/42" || p.Kind != EndpointKindPage || p.Source != EndpointSourceCrawl ||
		p.StatusCode != 200 || p.ContentType != "text/html" || p.Parent != "https://shop.example.com/?sid=" {
		t.Errorf("products: %+v", p)
	}
	var names []string
	for _, x := range p.Params {
		names = append(names, string(x.Location)+":"+x.Name)
	}
	if strings.Join(names, ",") != "query:ref,query:utm,query:page" {
		t.Errorf("params %v", names)
	}
	for tmpl, want := range map[string]EndpointKind{"GET /app.js": EndpointKindScript, "GET /logo.png": EndpointKindStatic, "POST /cart": EndpointKindForm} {
		if by[tmpl].Kind != want {
			t.Errorf("%s kind %q", tmpl, by[tmpl].Kind)
		}
	}
	for tmpl, want := range map[string]EndpointSource{"GET /app.js": EndpointSourceJS, "GET /robots-listed": EndpointSourceRobots,
		"GET /sitemap-page": EndpointSourceSitemap, "GET /old": EndpointSourceArchive} {
		if by[tmpl].Source != want {
			t.Errorf("%s source %q", tmpl, by[tmpl].Source)
		}
	}
	if c := by["POST /cart"]; len(c.Params) != 1 || c.Params[0].Name != "qty" {
		t.Errorf("cart params %+v", c.Params)
	}
	// Legacy assets stay, redacted.
	if _, ok := assetsByValue(r)["https://shop.example.com/products/42?ref=&utm="]; !ok {
		t.Errorf("legacy asset: %v", keys(assetsByValue(r)))
	}

	// Merging two crawls combines endpoints by origin, method and template.
	in2 := &ReconToCTISInput{ScannerName: "katana", ReconType: "url_crawl",
		URLs: []DiscoveredURLInput{{URL: "https://shop.example.com/products/7?sort=asc"}, {URL: "https://shop.example.com/new"}}}
	r2, _ := ConvertReconToCTIS(in2, nil)
	m := MergeReconReports([]*Report{r, r2})
	if len(m.Endpoints) != 8 {
		t.Fatalf("merged endpoints %d", len(m.Endpoints))
	}
	if n := len(m.Endpoints[0].Params); n != 4 {
		t.Errorf("merged params %d", n)
	}
	if len(r.Endpoints[0].Params) != 3 {
		t.Error("merge modified its input")
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
}
