package ctis

import (
	"errors"
	"sort"
	"strings"
	"testing"
	"time"
)

const httpxSample = `{"url":"https://www.example.com:443/login?next=/a","input":"www.example.com","host":"192.0.2.10","host_ip":"192.0.2.10","port":"443","scheme":"https","status_code":200,"content_length":1234,"title":" Example\tShop ","webserver":"nginx","content_type":"text/html","tech":["Nginx","HSTS"],"cdn":true,"cdn_name":"cloudflare","cdn_type":"waf","time":"123.4ms","location":"https://www.example.com/en?session=abc","favicon":"-1234567890","jarm":"07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1","header":{"set_cookie":"sid=abc"},"body_preview":"secret","tls":{"tls_version":"tls13","subject_cn":"www.example.com","subject_an":["www.example.com"],"issuer_cn":"CA","issuer_org":["Org"],"fingerprint_hash":{"sha256":"` + "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1" + `"},"not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","wildcard_certificate":true},"asn":{"as_number":"AS64496","as_name":"EXAMPLE-AS","as_country":"US"}}`

func TestParseHTTPXLine(t *testing.T) {
	var seen []string
	h, err := ParseHTTPXLine([]byte(httpxSample), func(p string) { seen = append(seen, p) })
	if err != nil {
		t.Fatal(err)
	}
	if h.URL != "https://www.example.com/login" || h.Host != "www.example.com" || h.Scheme != "https" || h.Port != 443 {
		t.Errorf("url fields: %+v", h)
	}
	if h.IP != "192.0.2.10" || h.StatusCode != 200 || h.ContentLength != 1234 || h.Title != "Example Shop" || h.WebServer != "nginx" {
		t.Errorf("fields: %+v", h)
	}
	if h.CDN != "cloudflare" || h.CDNType != "waf" || h.ResponseTime != 123 || h.Redirect != "https://www.example.com/en" {
		t.Errorf("cdn, time or redirect: %+v", h)
	}
	if len(h.Technologies) != 2 || h.TLSVersion != "tls13" || h.TLS == nil || !h.TLS.Wildcard || h.TLS.IssuerOrg != "Org" || h.ASN == nil || h.ASN.Number != "AS64496" {
		t.Errorf("tech, tls or asn: %+v", h)
	}
	sort.Strings(seen)
	for _, want := range []string{"/url", "/header", "/body_preview", "/tls/fingerprint_hash", "/tls/subject_cn", "/asn/as_name"} {
		i := sort.SearchStrings(seen, want)
		if i == len(seen) || seen[i] != want {
			t.Errorf("%s was not observed: %v", want, seen)
		}
	}
	for _, p := range seen {
		if strings.HasPrefix(p, "/header/") {
			t.Errorf("header members must not be observed one by one: %s", p)
		}
	}
	// The same line becomes an http_service asset through the converter.
	rep, err := ConvertReconToCTIS(&ReconToCTISInput{ScannerName: "httpx", ReconType: "http_probe", LiveHosts: []LiveHostInput{h}}, nil)
	if err != nil || len(rep.Assets) != 2 {
		t.Fatalf("convert: %v, %d assets", err, len(rep.Assets))
	}
}

func TestParseHTTPXLine_Hostile(t *testing.T) {
	deep := `{"url":"https://a.example.com","x":` + strings.Repeat("[", 100) + strings.Repeat("]", 100) + `}`
	for name, line := range map[string]string{
		"empty":        "",
		"not object":   `["https://a.example.com"]`,
		"not json":     `{"url":`,
		"no url":       `{"title":"x"}`,
		"javascript":   `{"url":"javascript:alert(1)"}`,
		"data":         `{"url":"data:text/html,x"}`,
		"user info":    `{"url":"https://u:p@a.example.com/"}`,
		"crlf":         "{\"url\":\"https://a.example.com/\\r\\nHost: x\"}",
		"nul":          "{\"url\":\"https://a.example.com/\\u0000\"}",
		"raw nul":      "{\"url\":\"https://a.example.com/\x00\"}",
		"failed":       `{"url":"https://a.example.com","failed":true}`,
		"wrong type":   `{"url":"https://a.example.com","status_code":"200"}`,
		"deep":         deep,
		"huge":         `{"url":"https://a.example.com/` + strings.Repeat("a", MaxHTTPXLineBytes) + `"}`,
		"scheme":       `{"url":"ftp://a.example.com/"}`,
		"bad host":     `{"url":"https://exa mple.com/"}`,
		"long url":     `{"url":"https://a.example.com/` + strings.Repeat("a", 5000) + `"}`,
		"unicode ctrl": "{\"url\":\"https://a.example.com/\\u202e\"}",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseHTTPXLine([]byte(line), nil)
			if !errors.Is(err, ErrHTTPXLine) {
				t.Fatalf("err %v, want ErrHTTPXLine", err)
			}
		})
	}
}

func TestParseHTTPXLine_Bounds(t *testing.T) {
	line := `{"url":"https://a.example.com","status_code":99999,"content_length":-5,"title":"` + strings.Repeat("t", 4000) + `","tls":{"fingerprint_hash":{"sha256":"zz"}},"asn":{"as_number":"x"},"favicon":"zz","time":"-1s","location":"javascript:x"}`
	h, err := ParseHTTPXLine([]byte(line), nil)
	if err != nil {
		t.Fatal(err)
	}
	if h.StatusCode != 0 || h.ContentLength != 0 || len(h.Title) > 600 || h.TLS != nil || h.ResponseTime != 0 || h.Redirect != "" {
		t.Errorf("values were not bounded: %+v", h)
	}
}

func TestEndpointSourceImport(t *testing.T) {
	if !validEnum(EndpointSourceImport, AllEndpointSources()) {
		t.Fatal("import is not an endpoint source")
	}
	eps := ConvertEndpoints([]DiscoveredURLInput{
		{URL: "https://a.example.com/p?x=1&y=2", Source: "import"},
		{URL: "javascript:alert(1)", Source: "import"},
		{URL: "https://a.example.com/s.js", Source: "js"},
	})
	if len(eps) != 2 || eps[0].Source != EndpointSourceImport || eps[1].Source != EndpointSourceJS {
		t.Fatalf("endpoints %+v", eps)
	}
	r := &Report{Version: SchemaVersion, Metadata: ReportMetadata{Timestamp: time.Unix(1700000000, 0).UTC()}, Endpoints: eps}
	if err := r.Validate(); err != nil {
		t.Fatalf("an import endpoint does not validate: %v", err)
	}
}

func FuzzParseHTTPXLine(f *testing.F) {
	f.Add([]byte(httpxSample))
	f.Add([]byte(`{"url":"https://a.example.com","failed":false}`))
	f.Add([]byte(`{"url":"javascript:alert(1)"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := ParseHTTPXLine(data, func(string) {})
		if err != nil {
			if !errors.Is(err, ErrHTTPXLine) {
				t.Fatalf("error does not wrap ErrHTTPXLine: %v", err)
			}
			return
		}
		rep, err := ConvertReconToCTIS(&ReconToCTISInput{ScannerName: "httpx", ReconType: "http_probe", LiveHosts: []LiveHostInput{h}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := rep.Validate(); err != nil {
			t.Fatalf("a mapped line gives an invalid report: %v", err)
		}
	})
}
