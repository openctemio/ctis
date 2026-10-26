package ctis

import (
	"encoding/json"
	"strings"
	"testing"
)

func probeReport(t *testing.T, h LiveHostInput) *Report {
	t.Helper()
	r, err := ConvertReconToCTIS(&ReconToCTISInput{ScannerName: "httpx", ReconType: "http_probe", Target: "example.com", LiveHosts: []LiveHostInput{h}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	assertReportValid(t, loadSchemaSet(t), r)
	return r
}

func TestHTTPPostureAllowList(t *testing.T) {
	r := probeReport(t, LiveHostInput{URL: "https://example.com", Host: "example.com", Scheme: "https", StatusCode: 200,
		ResponseHeaders: &ResponseHeadersInput{
			Values: map[string]string{
				"Strict-Transport-Security": "max-age=63072000", "content-security-policy": "default-src 'self'",
				"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
				"Permissions-Policy": "camera=()", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true",
				"Server": "SECRET-server", "X-Api-Key": "SECRET-key", "Set-Cookie": "sid=SECRET-cookie", "Authorization": "SECRET-auth",
			},
			Cookies: []CookieFlagsInput{{Name: "sid", Secure: true, HTTPOnly: true, SameSite: "LAX"}, {Name: "a", Persistent: true, SameSite: "bogus"}},
		},
		CNAMEs: []string{"Edge.CDN.net.", "bad host"}})
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "SECRET") {
		t.Fatalf("a disallowed value reached the report: %s", raw)
	}
	props := r.Assets[0].Properties
	posture, ok := props[HTTPPostureProperty].(map[string]any)
	if !ok {
		t.Fatalf("no posture: %v", props)
	}
	for _, k := range PostureKeys() {
		if _, ok := posture[k]; !ok {
			t.Errorf("%s missing", k)
		}
	}
	if len(posture) != len(PostureKeys())+1 {
		t.Errorf("unexpected keys: %v", posture)
	}
	cookies := posture["cookies"].([]map[string]any)
	if len(cookies) != 2 || cookies[0]["name"] != "a" || cookies[1]["same_site"] != "lax" || cookies[1]["secure"] != true {
		t.Errorf("cookies %v", cookies)
	}
	if _, has := cookies[0]["same_site"]; has {
		t.Error("bogus same_site kept")
	}
	if cn := props["cnames"].([]string); len(cn) != 1 || cn[0] != "edge.cdn.net" {
		t.Errorf("cnames %v", props["cnames"])
	}
}

func TestHTTPPostureHostile(t *testing.T) {
	hostile := map[string]string{
		"crlf": "max-age=1\r\nSet-Cookie: x=y", "nul": "a\x00b", "bell": "a\x07", "bidi": "a\u202eb",
		"1MiB": strings.Repeat("a", 1<<20), "over": strings.Repeat("a", MaxPostureValueLen+1), "badutf8": "a\xff", "blank": "  ",
	}
	for name, v := range hostile {
		if p := httpPosture(&ResponseHeadersInput{Values: map[string]string{"Content-Security-Policy": v}}); p != nil {
			t.Errorf("%s passed: %v", name, p)
		}
	}
	var cookies []CookieFlagsInput
	for _, n := range []string{"", "a b", "a;b", "a=b", "n\r\n", "n\x00", "é", strings.Repeat("n", 129), "javascript:alert(1)"} {
		cookies = append(cookies, CookieFlagsInput{Name: n})
	}
	if p := httpPosture(&ResponseHeadersInput{Cookies: cookies}); p != nil {
		t.Errorf("hostile cookie names passed: %v", p)
	}
	var many []CookieFlagsInput
	for i := 0; i < 60; i++ {
		many = append(many, CookieFlagsInput{Name: "c" + strings.Repeat("x", i)})
	}
	if p := httpPosture(&ResponseHeadersInput{Cookies: many}); len(p["cookies"].([]map[string]any)) != MaxPostureCookies {
		t.Error("cookie cap")
	}
	if httpPosture(nil) != nil || httpPosture(&ResponseHeadersInput{}) != nil {
		t.Error("empty posture must be nil")
	}
	var longChain []string
	for i := 0; i < 20; i++ {
		longChain = append(longChain, "h.example.com")
	}
	if n := len(boundCNAMEs(longChain)); n != maxCNAMEs {
		t.Errorf("cname cap %d", n)
	}
	if got := boundCNAMEs([]string{"a\r\nb.com", "x..y", ".x", "javascript:1", strings.Repeat("a", 254), ""}); len(got) != 0 {
		t.Errorf("hostile cnames: %v", got)
	}
}

func TestNoPostureWithoutHeaders(t *testing.T) {
	r := probeReport(t, LiveHostInput{URL: "https://example.com", Host: "example.com", Scheme: "https"})
	if _, ok := r.Assets[0].Properties[HTTPPostureProperty]; ok {
		t.Error("posture set without headers")
	}
	if _, ok := r.Assets[0].Properties["cnames"]; ok {
		t.Error("cnames set without data")
	}
}

func TestCrawlFormEndpoints(t *testing.T) {
	in := &ReconToCTISInput{ScannerName: "katana", ReconType: "url_crawl", Target: "https://app.example.com",
		URLs: []DiscoveredURLInput{
			{URL: "https://app.example.com/login?next=/a", Source: "href", ContentType: "text/html", Forms: []WebFormInput{
				{Method: "post", Action: "https://app.example.com/session?csrf=SECRET#f", Params: []EndpointParam{
					{Location: ParamLocationForm, Name: "email"}, {Location: ParamLocationForm, Name: "Password"},
					{Location: ParamLocationForm, Name: "pin", TypeHint: TypeHintPassword}, {Location: ParamLocationQuery, Name: "ignored"},
					{Location: ParamLocationForm, Name: "a\r\nb"}}},
				{Method: "GET", Params: []EndpointParam{{Location: ParamLocationForm, Name: "q"}}},
				{Method: "TRACE", Action: "javascript:alert(1)", Params: []EndpointParam{{Location: ParamLocationForm, Name: "z"}}},
			}},
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
	if strings.Contains(string(raw), "SECRET") {
		t.Errorf("form action query leaked: %s", raw)
	}
	by := map[string]Endpoint{}
	for _, e := range r.Endpoints {
		by[e.Method+" "+e.Template] = e
	}
	login := by["POST /session"]
	if login.Kind != EndpointKindForm || login.Parent != "https://app.example.com/login" {
		t.Fatalf("login form: %+v", login)
	}
	hint := map[string]string{}
	for _, p := range login.Params {
		if p.Location != ParamLocationForm {
			t.Errorf("param %+v", p)
		}
		hint[p.Name] = p.TypeHint
	}
	if len(hint) != 3 || hint["Password"] != TypeHintPassword || hint["pin"] != TypeHintPassword || hint["email"] != "" {
		t.Errorf("hints %v", hint)
	}
	page := by["GET /login"]
	var got []string
	for _, p := range page.Params {
		got = append(got, string(p.Location)+":"+p.Name)
	}
	// The page keeps its query parameter; the GET form and the form whose
	// action was javascript: (method TRACE, so GET) both land on the page.
	if page.Kind != EndpointKindForm || strings.Join(got, ",") != "query:next,form:q,form:z" {
		t.Errorf("page endpoint: %+v %v", page, got)
	}
}

func TestCrawlFormCaps(t *testing.T) {
	var params []EndpointParam
	for i := 0; i < 300; i++ {
		params = append(params, EndpointParam{Location: ParamLocationForm, Name: "p" + strings.Repeat("x", i)})
	}
	in := &ReconToCTISInput{ScannerName: "katana", ReconType: "url_crawl", Target: "https://a.example.com",
		URLs: []DiscoveredURLInput{{URL: "https://a.example.com/f", Forms: []WebFormInput{{Method: "POST", Params: params}}}}}
	r, err := ConvertReconToCTIS(in, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range r.Endpoints {
		if len(e.Params) > MaxEndpointParams {
			t.Errorf("%d params", len(e.Params))
		}
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestCrawlFormToOtherOriginSkipped(t *testing.T) {
	in := &ReconToCTISInput{ScannerName: "katana", ReconType: "url_crawl", Target: "https://a.example.com",
		URLs: []DiscoveredURLInput{{URL: "https://a.example.com/f", Forms: []WebFormInput{
			{Method: "POST", Action: "https://evil.example.net/collect", Params: []EndpointParam{{Location: ParamLocationForm, Name: "x"}}}}}}}
	r, err := ConvertReconToCTIS(in, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range r.Endpoints {
		if strings.Contains(e.Origin, "evil") {
			t.Errorf("endpoint on the other origin: %+v", e)
		}
	}
}
