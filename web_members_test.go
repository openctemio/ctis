package ctis

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func intp(n int) *int { return &n }

func webReport() *Report {
	at := time.Date(2026, 10, 7, 9, 59, 3, 0, time.UTC)
	return &Report{
		Version:  SchemaVersion,
		Metadata: ReportMetadata{Timestamp: at},
		Assets:   []Asset{{ID: "origin-1", Type: AssetTypeHTTPService, Value: "https://api.example.com"}},
		Endpoints: []Endpoint{{
			ID: "ep-1", Origin: "https://api.example.com", OriginRef: "origin-1", Method: "POST",
			Path: "/api/v1/orders/42", Template: "/api/v1/orders/{int}", Kind: EndpointKindAPI, Source: EndpointSourceCrawl,
			Parent: "https://api.example.com/app", StatusCode: 200, ContentType: "application/json", Auth: EndpointAuthRequired,
			Technologies: []Technology{{Name: "nginx"}},
			Params:       []EndpointParam{{Location: ParamLocationJSON, Name: "/note", TypeHint: "string"}, {Location: ParamLocationQuery, Name: "page"}},
		}},
		Findings: []Finding{{
			Type: FindingTypeVulnerability, Title: "Stored XSS", Severity: SeverityHigh, AssetRef: "origin-1",
			Web: &WebLocation{URL: "https://api.example.com/api/v1/orders/42", Method: "POST", EndpointRef: "ep-1",
				Parameter: &WebParameter{Location: ParamLocationJSON, Name: "/note"}, StatusCode: 500},
			EvidenceItems: []EvidenceItem{
				{Kind: EvidenceKindHTTPExchange, Version: 1, Label: "xss probe", CapturedAt: &at,
					ContentSHA256: "sha256:" + strings.Repeat("a", 64),
					HTTP: &EvidenceHTTP{
						Request: &EvidenceRequest{Method: "POST", URL: "https://api.example.com/api/v1/orders/42?token=abc", HTTPVersion: "HTTP/1.1",
							Headers: []EvidenceHeader{{Name: "Host", Value: "api.example.com"}, {Name: "Authorization", Value: "Bearer s3cr3t-session-token"}},
							Body:    `{"note":"<script>"}`, BodyEncoding: BodyEncodingText, BodySize: 19},
						Response: &EvidenceResponse{Status: 500, Reason: "Internal Server Error", HTTPVersion: "HTTP/1.1", Body: "<script>", TimeMs: 87}},
					Match:     []EvidenceMatch{{Location: MatchLocationResponse, Part: MatchPartBody, Start: intp(0), End: intp(8), Matcher: "word-1"}},
					Extracted: []string{"7.1.0"},
					Sensitive: []SensitiveSpan{{Pointer: "/http/request/headers/1/value", Start: intp(7), End: intp(27), Kind: "authorization"}}},
				{Kind: EvidenceKindCurl, Text: "curl -X POST https://api.example.com/api/v1/orders/42"},
				{Kind: EvidenceKindRawText, Text: "SSH-2.0-OpenSSH_9.6", Protocol: "ssh"},
				{Kind: EvidenceKindCommandOutput, Command: "openssl s_client -connect a:443", ExitCode: intp(0), Text: "CONNECTED"},
				{Kind: EvidenceKindFileExcerpt, File: &EvidenceFile{Path: "src/a.go", StartLine: 10, EndLine: 12, Snippet: "x := 1"}},
				{Kind: EvidenceKindScreenshot, Artifact: &EvidenceArtifact{MediaType: "image/png", SHA256: "sha256:" + strings.Repeat("b", 64), Size: 1234, Ref: "attachment:9"}},
				// A kind this version does not know: kept, envelope only.
				{Kind: "dns_trace", Version: 1, Data: map[string]any{"answers": []any{"192.0.2.1"}}},
			},
		}},
	}
}

func TestWebMembersRoundTrip(t *testing.T) {
	r := webReport()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	back, err := decodeStrict(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, _ := json.Marshal(back)
	if string(raw) != string(raw2) {
		t.Fatalf("round trip changed the report:\n%s\n%s", raw, raw2)
	}
	if errs := loadSchemaSet(t).validateJSON(raw, "report.json"); len(errs) > 0 {
		t.Fatalf("schema rejects a valid 1.6 report: %v", errs)
	}
}

// A parameter never carries a value: a strict receiver refuses one.
func TestEndpointParamValueRefused(t *testing.T) {
	raw := []byte(`{"version":"1.6","metadata":{"timestamp":"2026-10-07T00:00:00Z"},"endpoints":[{"origin":"https://a.example","path":"/x","params":[{"location":"query","name":"token","value":"s3cr3t"}]}]}`)
	if _, err := decodeStrict(raw); err == nil {
		t.Fatal("a parameter value was accepted")
	}
	if errs := loadSchemaSet(t).validateJSON(raw, "report.json"); len(errs) == 0 {
		t.Fatal("the schema accepted a parameter value")
	}
}

func TestWebMembersRefused(t *testing.T) {
	long := strings.Repeat("a", 3000)
	cases := map[string]struct {
		mut  func(r *Report)
		want string
	}{
		"origin with path":      {func(r *Report) { r.Endpoints[0].Origin = "https://api.example.com/x" }, "normalised origin"},
		"origin not normalised": {func(r *Report) { r.Endpoints[0].Origin = "HTTPS://API.example.com:443" }, "normalised origin"},
		"origin user info":      {func(r *Report) { r.Endpoints[0].Origin = "https://u:p@api.example.com" }, "normalised origin"},
		"origin_ref dangling":   {func(r *Report) { r.Endpoints[0].OriginRef = "nope" }, "names no asset"},
		"method":                {func(r *Report) { r.Endpoints[0].Method = "BREW" }, "invalid method"},
		"path with query":       {func(r *Report) { r.Endpoints[0].Path = "/x?token=s3cr3t" }, "path must"},
		"path relative":         {func(r *Report) { r.Endpoints[0].Path = "x" }, "path must"},
		"path control":          {func(r *Report) { r.Endpoints[0].Path = "/a\u0007" }, "path must"},
		"template query":        {func(r *Report) { r.Endpoints[0].Template = "/x?a=1" }, "invalid template"},
		"kind":                  {func(r *Report) { r.Endpoints[0].Kind = "shell" }, "invalid kind"},
		"source":                {func(r *Report) { r.Endpoints[0].Source = "guess" }, "invalid source"},
		"auth":                  {func(r *Report) { r.Endpoints[0].Auth = "maybe" }, "invalid auth"},
		"parent with value":     {func(r *Report) { r.Endpoints[0].Parent = "https://a.example/x?sid=s3cr3t" }, "parent must"},
		"status":                {func(r *Report) { r.Endpoints[0].StatusCode = 99 }, "outside 100-599"},
		"content type":          {func(r *Report) { r.Endpoints[0].ContentType = long }, "content_type"},
		"param location":        {func(r *Report) { r.Endpoints[0].Params[0].Location = "body" }, "invalid location"},
		"param name long":       {func(r *Report) { r.Endpoints[0].Params[0].Name = long }, "name must"},
		"param name empty":      {func(r *Report) { r.Endpoints[0].Params[0].Name = " " }, "name must"},
		"type hint":             {func(r *Report) { r.Endpoints[0].Params[0].TypeHint = "String!" }, "type_hint"},
		"too many params":       {func(r *Report) { r.Endpoints[0].Params = make([]EndpointParam, 101) }, "at most 100"},
		"hostile id":            {func(r *Report) { r.Endpoints[0].ID = "ep 1<script>" }, "invalid id"},
		"duplicate id": {func(r *Report) {
			r.Endpoints = append(r.Endpoints, r.Endpoints[0])
		}, "duplicate id"},
		"technology":          {func(r *Report) { r.Endpoints[0].Technologies[0].Name = "" }, "technologies[0].name"},
		"web url with value":  {func(r *Report) { r.Findings[0].Web.URL = "https://a.example/x?token=s3cr3t" }, "web: url"},
		"web url user":        {func(r *Report) { r.Findings[0].Web.URL = "https://u:p@a.example/x" }, "web: url"},
		"web url fragment":    {func(r *Report) { r.Findings[0].Web.URL = "https://a.example/x#t=1" }, "web: url"},
		"web url not http":    {func(r *Report) { r.Findings[0].Web.URL = "javascript:alert(1)" }, "web: url"},
		"web method":          {func(r *Report) { r.Findings[0].Web.Method = "BREW" }, "invalid method"},
		"web endpoint_ref":    {func(r *Report) { r.Findings[0].Web.EndpointRef = "ep-9" }, "names no endpoint"},
		"web param location":  {func(r *Report) { r.Findings[0].Web.Parameter.Location = "x" }, "parameter: invalid location"},
		"web param name":      {func(r *Report) { r.Findings[0].Web.Parameter.Name = "" }, "parameter: name"},
		"web request_ref":     {func(r *Report) { r.Findings[0].Web.RequestRef = "../x" }, "request_ref"},
		"web status":          {func(r *Report) { r.Findings[0].Web.StatusCode = 700 }, "outside 100-599"},
		"evidence too many":   {func(r *Report) { r.Findings[0].EvidenceItems = make([]EvidenceItem, 21) }, "at most 20"},
		"evidence kind":       {func(r *Report) { r.Findings[0].EvidenceItems[0].Kind = "HTTP Exchange" }, "invalid kind"},
		"evidence label":      {func(r *Report) { r.Findings[0].EvidenceItems[0].Label = long }, "label"},
		"evidence sha":        {func(r *Report) { r.Findings[0].EvidenceItems[0].ContentSHA256 = "md5:x" }, "content_sha256"},
		"evidence no http":    {func(r *Report) { r.Findings[0].EvidenceItems[0].HTTP = nil }, "needs http"},
		"evidence header":     {func(r *Report) { r.Findings[0].EvidenceItems[0].HTTP.Request.Headers[0].Name = "Bad Name" }, "headers[0].name"},
		"evidence header ctl": {func(r *Report) { r.Findings[0].EvidenceItems[0].HTTP.Request.Headers[0].Value = "a\nInjected: x" }, "headers[0].value"},
		"evidence headers": {func(r *Report) {
			r.Findings[0].EvidenceItems[0].HTTP.Request.Headers = make([]EvidenceHeader, 101)
		}, "at most 100"},
		"evidence body cap": {func(r *Report) {
			r.Findings[0].EvidenceItems[0].HTTP.Response.Body = strings.Repeat("x", MaxEvidenceBodyBytes+1)
		}, "body longer"},
		"evidence item cap": {func(r *Report) {
			b := strings.Repeat("x", MaxEvidenceBodyBytes)
			h := r.Findings[0].EvidenceItems[0].HTTP
			h.Request.Body, h.Response.Body = b, b
			r.Findings[0].EvidenceItems[0].Text = b
			r.Findings[0].EvidenceItems[0].Extracted = []string{strings.Repeat("y", 1000)}
			for k := 0; k < 10; k++ {
				h.Request.Headers = append(h.Request.Headers, EvidenceHeader{Name: "X", Value: strings.Repeat("z", 8000)})
			}
		}, "larger than"},
		"evidence encoding":  {func(r *Report) { r.Findings[0].EvidenceItems[0].HTTP.Response.BodyEncoding = "gzip" }, "body_encoding"},
		"evidence status":    {func(r *Report) { r.Findings[0].EvidenceItems[0].HTTP.Response.Status = 42 }, "status 42"},
		"evidence method":    {func(r *Report) { r.Findings[0].EvidenceItems[0].HTTP.Request.Method = "GET /" }, "request.method"},
		"evidence version":   {func(r *Report) { r.Findings[0].EvidenceItems[0].HTTP.Response.HTTPVersion = "HTTP/9.9.9" }, "http_version"},
		"evidence match":     {func(r *Report) { r.Findings[0].EvidenceItems[0].Match[0].Part = "cookie" }, "part must"},
		"evidence match ord": {func(r *Report) { r.Findings[0].EvidenceItems[0].Match[0].Start = intp(9) }, "start and end"},
		"evidence extracted": {func(r *Report) { r.Findings[0].EvidenceItems[0].Extracted = make([]string, 21) }, "extracted has"},
		"evidence span ptr":  {func(r *Report) { r.Findings[0].EvidenceItems[0].Sensitive[0].Pointer = "http.request" }, "JSON pointer"},
		"evidence span ord":  {func(r *Report) { r.Findings[0].EvidenceItems[0].Sensitive[0].End = intp(1) }, "start and end"},
		"evidence span kind": {func(r *Report) { r.Findings[0].EvidenceItems[0].Sensitive[0].Kind = "Bad Kind" }, "invalid kind"},
		"curl no text":       {func(r *Report) { r.Findings[0].EvidenceItems[1].Text = "" }, "needs text"},
		"raw protocol":       {func(r *Report) { r.Findings[0].EvidenceItems[2].Protocol = "SSH 2" }, "invalid protocol"},
		"command empty": {func(r *Report) {
			r.Findings[0].EvidenceItems[3].Command, r.Findings[0].EvidenceItems[3].Text = "", ""
		}, "needs a command"},
		"file path":     {func(r *Report) { r.Findings[0].EvidenceItems[4].File.Path = "" }, "file.path"},
		"file lines":    {func(r *Report) { r.Findings[0].EvidenceItems[4].File.EndLine = 2 }, "out of order"},
		"no file":       {func(r *Report) { r.Findings[0].EvidenceItems[4].File = nil }, "needs file"},
		"artifact sha":  {func(r *Report) { r.Findings[0].EvidenceItems[5].Artifact.SHA256 = "x" }, "artifact.sha256"},
		"no artifact":   {func(r *Report) { r.Findings[0].EvidenceItems[5].Artifact = nil }, "needs artifact"},
		"data on known": {func(r *Report) { r.Findings[0].EvidenceItems[1].Data = map[string]any{"x": 1} }, "data is only"},
		"data too large": {func(r *Report) {
			r.Findings[0].EvidenceItems[6].Data = map[string]any{"x": strings.Repeat("d", MaxEvidenceDataBytes)}
		}, "data larger"},
		"unknown kind ok": {func(r *Report) {}, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := webReport()
			tc.mut(r)
			err := r.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// RedactSecretFinding masks a known raw secret everywhere, inside evidence
// too, except inside a span the tool marked: a marked value is the
// receiver's to mask for display and reveal on authorization. A span after
// a masked value moves with it.
func TestRedactSecretFindingKeepsMarkedEvidenceSpans(t *testing.T) {
	secret := "ghp_" + strings.Repeat("Z9", 18)
	f := Finding{Type: FindingTypeSecret, Title: "token " + secret, Severity: SeverityHigh,
		Location: &FindingLocation{Path: "deploy.env", Snippet: secret},
		EvidenceItems: []EvidenceItem{{Kind: EvidenceKindHTTPExchange, HTTP: &EvidenceHTTP{
			Request: &EvidenceRequest{Headers: []EvidenceHeader{
				{Name: "Authorization", Value: "Bearer " + secret},
				{Name: "X-Debug", Value: "leaked " + secret + " again " + secret},
			}},
			Response: &EvidenceResponse{Body: "echo " + secret},
		}, Sensitive: []SensitiveSpan{
			{Pointer: "/http/request/headers/0/value", Start: intp(7), End: intp(7 + len(secret)), Kind: "authorization"},
			{Pointer: "/http/request/headers/1/value", Start: intp(len("leaked " + secret + " again ")), End: intp(len("leaked "+secret+" again ") + len(secret))},
		}}},
	}
	RedactSecretFinding(&f, secret)
	if strings.Contains(f.Title, secret) || strings.Contains(f.Location.Snippet, secret) {
		t.Fatal("a raw secret survived outside evidence")
	}
	h := f.EvidenceItems[0].HTTP
	if h.Request.Headers[0].Value != "Bearer "+secret {
		t.Fatalf("a marked span was masked: %q", h.Request.Headers[0].Value)
	}
	if strings.Contains(h.Response.Body, secret) {
		t.Fatal("an unmarked copy in the body survived")
	}
	v := h.Request.Headers[1].Value
	if strings.Count(v, secret) != 1 || !strings.HasPrefix(v, "leaked ") {
		t.Fatalf("header 1: %q", v)
	}
	sp := f.EvidenceItems[0].Sensitive[1]
	if v[*sp.Start:*sp.End] != secret {
		t.Fatalf("the span did not move with the masked text: %q", v[*sp.Start:*sp.End])
	}
	// Outside marked spans no raw secret is left anywhere in the finding.
	raw, _ := json.Marshal(f)
	if n := strings.Count(string(raw), secret); n != 2 {
		t.Fatalf("raw secret appears %d times, want only the 2 marked spans", n)
	}
	// A whole-string span (no offsets) is left whole.
	g := Finding{Type: FindingTypeSecret, Title: "t", EvidenceItems: []EvidenceItem{{Kind: EvidenceKindRawText,
		Text: secret, Sensitive: []SensitiveSpan{{Pointer: "/text"}}}}}
	RedactSecretFinding(&g, secret)
	if g.EvidenceItems[0].Text != secret {
		t.Fatal("a whole-string span was masked")
	}
}

func TestOlderReportsStillValidate16(t *testing.T) {
	raw := []byte(`{"version":"1.5","metadata":{"timestamp":"2026-10-02T00:00:00Z"},"findings":[{"type":"vulnerability","title":"t","severity":"high","evidence":"legacy text"}]}`)
	r, err := decodeStrict(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if !IsKnownEvidenceKind(EvidenceKindCurl) || IsKnownEvidenceKind("dns_trace") {
		t.Fatal("IsKnownEvidenceKind")
	}
}
