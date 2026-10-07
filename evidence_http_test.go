package ctis

import (
	"strings"
	"testing"
)

// unmarked returns the pointers of the item's strings that hold secret
// outside every marked span.
func unmarked(it *EvidenceItem, secret string) []string {
	var out []string
	for ptr, s := range evidenceStrings(it) {
		for from := 0; ; {
			i := strings.Index(s[from:], secret)
			if i < 0 {
				break
			}
			start, end := from+i, from+i+len(secret)
			covered := false
			for _, sp := range it.Sensitive {
				if sp.Pointer != ptr {
					continue
				}
				lo, hi := 0, len(s)
				if sp.Start != nil {
					lo = *sp.Start
				}
				if sp.End != nil {
					hi = *sp.End
				}
				if lo <= start && end <= hi {
					covered = true
				}
			}
			if !covered {
				out = append(out, ptr)
			}
			from = end
		}
	}
	return out
}

func validItem(t *testing.T, it EvidenceItem) {
	t.Helper()
	var errs []string
	validateEvidenceItem(&it, func(format string, args ...any) { errs = append(errs, format) })
	if len(errs) > 0 {
		t.Fatalf("item does not validate: %v", errs)
	}
}

const (
	tBearer = "eyJhbGciOiJIUzI1NiJ9.c2VjcmV0LXBheWxvYWQ.c2lnbmF0dXJl"
	tCookie = "s3ss10n-c00k1e-value"
	tAPIKey = "ak_live_0123456789abcdef"
	tPass   = "hunter2-passw0rd"
)

func TestHTTPExchangeFromRawMarksSecrets(t *testing.T) {
	req := "POST /login?next=/home&access_token=" + tAPIKey + " HTTP/1.1\r\n" +
		"Host: app.example.com\r\n" +
		"Authorization: Bearer " + tBearer + "\r\n" +
		"Cookie: theme=dark; sid=" + tCookie + "\r\n" +
		"X-Api-Key: " + tAPIKey + "\r\n" +
		"X-Session-Id: " + tCookie + "\r\n" +
		"Bad Header: x\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n\r\n" +
		"user=alice&password=" + tPass + "&remember=1"
	resp := "HTTP/1.1 302 Found\r\nSet-Cookie: sid=" + tCookie + "; HttpOnly\r\nLocation: /home\r\n\r\n" +
		`{"ok":true,"api_token":"` + tAPIKey + `","echo":"Bearer ` + tBearer + `"}`
	it, ok := HTTPExchangeFromRaw(req, resp, "https://app.example.com")
	if !ok {
		t.Fatal("no item")
	}
	validItem(t, it)
	r := it.HTTP.Request
	if r.Method != "POST" || r.URL != "https://app.example.com/login?next=/home&access_token="+tAPIKey || r.HTTPVersion != "HTTP/1.1" {
		t.Errorf("request line: %+v", r)
	}
	if len(r.Headers) != 6 {
		t.Errorf("headers %+v (the malformed one is dropped)", r.Headers)
	}
	if it.HTTP.Response.Status != 302 || it.HTTP.Response.Reason != "Found" {
		t.Errorf("status line %+v", it.HTTP.Response)
	}
	curl, _ := CurlEvidence("curl -X POST -H 'Authorization: Bearer " + tBearer + "' -b 'sid=" + tCookie + "' 'https://app.example.com/login?access_token=" + tAPIKey + "' -d 'password=" + tPass + "'")
	MarkSensitive(&it, &curl)
	validItem(t, curl)
	for _, secret := range []string{tBearer, tCookie, tAPIKey, tPass} {
		for _, item := range []*EvidenceItem{&it, &curl} {
			if u := unmarked(item, secret); len(u) > 0 {
				t.Errorf("%s: %q unmarked at %v", item.Kind, secret[:6], u)
			}
		}
	}
	// Marking is idempotent.
	n := len(it.Sensitive)
	MarkSensitive(&it, &curl)
	if len(it.Sensitive) != n {
		t.Error("MarkSensitive added spans twice")
	}
	// Redaction keeps marked values, the receiver masks them.
	f := Finding{Type: FindingTypeVulnerability, Title: "t", EvidenceItems: []EvidenceItem{it, curl}}
	RedactSecretFinding(&f, tBearer)
	if !strings.Contains(f.EvidenceItems[0].HTTP.Request.Headers[1].Value, tBearer) {
		t.Error("a marked value was masked")
	}
}

func TestHTTPExchangeFromRawEdges(t *testing.T) {
	if _, ok := HTTPExchangeFromRaw("", "", ""); ok {
		t.Error("empty input")
	}
	if _, ok := HTTPExchangeFromRaw("not http", "neither", ""); ok {
		t.Error("garbage input")
	}
	// Response only, LF line ends, HTTP/2, binary body, a huge body.
	it, ok := HTTPExchangeFromRaw("", "HTTP/2 200\nContent-Type: image/png\n\n\x89PNG\x00\xff", "")
	if !ok || it.HTTP.Response.HTTPVersion != "HTTP/2" || it.HTTP.Response.BodyEncoding != BodyEncodingBase64 {
		t.Fatalf("binary response %+v", it.HTTP.Response)
	}
	validItem(t, it)
	big := strings.Repeat("<", 200<<10)
	it, _ = HTTPExchangeFromRaw("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"+big, "HTTP/1.1 200 OK\r\n\r\n"+big, "")
	validItem(t, it)
	if !it.HTTP.Response.BodyTruncated || it.HTTP.Response.BodySize != int64(len(big)) || it.HTTP.Request.URL != "http://a.example/" {
		t.Errorf("big: truncated %v size %d url %q", it.HTTP.Response.BodyTruncated, it.HTTP.Response.BodySize, it.HTTP.Request.URL)
	}
	// Header flood and control characters.
	var b strings.Builder
	b.WriteString("GET /x HTTP/1.1\r\n")
	for i := 0; i < 300; i++ {
		b.WriteString("X-H: " + strings.Repeat("v", 9000) + "\x1b[31m\r\n")
	}
	it, _ = HTTPExchangeFromRaw(b.String(), "", "")
	validItem(t, it)
	if n := len(it.HTTP.Request.Headers); n == 0 || n > MaxEvidenceHeaders {
		t.Errorf("headers %d", n)
	}
	if it.HTTP.Request.URL != "/x" {
		t.Errorf("relative target without a host: %q", it.HTTP.Request.URL)
	}
	if _, ok := CurlEvidence("  "); ok {
		t.Error("empty curl")
	}
	for _, h := range []string{"Authorization", "cookie", "X-Auth-User", "X-Session", "X-CSRF-Token", "x-api-key"} {
		if !IsSensitiveHeader(h) {
			t.Errorf("%s is sensitive", h)
		}
	}
	for _, h := range []string{"Content-Type", "Host", "Accept"} {
		if IsSensitiveHeader(h) {
			t.Errorf("%s is not sensitive", h)
		}
	}
	if !IsSensitiveParam("password") || IsSensitiveParam("page") {
		t.Error("IsSensitiveParam")
	}
}

func TestHTTPExchangeFromHAR(t *testing.T) {
	entry := `{"startedDateTime":"2026-10-07T10:00:00.123+02:00","time":87.4,
	 "request":{"method":"POST","url":"https://app.example.com/api?session=` + tCookie + `","httpVersion":"HTTP/2.0",
	  "headers":[{"name":"Authorization","value":"Basic ` + tAPIKey + `"},{"name":"Content-Type","value":"application/json"}],
	  "postData":{"mimeType":"application/json","text":"{\"user\":\"a\",\"password\":\"` + tPass + `\"}"}},
	 "response":{"status":200,"statusText":"OK","httpVersion":"HTTP/2.0","headers":[{"name":"Set-Cookie","value":"sid=` + tCookie + `"}],
	  "content":{"size":10,"mimeType":"text/plain","text":"aGVsbG8gd29ybGQ=","encoding":"base64"}}}`
	it, err := HTTPExchangeFromHAR([]byte(entry))
	if err != nil {
		t.Fatal(err)
	}
	validItem(t, it)
	if it.CapturedAt == nil || it.HTTP.Request.HTTPVersion != "HTTP/2" || it.HTTP.Response.Body != "hello world" || it.HTTP.Response.TimeMs != 87 {
		t.Errorf("har: %+v %+v", it.HTTP.Request, it.HTTP.Response)
	}
	for _, secret := range []string{tCookie, tAPIKey, tPass} {
		if u := unmarked(&it, secret); len(u) > 0 {
			t.Errorf("%q unmarked at %v", secret[:6], u)
		}
	}
	if _, err := HTTPExchangeFromHAR([]byte(`{}`)); err == nil {
		t.Error("an empty entry")
	}
	if _, err := HTTPExchangeFromHAR([]byte(`[`)); err == nil {
		t.Error("bad JSON")
	}
}

func FuzzHTTPExchangeFromRaw(f *testing.F) {
	f.Add("GET /a?token=x HTTP/1.1\r\nCookie: sid=abcdef\r\n\r\nbody", "HTTP/1.1 200 OK\r\nSet-Cookie: a=bcdefg\r\n\r\nok")
	f.Add("\n\n", "HTTP/")
	f.Fuzz(func(t *testing.T, req, resp string) {
		it, ok := HTTPExchangeFromRaw(req, resp, "https://a.example")
		if !ok {
			return
		}
		var errs []string
		validateEvidenceItem(&it, func(format string, args ...any) { errs = append(errs, format) })
		if len(errs) > 0 {
			t.Fatalf("invalid item %v", errs)
		}
		if r := it.HTTP.Request; r != nil {
			for _, h := range r.Headers {
				if IsSensitiveHeader(h.Name) && h.Value != "" && len(unmarked(&it, h.Value)) > 0 {
					t.Fatalf("sensitive header %s unmarked", h.Name)
				}
			}
		}
	})
}
