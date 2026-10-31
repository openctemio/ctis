package ctis

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func hashOf(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func convertCapture(t *testing.T, caps ...WebCaptureInput) any {
	t.Helper()
	r, err := ConvertReconToCTIS(&ReconToCTISInput{
		LiveHosts: []LiveHostInput{{URL: "https://app.example.com/login", Host: "app.example.com", Scheme: "https", WebContent: caps}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range r.Assets {
		if a.Type == AssetTypeHTTPService {
			return a.Properties[WebContentProperty]
		}
	}
	t.Fatal("no http_service asset")
	return nil
}

func TestWebContentPropertyShape(t *testing.T) {
	at := time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)
	got := convertCapture(t, WebCaptureInput{
		URL: "https://app.example.com/login", FinalURL: "https://app.example.com/login/",
		StatusCode: 200, ContentType: "text/html; charset=utf-8", Size: 12,
		SHA256: hashOf("<html></html>"), Body: "<html></html>", FetchedAt: at,
	})
	list, ok := got.([]map[string]any)
	if !ok || len(list) != 1 {
		t.Fatalf("property = %#v", got)
	}
	c := list[0]
	want := map[string]any{
		"url": "https://app.example.com/login", "final_url": "https://app.example.com/login/",
		"status_code": 200, "content_type": "text/html; charset=utf-8", "size": int64(12),
		"sha256": hashOf("<html></html>"), "truncated": false, "body": "<html></html>",
		"body_truncated": false, "fetched_at": "2026-10-31T09:00:00Z",
	}
	if len(c) != len(want) {
		t.Fatalf("keys = %v", c)
	}
	for k, v := range want {
		if c[k] != v {
			t.Errorf("%s = %#v, want %#v", k, c[k], v)
		}
	}
}

func TestWebContentAbsentWithoutCaptures(t *testing.T) {
	if got := convertCapture(t); got != nil {
		t.Fatalf("property = %#v, want none", got)
	}
}

func TestWebContentBodyCapOnRuneBoundary(t *testing.T) {
	// 3-byte runes: the cap falls in the middle of one.
	body := strings.Repeat("€", MaxWebContentBody/3+10)
	got := convertCapture(t, WebCaptureInput{URL: "https://a.example.com/", SHA256: hashOf(body), Body: body}).([]map[string]any)[0]
	b := got["body"].(string)
	if len(b) > MaxWebContentBody || !utf8.ValidString(b) || len(b) < MaxWebContentBody-3 {
		t.Fatalf("body len %d valid=%v", len(b), utf8.ValidString(b))
	}
	if got["body_truncated"] != true {
		t.Fatal("body_truncated not set")
	}
}

func TestWebContentInvalidUTF8Replaced(t *testing.T) {
	got := convertCapture(t, WebCaptureInput{URL: "https://a.example.com/", SHA256: hashOf("x"), Body: "a\xff\xfeb"}).([]map[string]any)[0]
	if b := got["body"].(string); !utf8.ValidString(b) || !strings.Contains(b, "�") {
		t.Fatalf("body = %q", b)
	}
}

func TestWebContentHostileValuesDropped(t *testing.T) {
	good := hashOf("x")
	for name, c := range map[string]WebCaptureInput{
		"javascript url":   {URL: "javascript:alert(1)", SHA256: good},
		"file url":         {URL: "file:///etc/passwd", SHA256: good},
		"userinfo url":     {URL: "https://u:p@a.example.com/", SHA256: good},
		"control in url":   {URL: "https://a.example.com/\n", SHA256: good},
		"empty url":        {SHA256: good},
		"upper hex":        {URL: "https://a.example.com/", SHA256: strings.ToUpper(good)},
		"short hash":       {URL: "https://a.example.com/", SHA256: good[:63]},
		"non hex hash":     {URL: "https://a.example.com/", SHA256: strings.Repeat("g", 64)},
		"missing hash":     {URL: "https://a.example.com/"},
		"long url":         {URL: "https://a.example.com/" + strings.Repeat("a", 3000), SHA256: good},
		"hash with suffix": {URL: "https://a.example.com/", SHA256: good + "\n"},
	} {
		if got := convertCapture(t, c); got != nil {
			t.Errorf("%s: kept %#v", name, got)
		}
	}
}

func TestWebContentFieldsBounded(t *testing.T) {
	got := convertCapture(t, WebCaptureInput{
		URL: "https://a.example.com/", FinalURL: "ftp://evil/", SHA256: hashOf("x"),
		StatusCode: 99999, ContentType: "text/html\r\nX-Forged: 1" + strings.Repeat("a", 1000), Size: -5,
	}).([]map[string]any)[0]
	if got["final_url"] != "" || got["status_code"] != 0 || got["size"] != int64(0) {
		t.Fatalf("not normalised: %#v", got)
	}
	ct := got["content_type"].(string)
	if len(ct) > maxWebContentType || strings.ContainsAny(ct, "\r\n") {
		t.Fatalf("content_type = %q", ct)
	}
	if got["fetched_at"] == "" {
		t.Fatal("fetched_at empty")
	}
}

func TestWebContentCaptureCount(t *testing.T) {
	caps := make([]WebCaptureInput, MaxWebCaptures+50)
	for i := range caps {
		caps[i] = WebCaptureInput{URL: "https://a.example.com/", SHA256: hashOf("x")}
	}
	if n := len(convertCapture(t, caps...).([]map[string]any)); n != MaxWebCaptures {
		t.Fatalf("kept %d", n)
	}
}

// The httpx line mapper never keeps a body, and never fills WebContent.
func TestParseHTTPXLineNeverKeepsBody(t *testing.T) {
	h, err := ParseHTTPXLine([]byte(`{"url":"https://a.example.com/","body":"secret","response":"HTTP/1.1 200 OK\r\n\r\nsecret"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if h.WebContent != nil {
		t.Fatalf("WebContent = %#v", h.WebContent)
	}
}
