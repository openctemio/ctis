package ctis

import (
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/ctis/weburl"
)

// WebContentProperty is the reserved asset property that carries the
// captures of a web content fetch (capability monitor.web_content@1): a list
// of objects with the keys url, final_url, status_code, content_type, size,
// sha256, truncated, body, body_truncated and fetched_at. A receiver takes it
// only for assets the report may change and never stores it on the asset.
//
// It is an explicit input (LiveHostInput.WebContent), not part of the httpx
// line allow-list: ParseHTTPXLine never keeps a response body.
const WebContentProperty = "web_content"

// Bounds of a web content capture. A scanned server chooses every value, so
// the converter applies them again whatever the producer claims.
const (
	// MaxWebContentBody is the longest body kept, in bytes.
	MaxWebContentBody = 512 << 10
	// MaxWebCaptures is the most captures one live host carries.
	MaxWebCaptures = 200

	maxWebContentType = 255
	webSHA256Len      = 64
)

// WebCaptureInput is one fetched URL: what the server answered, never what a
// page would execute.
type WebCaptureInput struct {
	// URL is the URL that was asked for. FinalURL is where redirects ended.
	URL      string
	FinalURL string
	// StatusCode is the HTTP status of the final response.
	StatusCode  int
	ContentType string
	// Size is the number of body bytes the producer read.
	Size int64
	// SHA256 is the lowercase hex SHA-256 of those bytes.
	SHA256 string
	// Truncated reports that the producer stopped reading at its limit.
	Truncated bool
	// Body is the response body as text; empty when the content type is not
	// text, or the producer chose not to send it. BodyTruncated reports that
	// the producer already cut it.
	Body          string
	BodyTruncated bool
	// FetchedAt is when the response was read; zero means now.
	FetchedAt time.Time
}

// webContent maps captures to the property value, or nil when none is valid.
// A capture whose URL is not a plain http(s) URL, or whose hash is not 64
// lowercase hex characters, is dropped. A final_url that is not plain http(s)
// is blanked.
func webContent(in []WebCaptureInput, now time.Time) []map[string]any {
	var out []map[string]any
	for _, c := range in {
		if len(out) >= MaxWebCaptures {
			break
		}
		u := plainWebURL(c.URL)
		if u == "" || !isLowerHex(c.SHA256, webSHA256Len) {
			continue
		}
		body := strings.ToValidUTF8(c.Body, "�")
		bodyTruncated := c.BodyTruncated
		if len(body) > MaxWebContentBody {
			body = truncateUTF8(body, MaxWebContentBody)
			bodyTruncated = true
		}
		status := 0
		if validStatus(c.StatusCode) {
			status = c.StatusCode
		}
		size := c.Size
		if size < 0 {
			size = 0
		}
		at := c.FetchedAt
		if at.IsZero() {
			at = now
		}
		out = append(out, map[string]any{
			"url":            u,
			"final_url":      plainWebURL(c.FinalURL),
			"status_code":    status,
			"content_type":   boundLine(c.ContentType, maxWebContentType),
			"size":           size,
			"sha256":         c.SHA256,
			"truncated":      c.Truncated,
			"body":           body,
			"body_truncated": bodyTruncated,
			"fetched_at":     at.UTC().Format(time.RFC3339),
		})
	}
	return out
}

// plainWebURL returns raw when it is an http(s) URL without user info,
// control characters or white space, else "".
func plainWebURL(raw string) string {
	if raw == "" || !utf8.ValidString(raw) {
		return ""
	}
	if _, err := weburl.Parse(raw); err != nil {
		return ""
	}
	return raw
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
