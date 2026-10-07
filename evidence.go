package ctis

import (
	"encoding/json"
	"regexp"
	"time"
)

// Typed evidence of a finding (CTIS 1.6, spec section 4.13): what a tool
// sent and received, or saw, when it found the issue. An item has an
// envelope (kind, version, label, capture time, content hash, sensitive
// spans) and the body of its kind. Kinds this module knows are validated
// whole; an item of another kind (a newer producer) is validated by its
// envelope only and carries its own fields in Data, so receivers keep it
// instead of refusing the report.
//
// Evidence MAY carry sensitive values (a session cookie in a captured
// request) only inside the spans its Sensitive list marks, or values a
// receiver can detect; receivers MUST mask them before display or
// forwarding. Every other member of a report stays secret-free.

// Evidence kinds this module knows.
const (
	EvidenceKindHTTPExchange  = "http_exchange"
	EvidenceKindRawText       = "raw_text"
	EvidenceKindScreenshot    = "screenshot"
	EvidenceKindFileExcerpt   = "file_excerpt"
	EvidenceKindCommandOutput = "command_output"
	EvidenceKindCurl          = "curl"
)

// KnownEvidenceKinds returns the kinds whose body this module validates.
func KnownEvidenceKinds() []string {
	return []string{EvidenceKindHTTPExchange, EvidenceKindRawText, EvidenceKindScreenshot,
		EvidenceKindFileExcerpt, EvidenceKindCommandOutput, EvidenceKindCurl}
}

// Limits of evidence.
const (
	MaxEvidenceItems       = 20
	MaxEvidenceItemBytes   = 256 << 10
	MaxEvidenceBodyBytes   = 64 << 10
	MaxEvidenceTextBytes   = 64 << 10
	MaxEvidenceHeaders     = 100
	MaxEvidenceHeaderBytes = 8 << 10
	MaxEvidenceExtracted   = 20
	MaxEvidenceExtractLen  = 1 << 10
	MaxEvidenceLabelLen    = 200
	MaxEvidenceMatches     = 50
	MaxEvidenceSpans       = 200
	MaxEvidenceURLBytes    = 8 << 10
	MaxEvidenceCommandLen  = 8 << 10
	MaxEvidenceDataBytes   = 64 << 10
	maxEvidencePointerLen  = 256
	maxEvidencePathLen     = 4096
)

// Body encodings.
const (
	BodyEncodingText   = "text"
	BodyEncodingBase64 = "base64"
)

// EvidenceItem is one piece of evidence.
type EvidenceItem struct {
	// Kind is a known kind or another ^[a-z0-9][a-z0-9_.-]{0,63}$ name.
	Kind string `json:"kind"`

	// Version of the kind's body format (1).
	Version int `json:"version,omitempty"`

	Label      string     `json:"label,omitempty"`
	CapturedAt *time.Time `json:"captured_at,omitempty"`

	// ContentSHA256 is "sha256:<hex>" over the item as captured, before any
	// masking or truncation.
	ContentSHA256 string `json:"content_sha256,omitempty"`

	// http_exchange
	HTTP *EvidenceHTTP `json:"http,omitempty"`

	// Match locates what matched in the request or the response.
	Match []EvidenceMatch `json:"match,omitempty"`

	// Extracted are values the tool extracted (versions, banners).
	Extracted []string `json:"extracted,omitempty"`

	// Text is the content of raw_text, command_output and curl items.
	Text string `json:"text,omitempty"`

	// Protocol of raw_text ("dns", "tls", "ssh", "banner", "smtp", ...).
	Protocol string `json:"protocol,omitempty"`

	// command_output
	Command  string `json:"command,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`

	// file_excerpt
	File *EvidenceFile `json:"file,omitempty"`

	// screenshot (and any binary evidence)
	Artifact *EvidenceArtifact `json:"artifact,omitempty"`

	// Data holds the fields of a kind this module does not know; empty for
	// known kinds.
	Data map[string]any `json:"data,omitempty"`

	// Sensitive marks the spans that hold secrets or personal data.
	Sensitive []SensitiveSpan `json:"sensitive,omitempty"`
}

// EvidenceHTTP is one HTTP request and its response.
type EvidenceHTTP struct {
	Request  *EvidenceRequest  `json:"request,omitempty"`
	Response *EvidenceResponse `json:"response,omitempty"`
}

// EvidenceRequest is a captured HTTP request.
type EvidenceRequest struct {
	Method        string           `json:"method,omitempty"`
	URL           string           `json:"url,omitempty"`
	HTTPVersion   string           `json:"http_version,omitempty"`
	Headers       []EvidenceHeader `json:"headers,omitempty"`
	Body          string           `json:"body,omitempty"`
	BodyEncoding  string           `json:"body_encoding,omitempty"`
	BodyTruncated bool             `json:"body_truncated,omitempty"`
	BodySize      int64            `json:"body_size,omitempty"`
}

// EvidenceResponse is a captured HTTP response.
type EvidenceResponse struct {
	Status        int              `json:"status,omitempty"`
	Reason        string           `json:"reason,omitempty"`
	HTTPVersion   string           `json:"http_version,omitempty"`
	Headers       []EvidenceHeader `json:"headers,omitempty"`
	Body          string           `json:"body,omitempty"`
	BodyEncoding  string           `json:"body_encoding,omitempty"`
	BodyTruncated bool             `json:"body_truncated,omitempty"`
	BodySize      int64            `json:"body_size,omitempty"`
	TimeMs        int64            `json:"time_ms,omitempty"`
}

// EvidenceHeader is one header, in captured order.
type EvidenceHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Match locations and parts.
const (
	MatchLocationRequest  = "request"
	MatchLocationResponse = "response"
	MatchPartStatus       = "status"
	MatchPartHeader       = "header"
	MatchPartBody         = "body"
	MatchPartURL          = "url"
)

// EvidenceMatch locates what a matcher matched. Start and End are byte
// offsets into the part as sent.
type EvidenceMatch struct {
	Location string `json:"location"`
	Part     string `json:"part"`
	Start    *int   `json:"start,omitempty"`
	End      *int   `json:"end,omitempty"`
	Matcher  string `json:"matcher,omitempty"`
}

// EvidenceFile is an excerpt of a file.
type EvidenceFile struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	Snippet   string `json:"snippet,omitempty"`
}

// EvidenceArtifact names binary evidence stored apart from the report.
type EvidenceArtifact struct {
	MediaType string `json:"media_type"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size,omitempty"`
	Ref       string `json:"ref,omitempty"`
}

// SensitiveSpan marks a secret or personal value inside the item: the
// string at Pointer (a JSON pointer into the item), whole or the byte range
// [Start, End).
type SensitiveSpan struct {
	Pointer string `json:"pointer"`
	Start   *int   `json:"start,omitempty"`
	End     *int   `json:"end,omitempty"`
	Kind    string `json:"kind,omitempty"`
}

var (
	evidenceKindRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	contentSHA256RE   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	jsonPointerRE     = regexp.MustCompile(`^(/([^~/]|~[01])*)+$`)
	spanKindRE        = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	httpTokenRE       = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,31}$`)
	httpVersionRE     = regexp.MustCompile(`^(HTTP/[0-9](\.[0-9])?)?$`)
	headerNameRE      = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$")
	protocolRE        = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	mediaTypeRE       = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]{0,62}/[a-z0-9][a-z0-9!#$&^_.+-]{0,62}$`)
	evidenceMatcherRE = regexp.MustCompile(`^[^\x00-\x1f\x7f]{0,128}$`)
)

// IsKnownEvidenceKind reports whether this module validates the kind's
// body.
func IsKnownEvidenceKind(kind string) bool {
	for _, k := range KnownEvidenceKinds() {
		if k == kind {
			return true
		}
	}
	return false
}

// validateEvidenceItems checks finding.evidence_items.
func validateEvidenceItems(i int, items []EvidenceItem, add func(string, ...any)) {
	if len(items) > MaxEvidenceItems {
		add("findings[%d]: evidence_items has %d entries, at most %d", i, len(items), MaxEvidenceItems)
		return
	}
	for j := range items {
		it := &items[j]
		p := func(format string, args ...any) {
			add("findings[%d]: evidence_items[%d]: "+format, append([]any{i, j}, args...)...)
		}
		validateEvidenceItem(it, p)
	}
}

func validateEvidenceItem(it *EvidenceItem, p func(string, ...any)) {
	if raw, err := json.Marshal(it); err != nil || len(raw) > MaxEvidenceItemBytes {
		p("larger than %d bytes", MaxEvidenceItemBytes)
		return
	}
	if !evidenceKindRE.MatchString(it.Kind) {
		p("invalid kind")
		return
	}
	if it.Version < 0 || it.Version > 1000 {
		p("invalid version %d", it.Version)
	}
	if tooLong(it.Label, MaxEvidenceLabelLen) || hasControlRune(it.Label) {
		p("label longer than %d or with control characters", MaxEvidenceLabelLen)
	}
	if it.ContentSHA256 != "" && !contentSHA256RE.MatchString(it.ContentSHA256) {
		p("content_sha256 must be sha256:<64 hex>")
	}
	validateSpans(it, p)
	if !IsKnownEvidenceKind(it.Kind) {
		// A kind this module does not know: the envelope only, and its
		// own fields stay in data, bounded.
		if raw, err := json.Marshal(it.Data); err != nil || len(raw) > MaxEvidenceDataBytes {
			p("data larger than %d bytes", MaxEvidenceDataBytes)
		}
		return
	}
	if len(it.Data) > 0 {
		p("data is only for kinds this version does not know")
	}
	if len(it.Match) > MaxEvidenceMatches {
		p("match has %d entries, at most %d", len(it.Match), MaxEvidenceMatches)
	}
	for k, m := range it.Match {
		if k >= MaxEvidenceMatches {
			break
		}
		validateMatch(m, func(format string, args ...any) { p("match[%d]: "+format, append([]any{k}, args...)...) })
	}
	if len(it.Extracted) > MaxEvidenceExtracted {
		p("extracted has %d entries, at most %d", len(it.Extracted), MaxEvidenceExtracted)
	}
	for k, x := range it.Extracted {
		if len(x) > MaxEvidenceExtractLen {
			p("extracted[%d] longer than %d bytes", k, MaxEvidenceExtractLen)
		}
	}
	if len(it.Text) > MaxEvidenceTextBytes {
		p("text longer than %d bytes", MaxEvidenceTextBytes)
	}
	switch it.Kind {
	case EvidenceKindHTTPExchange:
		validateEvidenceHTTP(it.HTTP, p)
	case EvidenceKindRawText, EvidenceKindCurl:
		if it.Text == "" {
			p("%s needs text", it.Kind)
		}
		if it.Protocol != "" && !protocolRE.MatchString(it.Protocol) {
			p("invalid protocol")
		}
	case EvidenceKindCommandOutput:
		if it.Text == "" && it.Command == "" {
			p("command_output needs a command or text")
		}
		if len(it.Command) > MaxEvidenceCommandLen {
			p("command longer than %d bytes", MaxEvidenceCommandLen)
		}
	case EvidenceKindFileExcerpt:
		f := it.File
		switch {
		case f == nil:
			p("file_excerpt needs file")
		case f.Path == "" || len(f.Path) > maxEvidencePathLen || hasControlRune(f.Path):
			p("file.path must be 1 to %d bytes without control characters", maxEvidencePathLen)
		case f.StartLine < 0 || f.EndLine < 0 || (f.EndLine > 0 && f.EndLine < f.StartLine):
			p("file lines out of order")
		case len(f.Snippet) > MaxEvidenceTextBytes:
			p("file.snippet longer than %d bytes", MaxEvidenceTextBytes)
		}
	case EvidenceKindScreenshot:
		a := it.Artifact
		switch {
		case a == nil:
			p("screenshot needs artifact")
		case !mediaTypeRE.MatchString(a.MediaType):
			p("artifact.media_type")
		case !contentSHA256RE.MatchString(a.SHA256):
			p("artifact.sha256 must be sha256:<64 hex>")
		case a.Size < 0 || len(a.Ref) > 256 || hasControlRune(a.Ref):
			p("artifact size or ref")
		}
	}
}

func validateMatch(m EvidenceMatch, p func(string, ...any)) {
	if m.Location != MatchLocationRequest && m.Location != MatchLocationResponse {
		p("location must be request or response")
	}
	switch m.Part {
	case MatchPartStatus, MatchPartHeader, MatchPartBody, MatchPartURL:
	default:
		p("part must be status, header, body or url")
	}
	if !validRange(m.Start, m.End) {
		p("start and end must be 0 <= start <= end")
	}
	if !evidenceMatcherRE.MatchString(m.Matcher) {
		p("invalid matcher name")
	}
}

func validRange(start, end *int) bool {
	switch {
	case start != nil && *start < 0, end != nil && *end < 0:
		return false
	case start != nil && end != nil && *start > *end:
		return false
	}
	return true
}

func validateSpans(it *EvidenceItem, p func(string, ...any)) {
	if len(it.Sensitive) > MaxEvidenceSpans {
		p("sensitive has %d entries, at most %d", len(it.Sensitive), MaxEvidenceSpans)
		return
	}
	for k, s := range it.Sensitive {
		switch {
		case len(s.Pointer) > maxEvidencePointerLen || !jsonPointerRE.MatchString(s.Pointer):
			p("sensitive[%d]: pointer must be a JSON pointer", k)
		case !validRange(s.Start, s.End):
			p("sensitive[%d]: start and end must be 0 <= start <= end", k)
		case s.Kind != "" && !spanKindRE.MatchString(s.Kind):
			p("sensitive[%d]: invalid kind", k)
		}
	}
}

func validateEvidenceHTTP(h *EvidenceHTTP, p func(string, ...any)) {
	if h == nil || (h.Request == nil && h.Response == nil) {
		p("http_exchange needs http.request or http.response")
		return
	}
	if r := h.Request; r != nil {
		if r.Method != "" && !httpTokenRE.MatchString(r.Method) {
			p("http.request.method")
		}
		if len(r.URL) > MaxEvidenceURLBytes || hasControlRune(r.URL) {
			p("http.request.url longer than %d bytes or with control characters", MaxEvidenceURLBytes)
		}
		if !httpVersionRE.MatchString(r.HTTPVersion) {
			p("http.request.http_version")
		}
		validateHeaders(r.Headers, func(format string, args ...any) { p("http.request."+format, args...) })
		validateBody(r.Body, r.BodyEncoding, r.BodySize, func(format string, args ...any) { p("http.request."+format, args...) })
	}
	if r := h.Response; r != nil {
		if r.Status != 0 && (r.Status < minStatusCode || r.Status > maxStatusCode) {
			p("http.response.status %d is outside 100-599", r.Status)
		}
		if tooLong(r.Reason, 128) || hasControlRune(r.Reason) {
			p("http.response.reason")
		}
		if !httpVersionRE.MatchString(r.HTTPVersion) {
			p("http.response.http_version")
		}
		if r.TimeMs < 0 {
			p("http.response.time_ms is negative")
		}
		validateHeaders(r.Headers, func(format string, args ...any) { p("http.response."+format, args...) })
		validateBody(r.Body, r.BodyEncoding, r.BodySize, func(format string, args ...any) { p("http.response."+format, args...) })
	}
}

func validateHeaders(hs []EvidenceHeader, p func(string, ...any)) {
	if len(hs) > MaxEvidenceHeaders {
		p("headers has %d entries, at most %d", len(hs), MaxEvidenceHeaders)
		return
	}
	for k, h := range hs {
		if !headerNameRE.MatchString(h.Name) {
			p("headers[%d].name is not a header name", k)
		}
		if len(h.Value) > MaxEvidenceHeaderBytes || hasControlRune(h.Value) {
			p("headers[%d].value longer than %d bytes or with control characters", k, MaxEvidenceHeaderBytes)
		}
	}
}

func validateBody(body, enc string, size int64, p func(string, ...any)) {
	if len(body) > MaxEvidenceBodyBytes {
		p("body longer than %d bytes", MaxEvidenceBodyBytes)
	}
	if enc != "" && enc != BodyEncodingText && enc != BodyEncodingBase64 {
		p("body_encoding must be text or base64")
	}
	if size < 0 {
		p("body_size is negative")
	}
}
