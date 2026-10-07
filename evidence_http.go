package ctis

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Building evidence items from what tools capture (spec section 4.13): raw
// HTTP text, HAR entries, curl commands. The builders cap every part, so
// the item validates, and mark (never mask) the sensitive values: the
// Authorization, Cookie and API-key headers, headers named like a token,
// secret, session or auth, and query, form and JSON members named like
// one. A receiver masks the marked spans before display.

// maxEvidenceHeaderTotal bounds the headers of one message, so an item with
// both bodies stays under MaxEvidenceItemBytes.
const maxEvidenceHeaderTotal = 32 << 10

var (
	sensitiveHeaders = map[string]bool{
		"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true,
		"x-api-key": true, "x-auth-token": true, "x-csrf-token": true, "x-xsrf-token": true,
	}
	sensitiveNameRE = regexp.MustCompile(`(?i)token|secret|session|auth|passw|passwd|pwd|api[-_]?key|apikey|credential|signature|jwt|sid$|^sid|^code$|^key$|private`)
	jsonMemberRE    = regexp.MustCompile(`"([^"\\]{1,128})"\s*:\s*"((?:[^"\\]|\\.)*)"`)
)

// IsSensitiveHeader reports whether a header carries credentials or a
// session: Authorization, Proxy-Authorization, Cookie, Set-Cookie,
// X-Api-Key, or a name with token, secret, session or auth in it.
func IsSensitiveHeader(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	return sensitiveHeaders[n] || sensitiveNameRE.MatchString(n)
}

// IsSensitiveParam reports whether a query, form or JSON member name names
// a credential, a session or a token.
func IsSensitiveParam(name string) bool {
	return sensitiveNameRE.MatchString(strings.TrimSpace(name))
}

// HTTPExchangeFromRaw builds an http_exchange item from a raw HTTP/1.x
// request and response as a tool printed them. A relative request target is
// resolved against baseURL. It reports false when neither part holds an
// HTTP message. The item is capped and its sensitive values are marked.
func HTTPExchangeFromRaw(request, response, baseURL string) (EvidenceItem, bool) {
	it := EvidenceItem{Kind: EvidenceKindHTTPExchange, Version: 1, HTTP: &EvidenceHTTP{}}
	if req, ok := parseRawRequest(request, baseURL); ok {
		it.HTTP.Request = req
	}
	if resp, ok := parseRawResponse(response); ok {
		it.HTTP.Response = resp
	}
	if it.HTTP.Request == nil && it.HTTP.Response == nil {
		return EvidenceItem{}, false
	}
	FitEvidenceItem(&it)
	MarkSensitive(&it)
	return it, true
}

// CurlEvidence is a curl item holding the command, capped. Call
// MarkSensitive with the exchange it reproduces to mark the values the
// command repeats.
func CurlEvidence(command string) (EvidenceItem, bool) {
	command = strings.TrimSpace(command)
	if command == "" {
		return EvidenceItem{}, false
	}
	return EvidenceItem{Kind: EvidenceKindCurl, Version: 1, Text: cutUTF8(command, MaxEvidenceTextBytes)}, true
}

// harEntry is the part of a HAR 1.2 entry an exchange is built from.
type harEntry struct {
	StartedDateTime string  `json:"startedDateTime"`
	Time            float64 `json:"time"`
	Request         struct {
		Method      string      `json:"method"`
		URL         string      `json:"url"`
		HTTPVersion string      `json:"httpVersion"`
		Headers     []harHeader `json:"headers"`
		PostData    *struct {
			MimeType string `json:"mimeType"`
			Text     string `json:"text"`
		} `json:"postData"`
		BodySize int64 `json:"bodySize"`
	} `json:"request"`
	Response struct {
		Status      int         `json:"status"`
		StatusText  string      `json:"statusText"`
		HTTPVersion string      `json:"httpVersion"`
		Headers     []harHeader `json:"headers"`
		Content     struct {
			Size     int64  `json:"size"`
			Text     string `json:"text"`
			Encoding string `json:"encoding"`
		} `json:"content"`
	} `json:"response"`
}

type harHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HTTPExchangeFromHAR builds an http_exchange item from one HAR 1.2 entry
// (log.entries[i]). The item is capped and its sensitive values are marked.
func HTTPExchangeFromHAR(entry []byte) (EvidenceItem, error) {
	var e harEntry
	if err := json.Unmarshal(entry, &e); err != nil {
		return EvidenceItem{}, err
	}
	it := EvidenceItem{Kind: EvidenceKindHTTPExchange, Version: 1, HTTP: &EvidenceHTTP{}}
	if t, err := time.Parse(time.RFC3339, e.StartedDateTime); err == nil {
		t = t.UTC()
		it.CapturedAt = &t
	}
	if e.Request.Method != "" || e.Request.URL != "" {
		req := &EvidenceRequest{
			Method:      httpToken(e.Request.Method),
			URL:         cleanURL(e.Request.URL),
			HTTPVersion: httpVersion(e.Request.HTTPVersion),
		}
		for _, h := range e.Request.Headers {
			req.Headers = appendHeader(req.Headers, h.Name, h.Value)
		}
		if pd := e.Request.PostData; pd != nil {
			req.Body, req.BodyEncoding, req.BodyTruncated, req.BodySize = capBody(pd.Text)
		}
		it.HTTP.Request = req
	}
	if e.Response.Status != 0 || len(e.Response.Headers) > 0 {
		resp := &EvidenceResponse{
			Reason:      cleanReason(e.Response.StatusText),
			HTTPVersion: httpVersion(e.Response.HTTPVersion),
		}
		if e.Response.Status >= minStatusCode && e.Response.Status <= maxStatusCode {
			resp.Status = e.Response.Status
		}
		for _, h := range e.Response.Headers {
			resp.Headers = appendHeader(resp.Headers, h.Name, h.Value)
		}
		body := e.Response.Content.Text
		if strings.EqualFold(e.Response.Content.Encoding, "base64") {
			if raw, err := base64.StdEncoding.DecodeString(body); err == nil {
				body = string(raw)
			}
		}
		resp.Body, resp.BodyEncoding, resp.BodyTruncated, resp.BodySize = capBody(body)
		if e.Time > 0 {
			resp.TimeMs = int64(e.Time)
		}
		it.HTTP.Response = resp
	}
	if it.HTTP.Request == nil && it.HTTP.Response == nil {
		return EvidenceItem{}, errNoExchange
	}
	FitEvidenceItem(&it)
	MarkSensitive(&it)
	return it, nil
}

type evidenceError string

func (e evidenceError) Error() string { return string(e) }

const errNoExchange = evidenceError("no HTTP request or response")

func parseRawRequest(raw, baseURL string) (*EvidenceRequest, bool) {
	head, body, ok := splitHTTPMessage(raw)
	if !ok {
		return nil, false
	}
	fields := strings.Fields(head[0])
	if len(fields) < 2 || !httpTokenRE.MatchString(fields[0]) || strings.ToUpper(fields[0]) != fields[0] ||
		!isRequestTarget(fields[1]) {
		return nil, false
	}
	req := &EvidenceRequest{Method: fields[0]}
	if len(fields) >= 3 {
		req.HTTPVersion = httpVersion(fields[2])
	}
	for _, l := range head[1:] {
		if name, value, ok := strings.Cut(l, ":"); ok {
			req.Headers = appendHeader(req.Headers, name, strings.TrimSpace(value))
		}
	}
	req.URL = cleanURL(resolveTarget(fields[1], baseURL, req.Headers))
	req.Body, req.BodyEncoding, req.BodyTruncated, req.BodySize = capBody(body)
	return req, true
}

// isRequestTarget reports whether t is an origin-form, absolute-form or
// asterisk-form request target.
func isRequestTarget(t string) bool {
	return strings.HasPrefix(t, "/") || strings.Contains(t, "://") || t == "*"
}

func parseRawResponse(raw string) (*EvidenceResponse, bool) {
	head, body, ok := splitHTTPMessage(raw)
	if !ok || !strings.HasPrefix(head[0], "HTTP/") {
		return nil, false
	}
	fields := strings.SplitN(head[0], " ", 3)
	resp := &EvidenceResponse{HTTPVersion: httpVersion(fields[0])}
	if len(fields) >= 2 {
		if c, err := strconv.Atoi(fields[1]); err == nil && c >= minStatusCode && c <= maxStatusCode {
			resp.Status = c
		}
	}
	if len(fields) == 3 {
		resp.Reason = cleanReason(fields[2])
	}
	for _, l := range head[1:] {
		if name, value, ok := strings.Cut(l, ":"); ok {
			resp.Headers = appendHeader(resp.Headers, name, strings.TrimSpace(value))
		}
	}
	resp.Body, resp.BodyEncoding, resp.BodyTruncated, resp.BodySize = capBody(body)
	return resp, true
}

// splitHTTPMessage returns the start line and header lines, and the body.
func splitHTTPMessage(raw string) ([]string, string, bool) {
	raw = strings.TrimLeft(raw, "\r\n")
	if raw == "" {
		return nil, "", false
	}
	head, body := raw, ""
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		head, body = raw[:i], raw[i+4:]
	} else if i := strings.Index(raw, "\n\n"); i >= 0 {
		head, body = raw[:i], raw[i+2:]
	}
	lines := strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n")
	if len(lines[0]) > MaxEvidenceURLBytes+64 {
		return nil, "", false
	}
	return lines, body, true
}

func resolveTarget(target, baseURL string, headers []EvidenceHeader) string {
	if strings.Contains(target, "://") || !strings.HasPrefix(target, "/") {
		return target
	}
	scheme, host := "http", ""
	if base, err := url.Parse(baseURL); err == nil && base.Host != "" {
		scheme, host = base.Scheme, base.Host
	}
	for _, h := range headers {
		if host == "" && strings.EqualFold(h.Name, "host") {
			host = h.Value
		}
	}
	if host == "" {
		return target
	}
	return scheme + "://" + host + target
}

func appendHeader(hs []EvidenceHeader, name, value string) []EvidenceHeader {
	name = strings.TrimSpace(name)
	if len(hs) >= MaxEvidenceHeaders || !headerNameRE.MatchString(name) {
		return hs
	}
	value = cutUTF8(stripControl(value), MaxEvidenceHeaderBytes)
	total := 0
	for _, h := range hs {
		total += len(h.Name) + len(h.Value)
	}
	if total+len(name)+len(value) > maxEvidenceHeaderTotal {
		return hs
	}
	return append(hs, EvidenceHeader{Name: name, Value: value})
}

// capBody keeps the head of a body: as text when it is UTF-8, else base64.
func capBody(body string) (string, string, bool, int64) {
	if body == "" {
		return "", "", false, 0
	}
	size := int64(len(body))
	if utf8.ValidString(body) {
		cut := cutUTF8(body, MaxEvidenceBodyBytes)
		return cut, BodyEncodingText, len(cut) < len(body), size
	}
	n := MaxEvidenceBodyBytes / 4 * 3
	if len(body) < n {
		n = len(body)
	}
	return base64.StdEncoding.EncodeToString([]byte(body[:n])), BodyEncodingBase64, n < len(body), size
}

// FitEvidenceItem shrinks an http_exchange item until it serializes under
// MaxEvidenceItemBytes (JSON escaping can make a body up to six times
// longer), halving the larger body first and marking it truncated.
func FitEvidenceItem(it *EvidenceItem) {
	for i := 0; i < 16; i++ {
		raw, err := json.Marshal(it)
		if err != nil || len(raw) <= MaxEvidenceItemBytes || it.HTTP == nil {
			return
		}
		var body *string
		var truncated *bool
		var enc string
		if r := it.HTTP.Response; r != nil && r.Body != "" {
			body, truncated, enc = &r.Body, &r.BodyTruncated, r.BodyEncoding
		}
		if r := it.HTTP.Request; r != nil && (body == nil || len(r.Body) > len(*body)) && r.Body != "" {
			body, truncated, enc = &r.Body, &r.BodyTruncated, r.BodyEncoding
		}
		if body == nil {
			it.Text = cutUTF8(it.Text, len(it.Text)/2)
			continue
		}
		n := len(*body) / 2
		if enc == BodyEncodingBase64 {
			n -= n % 4
			*body = (*body)[:n]
		} else {
			*body = cutUTF8(*body, n)
		}
		*truncated = true
	}
}

// MarkSensitive adds sensitive spans to the items for the values of
// sensitive headers, of sensitive query, form and JSON members of request
// URLs and bodies, and for every other place in the items that repeats one
// of those values (a curl command repeating the Cookie header). Values are
// marked, never masked; spans already present are kept.
func MarkSensitive(items ...*EvidenceItem) {
	values := map[string]string{} // value -> span kind
	for _, it := range items {
		if it == nil || it.HTTP == nil {
			continue
		}
		if r := it.HTTP.Request; r != nil {
			for k, h := range r.Headers {
				if IsSensitiveHeader(h.Name) && h.Value != "" {
					addSpan(it, "/http/request/headers/"+strconv.Itoa(k)+"/value", nil, nil, spanKindOf(h.Name))
					collectHeaderValues(values, h)
				}
			}
			markParams(it, "/http/request/url", queryOf(r.URL), queryOffset(r.URL), values)
			markParams(it, "/http/request/body", r.Body, 0, values)
		}
		if r := it.HTTP.Response; r != nil {
			for k, h := range r.Headers {
				if IsSensitiveHeader(h.Name) && h.Value != "" {
					addSpan(it, "/http/response/headers/"+strconv.Itoa(k)+"/value", nil, nil, spanKindOf(h.Name))
					collectHeaderValues(values, h)
				}
			}
		}
	}
	if len(values) == 0 {
		return
	}
	keys := make([]string, 0, len(values))
	for v := range values {
		if len(v) >= minRedactLen {
			keys = append(keys, v)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		return len(keys[i]) > len(keys[j]) || (len(keys[i]) == len(keys[j]) && keys[i] < keys[j])
	})
	for _, it := range items {
		if it == nil {
			continue
		}
		for ptr, s := range evidenceStrings(it) {
			if wholeMarked(it, ptr) {
				continue
			}
			for _, v := range keys {
				for from := 0; ; {
					i := strings.Index(s[from:], v)
					if i < 0 {
						break
					}
					start, end := from+i, from+i+len(v)
					addSpan(it, ptr, &start, &end, values[v])
					from = end
				}
			}
		}
	}
}

func spanKindOf(header string) string {
	switch n := strings.ToLower(header); n {
	case "authorization", "proxy-authorization":
		return "authorization"
	case "cookie", "set-cookie":
		return "cookie"
	}
	return "secret"
}

// collectHeaderValues records the value of a sensitive header and, for an
// Authorization header, its credential without the scheme, and for a
// cookie, each cookie value.
func collectHeaderValues(values map[string]string, h EvidenceHeader) {
	kind := spanKindOf(h.Name)
	values[h.Value] = kind
	switch kind {
	case "authorization":
		if _, cred, ok := strings.Cut(h.Value, " "); ok && strings.TrimSpace(cred) != "" {
			values[strings.TrimSpace(cred)] = kind
		}
	case "cookie":
		v := h.Value
		if strings.EqualFold(h.Name, "set-cookie") {
			v, _, _ = strings.Cut(v, ";")
		}
		for _, part := range strings.Split(v, ";") {
			if _, val, ok := strings.Cut(strings.TrimSpace(part), "="); ok && val != "" {
				values[val] = kind
			}
		}
	}
}

func queryOf(u string) string {
	if i := strings.IndexByte(u, '?'); i >= 0 {
		q := u[i+1:]
		if j := strings.IndexByte(q, '#'); j >= 0 {
			q = q[:j]
		}
		return q
	}
	return ""
}

func queryOffset(u string) int {
	if i := strings.IndexByte(u, '?'); i >= 0 {
		return i + 1
	}
	return 0
}

// markParams marks the values of sensitive members of a query or form
// string (a=b&c=d) and of a JSON text ("a":"b").
func markParams(it *EvidenceItem, ptr, s string, offset int, values map[string]string) {
	if s == "" {
		return
	}
	pos := 0
	for _, pair := range strings.Split(s, "&") {
		name, val, ok := strings.Cut(pair, "=")
		if ok && val != "" && IsSensitiveParam(unescapeName(name)) && !strings.ContainsAny(name, "{}\" \n") {
			start := offset + pos + len(name) + 1
			end := start + len(val)
			addSpan(it, ptr, &start, &end, "secret")
			values[val] = "secret"
		}
		pos += len(pair) + 1
	}
	for _, m := range jsonMemberRE.FindAllStringSubmatchIndex(s, -1) {
		if IsSensitiveParam(s[m[2]:m[3]]) && m[5] > m[4] {
			start, end := offset+m[4], offset+m[5]
			addSpan(it, ptr, &start, &end, "secret")
			values[s[m[4]:m[5]]] = "secret"
		}
	}
}

func unescapeName(n string) string {
	if u, err := url.QueryUnescape(n); err == nil {
		return u
	}
	return n
}

func addSpan(it *EvidenceItem, ptr string, start, end *int, kind string) {
	for _, s := range it.Sensitive {
		if s.Pointer == ptr && eqIntPtr(s.Start, start) && eqIntPtr(s.End, end) {
			return
		}
	}
	if len(it.Sensitive) >= MaxEvidenceSpans {
		return
	}
	it.Sensitive = append(it.Sensitive, SensitiveSpan{Pointer: ptr, Start: start, End: end, Kind: kind})
}

func eqIntPtr(a, b *int) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func wholeMarked(it *EvidenceItem, ptr string) bool {
	for _, s := range it.Sensitive {
		if s.Pointer == ptr && s.Start == nil && s.End == nil {
			return true
		}
	}
	return false
}

// evidenceStrings maps the JSON pointer of every string of an item (but
// its sensitive list) to the string.
func evidenceStrings(it *EvidenceItem) map[string]string {
	out := map[string]string{}
	raw, err := json.Marshal(it)
	if err != nil {
		return out
	}
	var doc any
	if json.Unmarshal(raw, &doc) != nil {
		return out
	}
	var walk func(v any, ptr string, depth int)
	walk = func(v any, ptr string, depth int) {
		if depth > maxRedactDepth {
			return
		}
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				if ptr == "" && k == "sensitive" {
					continue
				}
				walk(e, ptr+"/"+escapePointer(k), depth+1)
			}
		case []any:
			for i, e := range x {
				walk(e, ptr+"/"+strconv.Itoa(i), depth+1)
			}
		case string:
			out[ptr] = x
		}
	}
	walk(doc, "", 0)
	return out
}

func httpToken(s string) string {
	if httpTokenRE.MatchString(s) {
		return s
	}
	return ""
}

func httpVersion(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "HTTP/2.0" {
		s = "HTTP/2"
	}
	if httpVersionRE.MatchString(s) {
		return s
	}
	return ""
}

func cleanURL(s string) string {
	return cutUTF8(stripControl(strings.TrimSpace(s)), MaxEvidenceURLBytes)
}

func cleanReason(s string) string {
	return cutUTF8(stripControl(strings.TrimSpace(s)), 128)
}

func stripControl(s string) string {
	if !hasControlRune(s) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if hasControlRune(string(r)) {
			return -1
		}
		return r
	}, s)
}

// cutUTF8 cuts s to at most n bytes on a rune boundary.
func cutUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// sarifHTTPExchange builds an http_exchange item from a SARIF result's
// webRequest and webResponse, capped and with sensitive values marked.
func sarifHTTPExchange(req *SARIFWebRequest, resp *SARIFWebResponse) (EvidenceItem, bool) {
	it := EvidenceItem{Kind: EvidenceKindHTTPExchange, Version: 1, HTTP: &EvidenceHTTP{}}
	if req != nil && (req.Target != "" || req.Method != "") {
		r := &EvidenceRequest{
			Method:      httpToken(req.Method),
			URL:         cleanURL(req.Target),
			HTTPVersion: httpVersion(sarifProtocol(req.Protocol, req.Version)),
		}
		for _, k := range sortedMapKeys(req.Headers) {
			r.Headers = appendHeader(r.Headers, k, req.Headers[k])
		}
		r.Body, r.BodyEncoding, r.BodyTruncated, r.BodySize = sarifBody(req.Body)
		it.HTTP.Request = r
	}
	if resp != nil && !resp.NoResponseReceived && (resp.StatusCode != 0 || len(resp.Headers) > 0 || resp.Body != nil) {
		r := &EvidenceResponse{
			Reason:      cleanReason(resp.ReasonPhrase),
			HTTPVersion: httpVersion(sarifProtocol(resp.Protocol, resp.Version)),
		}
		if resp.StatusCode >= minStatusCode && resp.StatusCode <= maxStatusCode {
			r.Status = resp.StatusCode
		}
		for _, k := range sortedMapKeys(resp.Headers) {
			r.Headers = appendHeader(r.Headers, k, resp.Headers[k])
		}
		r.Body, r.BodyEncoding, r.BodyTruncated, r.BodySize = sarifBody(resp.Body)
		it.HTTP.Response = r
	}
	if it.HTTP.Request == nil && it.HTTP.Response == nil {
		return EvidenceItem{}, false
	}
	FitEvidenceItem(&it)
	MarkSensitive(&it)
	return it, true
}

func sarifProtocol(protocol, version string) string {
	if protocol == "" || version == "" {
		return ""
	}
	return strings.ToUpper(protocol) + "/" + version
}

func sarifBody(c *SARIFContent) (string, string, bool, int64) {
	if c == nil {
		return "", "", false, 0
	}
	if c.Text != "" {
		return capBody(c.Text)
	}
	if raw, err := base64.StdEncoding.DecodeString(c.Binary); err == nil && len(raw) > 0 {
		return capBody(string(raw))
	}
	return "", "", false, 0
}

func sortedMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
