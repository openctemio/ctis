package ctis

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/ctis/weburl"
)

// httpx JSON lines to LiveHostInput. One mapper serves a scan (a sensor
// wrapping httpx) and an import (a results directory that holds httpx
// output), so both produce the same facts from the same line.
//
// A line is hostile input: the target chose every value. The mapper keeps
// only the fields listed in HTTPXLineFields, bounds each one, refuses a URL
// that is not a plain http or https URL, and never keeps a response body,
// header value, request or hash.

// MaxHTTPXLineBytes is the longest line ParseHTTPXLine reads.
const MaxHTTPXLineBytes = 1 << 20

// maxHTTPXDepth is the deepest nesting of a line that is decoded.
const maxHTTPXDepth = 16

// ErrHTTPXLine is the error of a line that is not a usable httpx result.
var ErrHTTPXLine = errors.New("not a usable httpx result line")

func httpxErr(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrHTTPXLine}, args...)...)
}

type httpxTLS struct {
	Version     string   `json:"tls_version"`
	SubjectCN   string   `json:"subject_cn"`
	SubjectAN   []string `json:"subject_an"`
	IssuerCN    string   `json:"issuer_cn"`
	IssuerOrg   []string `json:"issuer_org"`
	Fingerprint struct {
		SHA256 string `json:"sha256"`
	} `json:"fingerprint_hash"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	SelfSigned bool   `json:"self_signed"`
	Mismatched bool   `json:"mismatched"`
	Expired    bool   `json:"expired"`
	Wildcard   bool   `json:"wildcard_certificate"`
}

type httpxASN struct {
	Number  string `json:"as_number"`
	Name    string `json:"as_name"`
	Country string `json:"as_country"`
}

type httpxLine struct {
	URL           string          `json:"url"`
	Input         string          `json:"input"`
	HostIP        string          `json:"host_ip"`
	Host          string          `json:"host"`
	Port          json.RawMessage `json:"port"` // the URL carries the port
	Scheme        string          `json:"scheme"`
	StatusCode    int             `json:"status_code"`
	ContentLength int64           `json:"content_length"`
	Title         string          `json:"title"`
	WebServer     string          `json:"webserver"`
	ContentType   string          `json:"content_type"`
	Tech          []string        `json:"tech"`
	CDN           bool            `json:"cdn"`
	CDNName       string          `json:"cdn_name"`
	CDNType       string          `json:"cdn_type"`
	Time          string          `json:"time"`
	Location      string          `json:"location"`
	Favicon       string          `json:"favicon"`
	JARM          string          `json:"jarm"`
	Failed        bool            `json:"failed"`
	TLS           *httpxTLS       `json:"tls"`
	ASN           *httpxASN       `json:"asn"`
}

// ParseHTTPXLine maps one line of httpx -json output to a LiveHostInput.
//
// observe, when set, receives the path of every member the line holds
// ("/url", "/tls/subject_cn", ...), mapped or not, so a caller can report
// the members it did not read. The returned error wraps ErrHTTPXLine.
func ParseHTTPXLine(line []byte, observe func(path string)) (LiveHostInput, error) {
	var zero LiveHostInput
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return zero, httpxErr("empty line")
	}
	if len(line) > MaxHTTPXLineBytes {
		return zero, httpxErr("longer than %d bytes", MaxHTTPXLineBytes)
	}
	if line[0] != '{' {
		return zero, httpxErr("not a JSON object")
	}
	if !jsonDepthWithin(line, maxHTTPXDepth) {
		return zero, httpxErr("nested deeper than %d", maxHTTPXDepth)
	}
	if bytes.IndexByte(line, 0) >= 0 {
		return zero, httpxErr("contains a NUL byte")
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(line, &members); err != nil {
		return zero, httpxErr("not valid JSON")
	}
	if observe != nil {
		for k, v := range members {
			observe("/" + pathKeySafe(k))
			if (k == "tls" || k == "asn") && len(v) > 0 && v[0] == '{' {
				var sub map[string]json.RawMessage
				if json.Unmarshal(v, &sub) == nil {
					for sk := range sub {
						observe("/" + k + "/" + pathKeySafe(sk))
					}
				}
			}
		}
	}
	var h httpxLine
	if err := json.Unmarshal(line, &h); err != nil {
		return zero, httpxErr("a member has the wrong type")
	}
	if h.Failed {
		return zero, httpxErr("the probe failed")
	}
	raw := strings.TrimSpace(h.URL)
	if raw == "" {
		return zero, httpxErr("no url")
	}
	pu, err := weburl.Parse(raw)
	if err != nil {
		return zero, httpxErr("url refused: %v", err)
	}
	out := LiveHostInput{
		URL:    pu.Origin(),
		Host:   pu.Host,
		Scheme: pu.Scheme,
		Port:   defaultPort(pu.Scheme, pu.Port),
	}
	if pu.Path != "/" {
		out.URL += pu.Path
	}
	// httpx writes the address in "host_ip" (and, in newer releases, in
	// "host" too).
	for _, c := range []string{h.HostIP, h.Host} {
		if ip := net.ParseIP(strings.TrimSpace(c)); ip != nil {
			out.IP = ip.String()
			break
		}
	}
	if validStatus(h.StatusCode) {
		out.StatusCode = h.StatusCode
	}
	if h.ContentLength > 0 {
		out.ContentLength = h.ContentLength
	}
	out.Title = boundLine(spaced(h.Title), 512)
	out.WebServer = boundLine(spaced(h.WebServer), 255)
	if ct := boundLine(h.ContentType, MaxContentTypeLen); ct != "" {
		out.ContentType = ct
	}
	for _, t := range h.Tech {
		if t = boundLine(t, 128); t != "" && len(out.Technologies) < 100 {
			out.Technologies = append(out.Technologies, t)
		}
	}
	if h.CDN || h.CDNName != "" {
		out.CDN = boundLine(h.CDNName, maxProviderLen)
		out.CDNType = strings.ToLower(boundLine(h.CDNType, 16))
	}
	if d, err := time.ParseDuration(strings.TrimSpace(h.Time)); err == nil && d > 0 {
		out.ResponseTime = d.Milliseconds()
	}
	if loc := strings.TrimSpace(h.Location); loc != "" {
		if lu, err := weburl.Parse(loc); err == nil {
			out.Redirect = lu.Origin() + lu.Path
		}
	}
	out.FaviconMMH3 = strings.TrimSpace(h.Favicon)
	out.JARM = strings.TrimSpace(h.JARM)
	if a := h.ASN; a != nil && a.Number != "" {
		out.ASN = &ASNInput{Number: boundLine(a.Number, 16), Org: boundLine(a.Name, maxASNOrgLen), Country: boundLine(a.Country, 2)}
	}
	if t := h.TLS; t != nil {
		out.TLSVersion = boundLine(t.Version, 16)
		if fp := sha256Fingerprint(t.Fingerprint.SHA256); fp != "" {
			leaf := &TLSLeafInput{
				SubjectCN:         t.SubjectCN,
				SANs:              t.SubjectAN,
				IssuerCN:          t.IssuerCN,
				FingerprintSHA256: fp,
				SelfSigned:        t.SelfSigned,
				Expired:           t.Expired,
				Wildcard:          t.Wildcard,
				Mismatched:        t.Mismatched,
			}
			if len(t.IssuerOrg) > 0 {
				leaf.IssuerOrg = t.IssuerOrg[0]
			}
			leaf.NotBefore, _ = time.Parse(time.RFC3339, t.NotBefore)
			leaf.NotAfter, _ = time.Parse(time.RFC3339, t.NotAfter)
			out.TLS = leaf
		}
	}
	return out, nil
}

func defaultPort(scheme, port string) int {
	if port != "" {
		if n, err := strconv.Atoi(port); err == nil {
			return n
		}
	}
	if scheme == "https" {
		return 443
	}
	return 80
}

// pathKeySafe makes a member name safe to use as a path segment: slashes and
// control characters are replaced, and the name is cut.
func pathKeySafe(k string) string {
	k = strings.Map(func(r rune) rune {
		if r == '/' || r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, k)
	if len(k) > 64 {
		k = truncateUTF8(k, 64)
	}
	return k
}

// jsonDepthWithin reports whether b nests objects and arrays at most max deep.
// It reads bytes only: strings and escapes are skipped, nothing is decoded.
func jsonDepthWithin(b []byte, max int) bool {
	depth, inStr, esc := 0, false, false
	for _, c := range b {
		switch {
		case inStr:
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
		case c == '"':
			inStr = true
		case c == '{' || c == '[':
			depth++
			if depth > max {
				return false
			}
		case c == '}' || c == ']':
			depth--
		}
	}
	return true
}

// spaced turns every run of white space (tabs and line breaks included) into
// one space, so cleaning control characters does not glue words together.
func spaced(s string) string { return strings.Join(strings.Fields(s), " ") }
