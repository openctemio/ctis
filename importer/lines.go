package importer

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/weburl"
)

// A line list: one value per line, as the plain output of name, address and
// URL tools prints it (gau, waymore, puredns, massdns -o S, subfinder and
// dnsx without -json, crlfuzz -o, dnstake -o). The mapping is
// spec_lines.go. A list is never detected: any text would look like one.

// What each line of a line list names (Options.LinesAs).
const (
	LinesAsAuto   = "auto"
	LinesAsHost   = "host"
	LinesAsDomain = "domain"
	LinesAsIP     = "ip"
	LinesAsURL    = "url"
)

// LinesAsValues lists the values of Options.LinesAs.
func LinesAsValues() []string {
	return []string{LinesAsAuto, LinesAsHost, LinesAsDomain, LinesAsIP, LinesAsURL}
}

func init() {
	parsers[FormatLines] = parseLines
	tools[FormatLines] = ctis.Tool{Name: "lines", Techniques: []ctis.Technique{ctis.TechniqueEASM}}
}

func parseLines(b *Builder, r io.Reader) error {
	as := strings.ToLower(strings.TrimSpace(b.opts.LinesAs))
	if as == "" {
		as = LinesAsAuto
	}
	valid := false
	for _, v := range LinesAsValues() {
		valid = valid || v == as
	}
	if !valid {
		return &ParseError{Format: FormatLines, Msg: fmt.Sprintf("Options.LinesAs %q is not one of %s", line(as, 32), strings.Join(LinesAsValues(), ", ")), Err: ErrMalformed}
	}
	bl := DefaultBundleLimits()
	var urls []ctis.DiscoveredURLInput
	var readErr error
	err := eachTextLine(b, "/line", newCapReader(r, b.lim.MaxInputBytes), bl.MaxLineBytes, bl.MaxLines, func(l string) bool {
		b.obs.add("/line")
		if strings.HasPrefix(l, "#") {
			// A comment counts as a skipped line, never a value.
			return false
		}
		tok := l
		if i := strings.IndexAny(tok, " \t"); i > 0 {
			tok = tok[:i]
		}
		kind := as
		if kind == LinesAsAuto {
			kind = lineKind(tok)
		}
		var a ctis.Asset
		switch kind {
		case LinesAsURL:
			// Credentials in a URL are never kept.
			tok = stripUserinfo(tok)
			u, err := weburl.Parse(tok)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
				return false
			}
			o, err := ctis.CanonicalOrigin(u.Origin())
			if err != nil {
				return false
			}
			a = ctis.Asset{Type: ctis.AssetTypeWebOrigin, Value: o}
			if len(urls) < 5*b.lim.MaxEndpoints {
				urls = append(urls, ctis.DiscoveredURLInput{URL: tok, Source: string(ctis.EndpointSourceImport)})
			}
		case LinesAsIP:
			var ok bool
			if a, ok = addressAsset(tok); !ok {
				return false
			}
		case LinesAsDomain:
			h, ok := dnsName(strings.TrimSuffix(tok, "."))
			if !ok {
				return false
			}
			a = ctis.Asset{Type: ctis.AssetTypeDomainName, Value: h}
		case LinesAsHost:
			var ok bool
			if a, ok = addressAsset(tok); ok && a.Type == ctis.AssetTypeIPAddress {
				break
			}
			h, ok := dnsName(strings.TrimSuffix(tok, "."))
			if !ok {
				return false
			}
			a = ctis.Asset{Type: ctis.AssetTypeDomainName, Value: h}
		default:
			return false
		}
		a.Name = a.Value
		if b.opts.DefaultConfidence > 0 {
			a.Confidence = b.opts.DefaultConfidence
		}
		id, err := b.asset(a)
		if err != nil {
			readErr = err
			return false
		}
		return id != ""
	})
	if readErr != nil {
		return readErr
	}
	if err != nil {
		return lineReadError(err)
	}
	b.addEndpoints(urls)
	b.stampImportScope()
	return nil
}

// lineKind names what a token is by its form.
func lineKind(tok string) string {
	switch {
	case strings.Contains(tok, "://"):
		return LinesAsURL
	case net.ParseIP(tok) != nil:
		return LinesAsIP
	}
	if _, err := netip.ParsePrefix(tok); err == nil {
		return LinesAsIP
	}
	return LinesAsDomain
}

// addressAsset is the asset of an address or a CIDR block.
func addressAsset(tok string) (ctis.Asset, bool) {
	if ip := net.ParseIP(tok); ip != nil {
		return ctis.Asset{Type: ctis.AssetTypeIPAddress, Value: ip.String()}, true
	}
	if p, err := netip.ParsePrefix(tok); err == nil {
		return ctis.Asset{Type: ctis.AssetTypeIPRange, Value: p.Masked().String()}, true
	}
	return ctis.Asset{}, false
}

// lineReadError turns a failure of the line reader into a ParseError.
func lineReadError(err error) error {
	var pe *ParseError
	if errors.As(err, &pe) {
		return pe
	}
	if errors.Is(err, ErrTooLarge) {
		return &ParseError{Format: FormatLines, Msg: err.Error(), Err: ErrTooLarge}
	}
	return &ParseError{Format: FormatLines, Msg: "read input: " + err.Error(), Err: ErrMalformed}
}

// addEndpoints converts URLs to endpoints of the report's web origins
// (names of parameters only, never values), within the endpoint limit.
func (b *Builder) addEndpoints(urls []ctis.DiscoveredURLInput) {
	if len(urls) == 0 {
		return
	}
	origins := map[string]string{}
	for _, a := range b.res.Report.Assets {
		if a.Type == ctis.AssetTypeWebOrigin {
			origins[a.Value] = a.ID
		}
	}
	eps := ctis.ConvertEndpoints(urls)
	if room := b.lim.MaxEndpoints - len(b.res.Report.Endpoints); len(eps) > room {
		b.issue(Issue{Message: fmt.Sprintf("more than %d endpoints: the rest are left out", b.lim.MaxEndpoints)})
		eps = eps[:max(room, 0)]
	}
	for i := range eps {
		eps[i].OriginRef = origins[eps[i].Origin]
		// An address in a path is personal data: the template stands for
		// it ({email}) and the concrete path is not kept.
		if strings.Contains(eps[i].Template, "{email}") {
			eps[i].Path = eps[i].Template
		}
	}
	b.res.Report.Endpoints = append(b.res.Report.Endpoints, eps...)
}
