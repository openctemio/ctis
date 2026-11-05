package importer

import (
	"encoding/json"
	"io"
	"sort"
	"strings"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/weburl"
)

// arjun JSON output (-oJ): an object keyed by URL, each with the method
// arjun used and the parameter names it found. Every URL's origin is a
// web_origin asset and the URL an endpoint of it with those parameter
// names (query for GET, form for POST, json for JSON, a body parameter for
// XML). The request headers arjun sent are never read: they hold the
// person's cookies and tokens. An inventory format: no findings. The
// mapping is spec_arjun.go.

func init() {
	parsers[FormatArjun] = parseArjun
	tools[FormatArjun] = ctis.Tool{Name: "arjun", InfoURL: "https://github.com/s0md3v/Arjun", Techniques: []ctis.Technique{ctis.TechniqueDAST}}
}

// maxArjunParams bounds the parameter names kept per endpoint.
const maxArjunParams = 200

func parseArjun(b *Builder, r io.Reader) error {
	data, err := readAll(r, FormatArjun, b.lim)
	if err != nil {
		return err
	}
	doc, err := scanJSON(data, FormatArjun, b.lim, b.obs)
	if err != nil {
		return err
	}
	var top map[string]json.RawMessage
	if err := doc.decode(&top); err != nil {
		return err
	}
	keys := make([]string, 0, len(top))
	for k := range top {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var urls []ctis.DiscoveredURLInput
	for _, k := range keys {
		b.res.Stats.Records++
		if err := b.tick(); err != nil {
			return err
		}
		var rec struct {
			Method string   `json:"method"`
			Params []string `json:"params"`
		}
		if err := json.Unmarshal(top[k], &rec); err != nil {
			b.issue(Issue{Path: "/" + line(k, 200), Message: "skipped: " + jsonErrText(err)})
			b.res.Stats.Skipped++
			continue
		}
		u := stripUserinfo(k)
		pu, err := weburl.Parse(u)
		if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") {
			b.issue(Issue{Path: "/" + line(k, 200), Message: "key is not a usable http(s) URL: skipped"})
			b.res.Stats.Skipped++
			continue
		}
		o, err := ctis.CanonicalOrigin(pu.Origin())
		if err != nil {
			b.res.Stats.Skipped++
			continue
		}
		a := ctis.Asset{Type: ctis.AssetTypeWebOrigin, Value: o, Name: o}
		if b.opts.DefaultConfidence > 0 {
			a.Confidence = b.opts.DefaultConfidence
		}
		id, err := b.asset(a)
		if err != nil {
			return err
		}
		if id == "" {
			b.res.Stats.Skipped++
			continue
		}
		method, loc := "GET", ctis.ParamLocationQuery
		switch strings.ToUpper(strings.TrimSpace(rec.Method)) {
		case "POST":
			method, loc = "POST", ctis.ParamLocationForm
		case "JSON":
			method, loc = "POST", ctis.ParamLocationJSON
		case "XML":
			method, loc = "POST", ctis.ParamLocationForm
		}
		in := ctis.DiscoveredURLInput{URL: u, Method: method, Source: string(ctis.EndpointSourceImport)}
		seen := map[string]bool{}
		for _, p := range rec.Params {
			p = line(p, 128)
			if p == "" || seen[p] || len(in.Params) >= maxArjunParams {
				continue
			}
			seen[p] = true
			in.Params = append(in.Params, ctis.EndpointParam{Location: loc, Name: p})
		}
		if len(urls) < 5*b.lim.MaxEndpoints {
			urls = append(urls, in)
		}
	}
	b.addEndpoints(urls)
	b.stampImportScope()
	return nil
}
