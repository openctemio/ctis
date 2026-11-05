package importer

import (
	"encoding/json"
	"io"
	"strconv"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/weburl"
)

// ffuf JSON output (-of json). Every result is a URL that answered: its
// origin is a web_origin asset and the URL an endpoint of it (parameter
// names only), with the status code and content type. The command line and
// the configuration are never read: they hold the headers, cookies and
// tokens the person gave ffuf. The fuzzed words (input) are not kept
// either. An inventory format: no findings. The mapping is spec_ffuf.go.

func init() {
	parsers[FormatFfuf] = parseFfuf
	tools[FormatFfuf] = ctis.Tool{Name: "ffuf", InfoURL: "https://github.com/ffuf/ffuf", Techniques: []ctis.Technique{ctis.TechniqueDAST}}
}

type ffufResult struct {
	Status      int    `json:"status"`
	ContentType string `json:"content-type"`
	URL         string `json:"url"`
}

func parseFfuf(b *Builder, r io.Reader) error {
	data, err := readAll(r, FormatFfuf, b.lim)
	if err != nil {
		return err
	}
	doc, err := scanJSON(data, FormatFfuf, b.lim, b.obs, "/results[]")
	if err != nil {
		return err
	}
	// Only the results are decoded: config and commandline stay raw bytes
	// nobody reads.
	var top struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := doc.decode(&top); err != nil {
		return err
	}
	var urls []ctis.DiscoveredURLInput
	for i, raw := range top.Results {
		b.res.Stats.Records++
		if err := b.tick(); err != nil {
			return err
		}
		ptr := "/results/" + strconv.Itoa(i)
		var res ffufResult
		if err := json.Unmarshal(raw, &res); err != nil {
			b.issue(doc.issueAt("/results[]", i, ptr, "skipped: "+jsonErrText(err)))
			b.res.Stats.Skipped++
			continue
		}
		u := stripUserinfo(res.URL)
		pu, err := weburl.Parse(u)
		if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") {
			b.issue(doc.issueAt("/results[]", i, ptr, "result without a usable http(s) URL: skipped"))
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
		if len(urls) < 5*b.lim.MaxEndpoints {
			urls = append(urls, ctis.DiscoveredURLInput{URL: u, Source: string(ctis.EndpointSourceImport), StatusCode: res.Status, ContentType: line(res.ContentType, 128)})
		}
	}
	b.addEndpoints(urls)
	b.stampImportScope()
	return nil
}
