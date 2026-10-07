package ctis

import (
	"path"
	"strings"

	"github.com/openctemio/ctis/weburl"
)

// Endpoints from crawl results (CTIS 1.6). A crawl reports one URL per
// fetch; the endpoints are one per origin, method and path template, with
// the query parameter names of every URL that fell into it. The legacy
// discovered_url assets are still emitted, redacted, for one release train.

// endpointKey is the dedup key of a crawled endpoint.
func endpointKey(origin, method, template string) string {
	return origin + "\n" + weburl.PathHash(method, template)
}

var staticExtensions = map[string]bool{
	".css": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".ico": true,
	".webp": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".otf": true, ".map": true,
	".mp4": true, ".webm": true, ".mp3": true, ".pdf": true, ".zip": true,
}

// crawlKind maps a crawler's type label and the path extension to a kind.
func crawlKind(typ, p string) EndpointKind {
	if k := EndpointKind(strings.ToLower(strings.TrimSpace(typ))); validEnum(k, AllEndpointKinds()) {
		return k
	}
	ext := strings.ToLower(path.Ext(p))
	switch {
	case ext == ".js" || ext == ".mjs":
		return EndpointKindScript
	case staticExtensions[ext]:
		return EndpointKindStatic
	}
	return EndpointKindPage
}

// crawlSource maps a crawler's source label (katana: href, script, form,
// jsluice, robotstxt, sitemapxml, ...) to an endpoint source.
func crawlSource(s string) EndpointSource {
	s = strings.ToLower(s)
	switch {
	case strings.Contains(s, "robots"):
		return EndpointSourceRobots
	case strings.Contains(s, "sitemap"):
		return EndpointSourceSitemap
	case strings.Contains(s, "js") || strings.Contains(s, "script"):
		return EndpointSourceJS
	case strings.Contains(s, "archive") || strings.Contains(s, "wayback"):
		return EndpointSourceArchive
	}
	return EndpointSourceCrawl
}

// convertCrawlEndpoints appends the endpoints of the crawled URLs to the
// report. URLs that do not parse (other schemes, hostile hosts) are left to
// the legacy assets only.
func convertCrawlEndpoints(report *Report, urls []DiscoveredURLInput) {
	index := map[string]int{}
	for _, u := range urls {
		if len(report.Endpoints) >= MaxEndpoints {
			return
		}
		pu, err := weburl.Parse(u.URL)
		if err != nil {
			continue
		}
		method := "GET"
		if u.Method != "" {
			m, ok := weburl.NormalizeMethod(u.Method)
			if !ok {
				continue
			}
			method = m
		}
		origin, tmpl := pu.Origin(), pu.Template()
		key := endpointKey(origin, method, tmpl)
		i, ok := index[key]
		if !ok {
			ep := Endpoint{
				Origin:   origin,
				Method:   method,
				Path:     pu.Path,
				Template: tmpl,
				Kind:     crawlKind(u.Type, pu.Path),
				Source:   crawlSource(u.Source),
			}
			if validStatus(u.StatusCode) {
				ep.StatusCode = u.StatusCode
			}
			if ct := cleanLine(u.ContentType); ct != "" && !tooLong(ct, MaxContentTypeLen) {
				ep.ContentType = ct
			}
			if u.Parent != "" {
				if p := weburl.RedactURL(u.Parent); redactedURL(p) {
					ep.Parent = p
				}
			}
			report.Endpoints = append(report.Endpoints, ep)
			i = len(report.Endpoints) - 1
			index[key] = i
		}
		ep := &report.Endpoints[i]
		for _, n := range pu.Params {
			addEndpointParam(ep, ParamLocationQuery, n)
		}
		for _, p := range u.Params {
			if validEnum(p.Location, AllParamLocations()) {
				addEndpointParam(ep, p.Location, p.Name)
			}
		}
	}
}

func addEndpointParam(ep *Endpoint, loc ParamLocation, name string) {
	if !validParamName(name) || len(ep.Params) >= MaxEndpointParams {
		return
	}
	for _, p := range ep.Params {
		if p.Location == loc && p.Name == name {
			return
		}
	}
	ep.Params = append(ep.Params, EndpointParam{Location: loc, Name: name})
}

// mergeEndpoints appends src's endpoints to dst's, one per origin, method
// and template, with their parameters combined.
func mergeEndpoints(dst []Endpoint, index map[string]int, src []Endpoint) []Endpoint {
	for _, e := range src {
		key := endpointKey(e.Origin, e.Method, weburl.TemplatePath(e.Path))
		if i, ok := index[key]; ok {
			for _, p := range e.Params {
				addEndpointParam(&dst[i], p.Location, p.Name)
			}
			continue
		}
		if len(dst) >= MaxEndpoints {
			continue
		}
		e.ID, e.OriginRef = "", "" // ids are per report
		e.Params = append([]EndpointParam(nil), e.Params...)
		e.Technologies = append([]Technology(nil), e.Technologies...)
		dst = append(dst, e)
		index[key] = len(dst) - 1
	}
	return dst
}
