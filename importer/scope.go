package importer

import (
	"net"
	"strings"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/weburl"
)

// extImportScope is the io.openctem extension key of the scope verdict of an
// imported host.
const extImportScope = "import_scope"

// Import scope verdicts.
const (
	scopeInTarget      = "in_target"
	scopeOutsideTarget = "outside_target"
	scopeUnknown       = "unknown"
)

// stampImportScope marks every host-bearing asset of the report (a name, an
// address, a host, a storage bucket, a web origin) with an import_scope
// verdict relative to Options.ScopeDomains. A format whose records come
// from a tool a person ran, not from a job, calls it last: the receiver
// then judges each host against the organization's scope instead of taking
// every host as its own.
func (b *Builder) stampImportScope() {
	for i := range b.res.Report.Assets {
		a := &b.res.Report.Assets[i]
		host := a.Value
		switch a.Type {
		case ctis.AssetTypeDomainName, ctis.AssetTypeIPAddress, ctis.AssetTypeIPRange, ctis.AssetTypeHost, ctis.AssetTypeStorage:
		case ctis.AssetTypeWebOrigin:
			u, err := weburl.Parse(a.Value)
			if err != nil {
				continue
			}
			host = u.Host
		default:
			continue
		}
		a.Extensions.Set(ctis.OpenCTEMNamespace, extImportScope, scopeVerdict(b.opts.ScopeDomains, host))
	}
}

// scopeVerdict is the verdict of host against the scope domains.
func scopeVerdict(scope []string, host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if len(scope) == 0 || net.ParseIP(host) != nil || strings.Contains(host, "/") {
		return scopeUnknown
	}
	for _, d := range scope {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d != "" && (host == d || strings.HasSuffix(host, "."+d)) {
			return scopeInTarget
		}
	}
	return scopeOutsideTarget
}

// dropReceiverExtensions removes the io.openctem namespace (the receiver
// profile: scope verdicts, candidate exposures, web content, CDN facts) from
// the report and from every asset, finding and endpoint. A document a person
// uploads may not say that a host is in scope or that an exposure was
// verified; the importer and the receiver set those members.
func dropReceiverExtensions(r *ctis.Report) {
	delete(r.Extensions, ctis.OpenCTEMNamespace)
	delete(r.Metadata.Extensions, ctis.OpenCTEMNamespace)
	for i := range r.Endpoints {
		delete(r.Endpoints[i].Extensions, ctis.OpenCTEMNamespace)
	}
	for i := range r.Assets {
		delete(r.Assets[i].Extensions, ctis.OpenCTEMNamespace)
	}
	for i := range r.Findings {
		delete(r.Findings[i].Extensions, ctis.OpenCTEMNamespace)
	}
}
