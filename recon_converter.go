package ctis

import (
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/openctemio/ctis/v2/weburl"
)

// ReconConverterOptions configures the conversion from ReconResult to CTIS Report.
type ReconConverterOptions struct {
	// Source tracking
	DiscoverySource string // "agent", "integration", "manual"
	DiscoveryTool   string // Scanner name

	// Default values. DefaultCriticality is business context that a scanner
	// does not know (spec section 4.1); leave it empty unless the caller
	// really has it.
	DefaultCriticality Criticality
	DefaultConfidence  int // 0-100

	// Filtering
	MinConfidence int // Minimum confidence to include
}

// DefaultReconConverterOptions returns sensible default options.
func DefaultReconConverterOptions() *ReconConverterOptions {
	return &ReconConverterOptions{
		DiscoverySource:   "agent",
		DefaultConfidence: 80,
		MinConfidence:     0,
	}
}

// ReconToCTISInput holds the data from a reconnaissance scan result.
// This is a simplified version of core.ReconResult to avoid import cycles.
type ReconToCTISInput struct {
	// Scanner info
	ScannerName    string
	ScannerVersion string
	ReconType      string // subdomain, dns, port, http_probe, url_crawl

	// Target
	Target string

	// Timing
	StartedAt  int64
	FinishedAt int64
	DurationMs int64

	// Results
	Subdomains   []SubdomainInput
	DNSRecords   []DNSRecordInput
	OpenPorts    []OpenPortInput
	LiveHosts    []LiveHostInput
	URLs         []DiscoveredURLInput
	Technologies []TechnologyInput
}

// SubdomainInput represents a discovered subdomain.
type SubdomainInput struct {
	Host   string
	Domain string
	Source string
	IPs    []string
}

// DNSRecordInput represents a DNS record.
type DNSRecordInput struct {
	Host       string
	RecordType string
	Values     []string
	TTL        int
	Resolver   string
	StatusCode string
}

// OpenPortInput represents an open port.
type OpenPortInput struct {
	Host     string
	IP       string
	Port     int
	Protocol string
	Service  string
	Version  string
	Banner   string
}

// LiveHostInput represents an HTTP/HTTPS live host.
type LiveHostInput struct {
	URL           string
	Host          string
	IP            string
	Port          int
	Scheme        string
	StatusCode    int
	ContentLength int64
	Title         string
	WebServer     string
	ContentType   string
	Technologies  []string
	CDN           string
	TLSVersion    string
	Redirect      string
	ResponseTime  int64

	// CDNType is what CDN names: "cdn", "waf" or "cloud" (httpx cdn_type).
	CDNType string
	// TLS is the leaf certificate seen in the TLS handshake (httpx
	// -tls-grab); nil when the probe did not grab one.
	TLS *TLSLeafInput
	// FaviconMMH3 is the mmh3 hash of the favicon (httpx -favicon), as
	// Shodan prints it: a signed 32-bit decimal.
	FaviconMMH3 string
	// JARM is the JARM TLS server fingerprint (62 hex characters).
	JARM string
	// ASN is the autonomous system of the host's address (httpx -asn).
	ASN *ASNInput
	// ResponseHeaders is the posture subset of the response headers. The
	// converter applies the allow-list again (recon_posture.go).
	ResponseHeaders *ResponseHeadersInput
	// CNAMEs is the DNS alias chain of the host.
	CNAMEs []string
	// WebContent is the result of a web content fetch of this host's URLs
	// (see WebContentKey). It is an explicit input: ParseHTTPXLine
	// never fills it.
	WebContent []WebCaptureInput
}

// TLSLeafInput is the leaf certificate an HTTP probe saw in a TLS handshake.
// Every value comes from the scanned server and is bounded by the converter.
type TLSLeafInput struct {
	SubjectCN    string
	SANs         []string
	IssuerCN     string
	IssuerOrg    string
	SerialNumber string
	NotBefore    time.Time
	NotAfter     time.Time
	// FingerprintSHA256 is the SHA-256 of the DER certificate, hex, with or
	// without colons. It is the certificate's identity: a leaf without a
	// valid one is not converted.
	FingerprintSHA256 string
	SelfSigned        bool
	Expired           bool
	Wildcard          bool
	Mismatched        bool
}

// ASNInput is an autonomous system.
type ASNInput struct {
	Number  string // "AS13335" or "13335"
	Org     string
	Country string // ISO 3166-1 alpha-2
}

// DiscoveredURLInput represents a discovered URL/endpoint.
type DiscoveredURLInput struct {
	URL        string
	Method     string
	Source     string
	StatusCode int
	Depth      int
	Parent     string
	Type       string
	Extension  string

	// ContentType of the response (1.6 endpoints).
	ContentType string

	// Params are parameters seen besides the query: form fields, JSON
	// members, headers. Names only.
	Params []EndpointParam

	// Forms are the HTML forms of the page. Each becomes a form endpoint
	// with its field names; values are not carried.
	Forms []WebFormInput
}

// WebFormInput is one HTML form of a crawled page.
type WebFormInput struct {
	// Method is GET or POST; anything else is GET.
	Method string
	// Action is the absolute form target; empty means the page itself.
	Action string
	// Params are the field names (location form). A producer that knows
	// the input type sets TypeHint to TypeHintPassword; the converter also
	// marks fields whose name says password.
	Params []EndpointParam
}

// TechnologyInput represents a detected technology.
type TechnologyInput struct {
	Name       string
	Version    string
	Categories []string
	Confidence int
	Website    string
}

// ConvertReconToCTIS converts reconnaissance results to a CTIS report.
//
// The output follows the CTIS 2.0 asset model:
//   - names are domain_name assets (canonical form), with their DNS records
//     in technical.domain; a name that has no canonical form is skipped;
//   - a port-scan target is an ip_address asset when it is an address and a
//     host asset otherwise; each open port is a service asset
//     ("host:port/transport") linked from it by an exposes relationship;
//   - every HTTP probe result is a web_origin asset (its canonical origin)
//     with technical.http (status, title, server, TLS version, CDN, WAF,
//     JARM, favicon hash, security headers) and typed technologies; the
//     leaf certificate is a certificate asset linked by serves_certificate;
//     the address the origin answered on is an ip_address asset that the
//     origin's name resolves_to;
//   - crawled URLs are endpoints of their web_origin asset.
//
// Asset ids are unique within the report and assets keep the input order.
func ConvertReconToCTIS(input *ReconToCTISInput, opts *ReconConverterOptions) (*Report, error) {
	if input == nil {
		return nil, fmt.Errorf("recon input is nil")
	}
	o := DefaultReconConverterOptions()
	if opts != nil {
		copied := *opts
		o = &copied
	}
	if o.DiscoveryTool == "" {
		o.DiscoveryTool = input.ScannerName
	}

	report := NewReport()
	report.Metadata.DurationMs = nonNegative(input.DurationMs)
	report.Metadata.Channel = ChannelScanner
	if input.StartedAt > 0 {
		t := time.Unix(input.StartedAt, 0).UTC()
		report.Metadata.StartedAt = &t
	}
	if input.FinishedAt > 0 && input.FinishedAt >= input.StartedAt {
		t := time.Unix(input.FinishedAt, 0).UTC()
		report.Metadata.EndedAt = &t
	}
	report.Metadata.Profiles = []Profile{ProfileDiscovery}
	report.Tool = &Tool{
		Name:       input.ScannerName,
		Version:    input.ScannerVersion,
		Vendor:     reconVendor(input.ScannerName),
		Techniques: []Technique{TechniqueEASM},
	}
	g := newReconGraph(report, o)

	switch input.ReconType {
	case "subdomain":
		g.subdomains(input.Subdomains)
	case "dns":
		g.dnsRecords(input.DNSRecords)
	case "port":
		g.openPorts(input.OpenPorts)
	case "http_probe":
		g.liveHosts(input.LiveHosts)
	case "url_crawl":
		g.crawl(input.URLs)
	default:
		g.subdomains(input.Subdomains)
		g.dnsRecords(input.DNSRecords)
		g.openPorts(input.OpenPorts)
		g.liveHosts(input.LiveHosts)
		g.crawl(input.URLs)
	}
	return report, nil
}

func nonNegative(v int64) int {
	if v < 0 {
		return 0
	}
	return int(v)
}

// projectDiscoveryTools are the scanners whose vendor is ProjectDiscovery.
var projectDiscoveryTools = map[string]bool{
	"subfinder": true, "dnsx": true, "naabu": true, "httpx": true, "katana": true,
	"nuclei": true, "uncover": true, "asnmap": true, "tlsx": true, "cdncheck": true,
	"alterx": true, "shuffledns": true, "chaos": true, "mapcidr": true,
}

func reconVendor(scanner string) string {
	if projectDiscoveryTools[strings.ToLower(strings.TrimSpace(scanner))] {
		return "projectdiscovery"
	}
	return ""
}

// assetIDs hands out report-unique asset IDs.
type assetIDs map[string]bool

func newAssetIDs() assetIDs { return assetIDs{} }

func (a assetIDs) next(prefix, value string) string {
	base := prefix + "-" + normalizeAssetID(value)
	id := base
	for i := 2; a[id]; i++ {
		id = base + "-" + strconv.Itoa(i)
	}
	a[id] = true
	return id
}

// reconGraph builds the assets and relationships of one report, one asset
// per (type, canonical value) and one relationship per (type, from, to).
type reconGraph struct {
	r     *Report
	o     *ReconConverterOptions
	ids   assetIDs
	index map[string]int  // type \x1f value -> asset index
	rels  map[string]bool // type \x1f from \x1f to
	now   time.Time
}

func newReconGraph(r *Report, o *ReconConverterOptions) *reconGraph {
	g := &reconGraph{r: r, o: o, ids: newAssetIDs(), index: map[string]int{}, rels: map[string]bool{}, now: r.Metadata.GeneratedAt}
	for i := range r.Assets {
		g.ids[r.Assets[i].ID] = true
		g.index[string(r.Assets[i].Type)+"\x1f"+r.Assets[i].Value] = i
	}
	return g
}

// asset returns the asset of type t and canonical value v, adding it when
// the report does not have it yet. The id prefix is the type.
func (g *reconGraph) asset(t AssetType, v string) *Asset {
	k := string(t) + "\x1f" + v
	if i, ok := g.index[k]; ok {
		return &g.r.Assets[i]
	}
	now := g.now
	g.r.Assets = append(g.r.Assets, Asset{
		ID:          g.ids.next(string(t), v),
		Type:        t,
		Value:       v,
		Criticality: g.o.DefaultCriticality,
		Confidence:  g.o.DefaultConfidence,
		LastSeenAt:  &now,
	})
	g.index[k] = len(g.r.Assets) - 1
	return &g.r.Assets[len(g.r.Assets)-1]
}

// relate adds a relationship once.
func (g *reconGraph) relate(t RelationshipType, from, to string) {
	if from == "" || to == "" || from == to {
		return
	}
	k := string(t) + "\x1f" + from + "\x1f" + to
	if g.rels[k] || len(g.r.Relationships) >= MaxRelationships {
		return
	}
	g.rels[k] = true
	g.r.Relationships = append(g.r.Relationships, Relationship{Type: t, FromRef: from, ToRef: to})
}

// hostAsset returns the ip_address asset of an address or the domain_name
// asset of a name, or nil when h is neither.
func (g *reconGraph) hostAsset(h string) *Asset {
	if ip, err := CanonicalIP(h); err == nil {
		a := g.asset(AssetTypeIPAddress, ip)
		if a.Technical == nil {
			v := 4
			if strings.Contains(ip, ":") {
				v = 6
			}
			a.Technical = &AssetTechnical{IPAddress: &IPAddressTechnical{Version: v}}
		}
		return a
	}
	if d, err := CanonicalDomain(h); err == nil {
		return g.asset(AssetTypeDomainName, d)
	}
	return nil
}

func domainTechnical(a *Asset) *DomainTechnical {
	if a.Technical == nil {
		a.Technical = &AssetTechnical{}
	}
	if a.Technical.Domain == nil {
		a.Technical.Domain = &DomainTechnical{}
	}
	return a.Technical.Domain
}

func addDNSRecord(d *DomainTechnical, rec DNSRecord) {
	for _, have := range d.DNSRecords {
		if have.Type == rec.Type && have.Name == rec.Name && have.Value == rec.Value {
			return
		}
	}
	if len(d.DNSRecords) < MaxDNSRecords {
		d.DNSRecords = append(d.DNSRecords, rec)
	}
}

// MaxDNSRecords bounds the DNS records of one domain_name asset.
const MaxDNSRecords = 500

// dnsTypeRE is the form of a DNS RR type mnemonic.
func validDNSType(t string) bool {
	if t == "" || len(t) > 16 {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func (g *reconGraph) subdomains(subdomains []SubdomainInput) {
	for _, sub := range subdomains {
		name, err := CanonicalDomain(sub.Host)
		if err != nil {
			continue
		}
		a := g.asset(AssetTypeDomainName, name)
		d := domainTechnical(a)
		for _, raw := range sub.IPs {
			ip, err := CanonicalIP(raw)
			if err != nil {
				continue
			}
			typ := "A"
			if strings.Contains(ip, ":") {
				typ = "AAAA"
			}
			addDNSRecord(d, DNSRecord{Type: typ, Name: name, Value: ip})
		}
	}
}

func (g *reconGraph) dnsRecords(records []DNSRecordInput) {
	for _, rec := range records {
		name, err := CanonicalDomain(rec.Host)
		if err != nil {
			continue
		}
		recType := strings.ToUpper(strings.TrimSpace(rec.RecordType))
		if !validDNSType(recType) {
			continue
		}
		ttl := max(rec.TTL, 0)
		a := g.asset(AssetTypeDomainName, name)
		d := domainTechnical(a)
		for _, v := range rec.Values {
			v = boundLine(v, MaxDNSValueLen)
			if v == "" {
				continue
			}
			addDNSRecord(d, DNSRecord{Type: recType, Name: name, Value: v, TTL: ttl})
			if recType == "NS" {
				if ns, err := CanonicalDomain(v); err == nil && !slices.Contains(d.Nameservers, ns) {
					d.Nameservers = append(d.Nameservers, ns)
				}
			}
		}
	}
}

// MaxDNSValueLen bounds a DNS record value.
const MaxDNSValueLen = 1024

func (g *reconGraph) openPorts(ports []OpenPortInput) {
	for _, p := range ports {
		key := p.IP
		if key == "" {
			key = p.Host
		}
		if key == "" || p.Port < 1 || p.Port > 65535 {
			continue
		}
		var host *Asset
		if ip, err := CanonicalIP(key); err == nil {
			host = g.hostAsset(ip)
			if h := strings.TrimSpace(p.Host); h != "" && h != key {
				if host.Technical.IPAddress.Hostname == "" {
					host.Technical.IPAddress.Hostname = boundLine(h, 253)
				}
			}
		} else if name, err := CanonicalDomain(key); err == nil {
			host = g.asset(AssetTypeHost, name)
		} else {
			continue
		}
		transport := Transport(strings.ToLower(strings.TrimSpace(p.Protocol)))
		if !transport.IsValid() {
			transport = TransportTCP
		}
		value, err := CanonicalService(host.Value, p.Port, string(transport))
		if err != nil {
			continue
		}
		hostID := host.ID
		svc := g.asset(AssetTypeService, value)
		if svc.Technical == nil {
			st := &ServiceTechnical{
				Port:      p.Port,
				Transport: transport,
				State:     PortOpen,
				Version:   boundLine(p.Version, 128),
				Banner:    truncateUTF8(cleanText(p.Banner), 4096),
			}
			if ap := ianaServiceName(p.Service); ap != "" {
				st.AppProtocol = ap
			}
			svc.Technical = &AssetTechnical{Service: st}
		}
		g.relate(RelExposes, hostID, svc.ID)
	}
}

// ianaServiceName returns a scanner's service label as an IANA service name
// ("http", "ssh", "microsoft-ds"), or "" when it is not one. Labels a scanner
// suffixes with "?" (unsure) are kept without it.
func ianaServiceName(s string) string {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "?"))
	if !ianaServiceRE.MatchString(s) {
		return ""
	}
	return s
}

// tlsVersionOf maps a probe's TLS version label ("tls13", "TLS 1.2",
// "tls1.1", "SSLv3") to a TLSVersion, or "".
func tlsVersionOf(s string) TLSVersion {
	v := strings.ToLower(strings.NewReplacer(" ", "", "v", "", "_", "").Replace(strings.TrimSpace(s)))
	switch v {
	case "ssl3", "ssl3.0":
		return TLSVersionSSL3
	case "tls1", "tls10", "tls1.0":
		return TLSVersionTLS10
	case "tls11", "tls1.1":
		return TLSVersionTLS11
	case "tls12", "tls1.2":
		return TLSVersionTLS12
	case "tls13", "tls1.3":
		return TLSVersionTLS13
	}
	return ""
}

// technologyOf parses a probe's technology label, "Name" or "Name:version".
func technologyOf(s string) (Technology, bool) {
	s = boundLine(s, MaxTechnologyNameLen+MaxTechnologyVerLen+1)
	name, ver, _ := strings.Cut(s, ":")
	name, ver = strings.TrimSpace(name), strings.TrimSpace(ver)
	if name == "" || tooLong(name, MaxTechnologyNameLen) || tooLong(ver, MaxTechnologyVerLen) {
		return Technology{}, false
	}
	return Technology{Name: name, Version: ver}, true
}

// providerToken returns a provider name as an open token ("Cloudflare" ->
// "cloudflare"), or "".
func providerToken(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	t = strings.NewReplacer(" ", "-", "_", "-").Replace(t)
	if !IsOpenToken(t) {
		return ""
	}
	return t
}

func (g *reconGraph) liveHosts(hosts []LiveHostInput) {
	for _, h := range hosts {
		origin, err := CanonicalOrigin(stripURLUserinfo(h.URL))
		if err != nil {
			continue
		}
		a := g.asset(AssetTypeWebOrigin, origin)
		if a.Technical != nil && a.Technical.HTTP != nil {
			continue // first probe of an origin wins
		}
		ht := &HTTPTechnical{
			Title:       boundLine(h.Title, 512),
			WebServer:   boundLine(h.WebServer, 255),
			ContentType: boundLine(h.ContentType, MaxContentTypeLen),
			TLSVersion:  tlsVersionOf(h.TLSVersion),
			JARM:        jarmHash(h.JARM),
			FaviconMMH3: faviconMMH3(h.FaviconMMH3),
		}
		if validStatus(h.StatusCode) {
			ht.StatusCode = h.StatusCode
		}
		if r := stripURLUserinfo(h.Redirect); r != "" && r != h.URL && IsWebURL(r) {
			ht.RedirectURL = weburl.RedactURL(r)
		}
		if cdn := providerToken(h.CDN); cdn != "" {
			switch strings.ToLower(strings.TrimSpace(h.CDNType)) {
			case "waf":
				ht.WAF = cdn
			default:
				ht.CDN = cdn
			}
		}
		ht.SecurityHeaders = httpPosture(h.ResponseHeaders)
		if a.Technical == nil {
			a.Technical = &AssetTechnical{}
		}
		a.Technical.HTTP = ht
		for _, raw := range h.Technologies {
			if len(a.Technologies) >= MaxTechnologies {
				break
			}
			if t, ok := technologyOf(raw); ok && !slices.ContainsFunc(a.Technologies, func(x Technology) bool { return x.Name == t.Name && x.Version == t.Version }) {
				a.Technologies = append(a.Technologies, t)
			}
		}
		if wc := webContent(h.WebContent, g.now); len(wc) > 0 {
			a.Extensions.Set(OpenCTEMNamespace, WebContentKey, wc)
		}
		originID := a.ID

		// The origin's name, its aliases and the address it answered on.
		var nameID string
		if u, err := url.Parse(origin); err == nil {
			if d, err := CanonicalDomain(u.Hostname()); err == nil {
				name := g.asset(AssetTypeDomainName, d)
				nameID = name.ID
				dt := domainTechnical(name)
				for _, c := range boundCNAMEs(h.CNAMEs) {
					addDNSRecord(dt, DNSRecord{Type: "CNAME", Name: d, Value: c})
				}
			}
		}
		if ip, err := CanonicalIP(h.IP); err == nil {
			ipa := g.hostAsset(ip)
			if asn := normalizeASN(h.ASN); asn != nil {
				t := ipa.Technical.IPAddress
				if t.ASN == 0 {
					t.ASN, t.ASNOrg, t.Country = asn.number, asn.org, asn.country
				}
			}
			if nameID != "" {
				g.relate(RelResolvesTo, nameID, ipa.ID)
			}
		}
		if cert := g.certificate(h.TLS); cert != "" {
			g.relate(RelServesCertificate, originID, cert)
		}
	}
}

// Bounds on values a scanned server chooses: sensor and target output is
// hostile.
const (
	maxCertNameLen = 255
	maxSerialLen   = 128
	maxCertSANs    = 100
	maxSANLen      = 253
	maxASNOrgLen   = 255
)

// boundLine is cleanLine cut to at most maxBytes bytes.
func boundLine(s string, maxBytes int) string {
	return strings.TrimSpace(truncateUTF8(cleanLine(s), maxBytes))
}

// certificate adds the leaf certificate of an HTTP probe and returns its
// asset id, or "" when there is no usable leaf (no certificate, or no valid
// SHA-256 fingerprint to identify it by). Several origins can serve one
// certificate; it is added once.
func (g *reconGraph) certificate(leaf *TLSLeafInput) string {
	if leaf == nil {
		return ""
	}
	fp, err := CanonicalCertificateFingerprint(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(leaf.FingerprintSHA256)), "sha256:"))
	if err != nil {
		return ""
	}
	a := g.asset(AssetTypeCertificate, fp)
	if a.Technical != nil {
		return a.ID
	}
	tech := &CertificateTechnical{
		SerialNumber:      boundLine(leaf.SerialNumber, maxSerialLen),
		SubjectCN:         boundLine(leaf.SubjectCN, maxCertNameLen),
		IssuerCN:          boundLine(leaf.IssuerCN, maxCertNameLen),
		IssuerOrg:         boundLine(leaf.IssuerOrg, maxCertNameLen),
		SHA256Fingerprint: fp,
		IsSelfSigned:      leaf.SelfSigned,
		IsWildcard:        leaf.Wildcard,
	}
	tech.SubjectAltNames, _ = boundSANs(leaf.SANs)
	if !leaf.NotBefore.IsZero() {
		nb := leaf.NotBefore.UTC()
		tech.NotBefore = &nb
	}
	if !leaf.NotAfter.IsZero() {
		na := leaf.NotAfter.UTC()
		tech.NotAfter = &na
	}
	a.Name = tech.SubjectCN
	a.Technical = &AssetTechnical{Certificate: tech}
	return a.ID
}

func isHex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return s != ""
}

// boundSANs cleans, de-duplicates and caps a certificate's names. It returns
// the names kept and how many were left out.
func boundSANs(in []string) ([]string, int) {
	if len(in) == 0 {
		return nil, 0
	}
	out := make([]string, 0, min(len(in), maxCertSANs))
	seen := map[string]bool{}
	dropped := 0
	for _, s := range in {
		s = strings.TrimSuffix(strings.ToLower(boundLine(s, maxSANLen+1)), ".")
		if s == "" || len(s) > maxSANLen || strings.ContainsAny(s, " /\\") {
			dropped++
			continue
		}
		if seen[s] {
			continue
		}
		if len(out) == maxCertSANs {
			dropped++
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, dropped
}

// faviconMMH3 returns a favicon mmh3 hash (a signed 32-bit decimal), or "".
func faviconMMH3(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 11 {
		return ""
	}
	n, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return ""
	}
	return strconv.FormatInt(n, 10)
}

// jarmHash returns a JARM fingerprint (62 lower-case hex characters), or ""
// for anything else and for the all-zero hash (no TLS answer).
func jarmHash(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != 62 || !isHex(s) || strings.Trim(s, "0") == "" {
		return ""
	}
	return s
}

type asnInfo struct {
	number  int
	org     string
	country string
}

// normalizeASN returns an autonomous system's number, organization and
// country, or nil when the number is not one.
func normalizeASN(a *ASNInput) *asnInfo {
	if a == nil {
		return nil
	}
	num := strings.TrimSpace(a.Number)
	if len(num) > 2 && strings.EqualFold(num[:2], "as") {
		num = num[2:]
	}
	n, err := strconv.ParseUint(num, 10, 31)
	if err != nil || n == 0 {
		return nil
	}
	out := &asnInfo{number: int(n), org: boundLine(a.Org, maxASNOrgLen)}
	if c := strings.ToUpper(strings.TrimSpace(a.Country)); len(c) == 2 && c[0] >= 'A' && c[0] <= 'Z' && c[1] >= 'A' && c[1] <= 'Z' {
		out.country = c
	}
	return out
}

// crawl adds the endpoints of crawled URLs and the web_origin asset of each
// origin they belong to.
func (g *reconGraph) crawl(urls []DiscoveredURLInput) {
	start := len(g.r.Endpoints)
	convertCrawlEndpoints(g.r, urls)
	for i := start; i < len(g.r.Endpoints); i++ {
		ep := &g.r.Endpoints[i]
		origin, err := CanonicalOrigin(ep.Origin)
		if err != nil {
			continue
		}
		ep.OriginRef = g.asset(AssetTypeWebOrigin, origin).ID
	}
}

// stripURLUserinfo removes the user and password from a URL. Crawlers and
// probes report URLs as they found them, and https://user:token@host/ would
// otherwise put a credential into the asset value. A value that does not
// parse as a URL with a host is returned unchanged.
func stripURLUserinfo(raw string) string {
	if !strings.Contains(raw, "@") {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil || u.Host == "" {
		return raw
	}
	u.User = nil
	return u.String()
}

// cleanLine removes control characters, newlines included, from a value that
// is displayed and logged on one line (an HTML title, a server header, a
// service name). Scanned hosts choose these values; ANSI escapes or forged
// newlines in them must not reach a receiver's terminal or log.
func cleanLine(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, "\uFFFD")))
}

// cleanText removes control characters other than tab, newline and carriage
// return from a multi-line value (a service banner).
func cleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if r != '\t' && r != '\n' && r != '\r' && unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, "\uFFFD"))
}

// normalizeAssetID creates a safe ID from a string value.
func normalizeAssetID(value string) string {
	// Replace special characters with dashes
	result := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' ||
			r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' ||
			r == '-' || r == '_' {
			return r
		}
		return '-'
	}, value)

	// Remove consecutive dashes
	for strings.Contains(result, "--") {
		result = strings.ReplaceAll(result, "--", "-")
	}

	// Trim dashes from ends
	result = strings.Trim(result, "-")

	// Truncate if too long
	if len(result) > 100 {
		result = result[:100]
	}

	return strings.ToLower(result)
}

// truncateString truncates a string to maxLen characters.
func truncateString(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	if len(s) <= maxLen {
		return s
	}
	// Not enough room for the "..." suffix — hard-truncate instead of
	// slicing with a negative bound (which would panic).
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// MergeReconReports merges the CTIS reports of a recon pipeline (subfinder
// -> dnsx -> naabu -> httpx) into one new report.
//
// Assets with the same type and value are merged into one: tags, DNS
// records, nameservers and technologies are combined, and the first
// report's other members win. Assets keep first-seen order and get
// report-unique ids; relationships, findings and endpoints are re-pointed at
// the merged ids, and relationships are de-duplicated. The merged tool's
// techniques are the union of the inputs'. The inputs are never modified.
func MergeReconReports(reports []*Report) *Report {
	if len(reports) == 0 {
		return nil
	}

	merged := NewReport()
	merged.Metadata.Channel = ChannelScanner
	merged.Metadata.Profiles = []Profile{ProfileDiscovery}
	g := newReconGraph(merged, &ReconConverterOptions{})
	var techniques []Technique
	totalDuration := 0
	endpointIndex := map[string]int{}

	for _, report := range reports {
		if report == nil {
			continue
		}
		if report.Tool != nil {
			for _, t := range report.Tool.Techniques {
				if !slices.Contains(techniques, t) {
					techniques = append(techniques, t)
				}
			}
		}
		totalDuration += report.Metadata.DurationMs

		idOf := make(map[string]string, len(report.Assets)) // id in this report -> merged id
		for i := range report.Assets {
			src := &report.Assets[i]
			k := string(src.Type) + "\x1f" + src.Value
			if j, ok := g.index[k]; ok {
				mergeAsset(&merged.Assets[j], src)
				idOf[src.ID] = merged.Assets[j].ID
				continue
			}
			c := cloneAsset(src)
			if c.ID == "" || g.ids[c.ID] {
				c.ID = g.ids.next(string(c.Type), c.Value)
			}
			g.ids[c.ID] = true
			merged.Assets = append(merged.Assets, c)
			g.index[k] = len(merged.Assets) - 1
			idOf[src.ID] = c.ID
		}
		for _, rel := range report.Relationships {
			g.relate(rel.Type, idOf[rel.FromRef], idOf[rel.ToRef])
		}
		for _, f := range report.Findings {
			f.AssetRef = idOf[f.AssetRef]
			merged.Findings = append(merged.Findings, f)
		}
		start := len(merged.Endpoints)
		merged.Endpoints = mergeEndpoints(merged.Endpoints, endpointIndex, report.Endpoints)
		for i := start; i < len(merged.Endpoints); i++ {
			ep := &merged.Endpoints[i]
			if origin, err := CanonicalOrigin(ep.Origin); err == nil {
				ep.OriginRef = g.asset(AssetTypeWebOrigin, origin).ID
			}
		}
	}

	merged.Metadata.DurationMs = totalDuration
	merged.Tool = &Tool{Name: "recon-pipeline", Techniques: techniques}
	return merged
}

// cloneAsset copies the parts of an asset that merging writes to, so the
// input reports are left untouched.
func cloneAsset(src *Asset) Asset {
	c := *src
	c.Tags = append([]string(nil), src.Tags...)
	c.Technologies = append([]Technology(nil), src.Technologies...)
	if src.Technical != nil {
		t := *src.Technical
		if t.Domain != nil {
			d := *t.Domain
			d.DNSRecords = append([]DNSRecord(nil), d.DNSRecords...)
			d.Nameservers = append([]string(nil), d.Nameservers...)
			t.Domain = &d
		}
		if t.IPAddress != nil {
			ip := *t.IPAddress
			t.IPAddress = &ip
		}
		c.Technical = &t
	}
	return c
}

// mergeAsset merges src into dst (the same type and value).
func mergeAsset(dst, src *Asset) {
	for _, t := range src.Tags {
		if !slices.Contains(dst.Tags, t) {
			dst.Tags = append(dst.Tags, t)
		}
	}
	for _, t := range src.Technologies {
		if len(dst.Technologies) < MaxTechnologies && !slices.ContainsFunc(dst.Technologies, func(x Technology) bool { return x.Name == t.Name && x.Version == t.Version }) {
			dst.Technologies = append(dst.Technologies, t)
		}
	}
	if src.Technical != nil {
		if dst.Technical == nil {
			t := *cloneAsset(src).Technical
			dst.Technical = &t
		} else {
			if src.Technical.Domain != nil {
				d := domainTechnical(dst)
				for _, rec := range src.Technical.Domain.DNSRecords {
					addDNSRecord(d, rec)
				}
				for _, ns := range src.Technical.Domain.Nameservers {
					if !slices.Contains(d.Nameservers, ns) {
						d.Nameservers = append(d.Nameservers, ns)
					}
				}
			}
			if dst.Technical.IPAddress == nil && src.Technical.IPAddress != nil {
				ip := *src.Technical.IPAddress
				dst.Technical.IPAddress = &ip
			}
			if dst.Technical.HTTP == nil {
				dst.Technical.HTTP = src.Technical.HTTP
			}
			if dst.Technical.Service == nil {
				dst.Technical.Service = src.Technical.Service
			}
			if dst.Technical.Certificate == nil {
				dst.Technical.Certificate = src.Technical.Certificate
			}
		}
	}
	if src.Confidence > dst.Confidence {
		dst.Confidence = src.Confidence
	}
}

// maxProviderLen bounds a CDN or WAF provider name.
const maxProviderLen = 64

// sha256Fingerprint returns a SHA-256 fingerprint as 64 lower-case hex
// characters (colons, spaces and a "sha256:" prefix removed), or "".
func sha256Fingerprint(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "sha256:")
	s = strings.NewReplacer(":", "", " ", "").Replace(s)
	if len(s) != 64 || !isHex(s) {
		return ""
	}
	return s
}
