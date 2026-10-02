package ctis

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ReconConverterOptions configures the conversion from ReconResult to CTIS Report.
type ReconConverterOptions struct {
	// Source tracking
	DiscoverySource string // "agent", "integration", "manual"
	DiscoveryTool   string // Scanner name

	// Default values
	DefaultCriticality Criticality
	DefaultConfidence  int // 0-100

	// Asset grouping
	GroupByDomain bool // Group subdomains under root domain asset
	GroupByIP     bool // Group ports under IP asset

	// Filtering
	MinConfidence int // Minimum confidence to include
}

// DefaultReconConverterOptions returns sensible default options.
func DefaultReconConverterOptions() *ReconConverterOptions {
	return &ReconConverterOptions{
		DiscoverySource:    "agent",
		DefaultCriticality: CriticalityMedium,
		DefaultConfidence:  80,
		GroupByDomain:      true,
		GroupByIP:          true,
		MinConfidence:      0,
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
}

// TechnologyInput represents a detected technology.
type TechnologyInput struct {
	Name       string
	Version    string
	Categories []string
	Confidence int
	Website    string
}

// ConvertReconToCTIS converts reconnaissance results to a CTIS Report.
//
// The output validates against schemas/v1:
//   - scope.type is domain for subdomain, dns, http_probe and url_crawl
//     scans and network for port scans;
//   - tool.capabilities uses the capability vocabulary (subdomain, dns,
//     portscan, http_probe, crawler, easm);
//   - DNS record types are upper-cased, each value is its own record, and
//     record types outside the schema enum are kept in the asset's
//     properties["other_dns_records"] instead;
//   - a port-scan target is an ip_address asset only when it is an IP
//     address; a hostname becomes a host asset;
//   - every HTTP probe result is an http_service asset, whatever its status.
//
// Asset IDs are unique within the report, and assets keep the input order.
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

	now := time.Now()
	report := &Report{
		Version: SchemaVersion,
		Schema:  SchemaURL,
		Metadata: ReportMetadata{
			ID:         fmt.Sprintf("recon-%s-%d", input.ScannerName, now.UnixNano()),
			Timestamp:  now,
			DurationMs: nonNegative(input.DurationMs),
			SourceType: "scanner",
			SourceRef:  input.Target,
			Scope: &Scope{
				Name: input.Target,
				Type: getTargetScopeType(input.ReconType),
			},
		},
		Tool: &Tool{
			Name:         input.ScannerName,
			Version:      input.ScannerVersion,
			Vendor:       reconVendor(input.ScannerName),
			Capabilities: []string{reconCapability(input.ReconType)},
		},
		Assets:     make([]Asset, 0),
		Findings:   make([]Finding, 0),
		Properties: make(Properties),
	}
	ids := newAssetIDs()

	// Convert based on recon type
	switch input.ReconType {
	case "subdomain":
		convertSubdomains(report, ids, input.Subdomains, o)
	case "dns":
		convertDNSRecords(report, ids, input.DNSRecords, o)
	case "port":
		convertOpenPorts(report, ids, input.OpenPorts, o)
	case "http_probe":
		convertLiveHosts(report, ids, input.LiveHosts, o)
	case "url_crawl":
		convertDiscoveredURLs(report, ids, input.URLs, o)
	default:
		// Try to convert all available data
		convertSubdomains(report, ids, input.Subdomains, o)
		convertDNSRecords(report, ids, input.DNSRecords, o)
		convertOpenPorts(report, ids, input.OpenPorts, o)
		convertLiveHosts(report, ids, input.LiveHosts, o)
		convertDiscoveredURLs(report, ids, input.URLs, o)
	}

	// Add technologies if present
	if len(input.Technologies) > 0 {
		report.Properties["technologies"] = input.Technologies
	}

	return report, nil
}

func nonNegative(v int64) int {
	if v < 0 {
		return 0
	}
	return int(v)
}

// getTargetScopeType maps a recon type to a scope type of report.json.
func getTargetScopeType(reconType string) string {
	if reconType == "port" {
		return "network"
	}
	return "domain"
}

// reconCapability maps a recon type to the capability vocabulary of
// report.json.
func reconCapability(reconType string) string {
	switch reconType {
	case "subdomain":
		return "subdomain"
	case "dns":
		return "dns"
	case "port":
		return "portscan"
	case "http_probe":
		return "http_probe"
	case "url_crawl":
		return "crawler"
	default:
		return "easm"
	}
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

// dnsRecordTypes are the record types report.json accepts.
var dnsRecordTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "MX": true, "TXT": true,
	"NS": true, "SOA": true, "PTR": true, "SRV": true, "CAA": true,
}

func baseProperties(o *ReconConverterOptions) Properties {
	return Properties{
		"discovery_source": o.DiscoverySource,
		"discovery_tool":   o.DiscoveryTool,
	}
}

func convertSubdomains(report *Report, ids assetIDs, subdomains []SubdomainInput, opts *ReconConverterOptions) {
	now := time.Now()
	seen := make(map[string]bool)

	for _, sub := range subdomains {
		if sub.Host == "" || seen[sub.Host] {
			continue
		}
		seen[sub.Host] = true

		assetType := AssetTypeDomain
		if sub.Domain != "" && sub.Host != sub.Domain {
			assetType = AssetTypeSubdomain
		}

		asset := Asset{
			ID:           ids.next("subdomain", sub.Host),
			Type:         assetType,
			Value:        sub.Host,
			Name:         sub.Host,
			Criticality:  opts.DefaultCriticality,
			Confidence:   opts.DefaultConfidence,
			DiscoveredAt: &now,
			Properties:   baseProperties(opts),
		}
		if sub.Domain != "" {
			asset.Properties["root_domain"] = sub.Domain
		}
		if sub.Source != "" {
			asset.Properties["discovery_method"] = sub.Source
		}

		technical := &AssetTechnical{Domain: &DomainTechnical{}}
		if len(sub.IPs) > 0 {
			asset.Properties["resolved_ips"] = sub.IPs
			for _, ip := range sub.IPs {
				recType := "A"
				if parsed := net.ParseIP(ip); parsed == nil {
					continue
				} else if parsed.To4() == nil {
					recType = "AAAA"
				}
				technical.Domain.DNSRecords = append(technical.Domain.DNSRecords, DNSRecord{
					Type:  recType,
					Name:  sub.Host,
					Value: ip,
				})
			}
		}
		asset.Technical = technical
		report.Assets = append(report.Assets, asset)
	}
}

func convertDNSRecords(report *Report, ids assetIDs, records []DNSRecordInput, opts *ReconConverterOptions) {
	now := time.Now()

	// Group records by host, keeping first-seen host order.
	var hosts []string
	hostRecords := make(map[string][]DNSRecord)
	otherRecords := make(map[string][]map[string]any)

	for _, rec := range records {
		if rec.Host == "" {
			continue
		}
		if _, ok := hostRecords[rec.Host]; !ok {
			if _, ok := otherRecords[rec.Host]; !ok {
				hosts = append(hosts, rec.Host)
			}
		}
		recType := strings.ToUpper(strings.TrimSpace(rec.RecordType))
		ttl := rec.TTL
		if ttl < 0 {
			ttl = 0
		}
		for _, v := range rec.Values {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			if !dnsRecordTypes[recType] {
				otherRecords[rec.Host] = append(otherRecords[rec.Host], map[string]any{
					"type": recType, "value": v, "ttl": ttl,
				})
				continue
			}
			hostRecords[rec.Host] = append(hostRecords[rec.Host], DNSRecord{
				Type:  recType,
				Name:  rec.Host,
				Value: v,
				TTL:   ttl,
			})
		}
	}

	for _, host := range hosts {
		dnsRecords := hostRecords[host]
		asset := Asset{
			ID:           ids.next("dns", host),
			Type:         AssetTypeDomain,
			Value:        host,
			Name:         host,
			Criticality:  opts.DefaultCriticality,
			Confidence:   opts.DefaultConfidence,
			DiscoveredAt: &now,
			Technical: &AssetTechnical{
				Domain: &DomainTechnical{
					DNSRecords: dnsRecords,
				},
			},
			Properties: baseProperties(opts),
		}
		asset.Properties["dns_record_count"] = len(dnsRecords)
		if other := otherRecords[host]; len(other) > 0 {
			asset.Properties["other_dns_records"] = other
		}

		// Extract nameservers from NS records
		for _, rec := range dnsRecords {
			if rec.Type == "NS" {
				asset.Technical.Domain.Nameservers = append(asset.Technical.Domain.Nameservers, strings.TrimSuffix(rec.Value, "."))
			}
		}

		report.Assets = append(report.Assets, asset)
	}
}

// portInfo converts a scanned port, dropping values outside the schema.
func portInfo(p OpenPortInput) (PortInfo, bool) {
	if p.Port < 1 || p.Port > 65535 {
		return PortInfo{}, false
	}
	info := PortInfo{
		Port:    p.Port,
		State:   "open",
		Service: p.Service,
		Version: p.Version,
		Banner:  p.Banner,
	}
	switch proto := strings.ToLower(strings.TrimSpace(p.Protocol)); proto {
	case "tcp", "udp":
		info.Protocol = proto
	}
	return info, true
}

func convertOpenPorts(report *Report, ids assetIDs, ports []OpenPortInput, opts *ReconConverterOptions) {
	now := time.Now()

	if opts.GroupByIP {
		// Group ports by IP/host, keeping first-seen order.
		var keys []string
		hostPorts := make(map[string][]PortInfo)
		hostNames := make(map[string]string)

		for _, p := range ports {
			key := p.IP
			if key == "" {
				key = p.Host
			}
			if key == "" {
				continue
			}
			info, ok := portInfo(p)
			if !ok {
				continue
			}
			if _, exists := hostPorts[key]; !exists {
				keys = append(keys, key)
				hostNames[key] = p.Host
			}
			hostPorts[key] = append(hostPorts[key], info)
		}

		for _, key := range keys {
			portList := hostPorts[key]
			technical := &IPAddressTechnical{Ports: portList}

			assetType := AssetTypeIPAddress
			idPrefix := "ip"
			if ip := net.ParseIP(key); ip != nil {
				technical.Version = 4
				if ip.To4() == nil {
					technical.Version = 6
				}
				if h := hostNames[key]; h != "" && h != key {
					technical.Hostname = h
				}
			} else {
				// Only a hostname is known: it is a host, not an IP address.
				assetType = AssetTypeHost
				idPrefix = "host"
				technical.Hostname = key
			}

			asset := Asset{
				ID:           ids.next(idPrefix, key),
				Type:         assetType,
				Value:        key,
				Name:         key,
				Criticality:  opts.DefaultCriticality,
				Confidence:   opts.DefaultConfidence,
				DiscoveredAt: &now,
				Technical:    &AssetTechnical{IPAddress: technical},
				Properties:   baseProperties(opts),
			}
			asset.Properties["open_port_count"] = len(portList)
			report.Assets = append(report.Assets, asset)
		}
		return
	}

	// Create individual asset for each port
	for _, p := range ports {
		key := p.IP
		if key == "" {
			key = p.Host
		}
		if key == "" || p.Port < 1 || p.Port > 65535 {
			continue
		}
		hostPort := net.JoinHostPort(key, strconv.Itoa(p.Port))
		asset := Asset{
			ID:           ids.next("port", hostPort),
			Type:         AssetTypeOpenPort,
			Value:        hostPort,
			Name:         hostPort + "/" + strings.ToLower(p.Protocol),
			Criticality:  opts.DefaultCriticality,
			Confidence:   opts.DefaultConfidence,
			DiscoveredAt: &now,
			Properties:   baseProperties(opts),
		}
		for k, v := range map[string]any{
			"host": key, "port": p.Port, "protocol": strings.ToLower(p.Protocol),
			"service": p.Service, "version": p.Version, "banner": p.Banner,
		} {
			asset.Properties[k] = v
		}
		report.Assets = append(report.Assets, asset)
	}
}

func convertLiveHosts(report *Report, ids assetIDs, hosts []LiveHostInput, opts *ReconConverterOptions) {
	now := time.Now()
	seen := make(map[string]bool)

	for _, h := range hosts {
		if h.URL == "" || seen[h.URL] {
			continue
		}
		seen[h.URL] = true

		scheme := strings.ToLower(h.Scheme)
		service := &ServiceTechnical{
			Name:     h.WebServer,
			Protocol: scheme,
			TLS:      scheme == "https",
		}
		if h.Port >= 1 && h.Port <= 65535 {
			service.Port = h.Port
		}
		if h.Port != 0 || scheme != "" {
			service.Transport = "tcp"
		}

		asset := Asset{
			ID:           ids.next("http", h.URL),
			Type:         AssetTypeHTTPService,
			Value:        h.URL,
			Name:         h.Host,
			Criticality:  opts.DefaultCriticality,
			Confidence:   opts.DefaultConfidence,
			DiscoveredAt: &now,
			Technical:    &AssetTechnical{Service: service},
			Properties:   baseProperties(opts),
		}
		for k, v := range map[string]any{
			"status_code": h.StatusCode, "content_length": h.ContentLength,
			"title": h.Title, "web_server": h.WebServer, "content_type": h.ContentType,
			"response_time_ms": h.ResponseTime,
		} {
			asset.Properties[k] = v
		}

		// Add technologies
		if len(h.Technologies) > 0 {
			asset.Properties["technologies"] = h.Technologies
			asset.Tags = append(asset.Tags, h.Technologies...)
		}
		if h.CDN != "" {
			asset.Properties["cdn"] = h.CDN
		}
		if h.TLSVersion != "" {
			asset.Properties["tls_version"] = h.TLSVersion
		}
		if h.IP != "" {
			asset.Properties["ip"] = h.IP
		}
		if h.Redirect != "" && h.Redirect != h.URL {
			asset.Properties["redirect_url"] = h.Redirect
		}

		report.Assets = append(report.Assets, asset)
	}
}

func convertDiscoveredURLs(report *Report, ids assetIDs, urls []DiscoveredURLInput, opts *ReconConverterOptions) {
	now := time.Now()
	seen := make(map[string]bool)

	for _, u := range urls {
		if u.URL == "" || seen[u.URL] {
			continue
		}
		seen[u.URL] = true

		// Parse URL to extract host
		host := u.URL
		if parsedURL, err := url.Parse(u.URL); err == nil && parsedURL.Host != "" {
			host = parsedURL.Host
		}

		asset := Asset{
			ID:           ids.next("url", u.URL),
			Type:         AssetTypeDiscoveredURL,
			Value:        u.URL,
			Name:         truncateString(u.URL, 255),
			Criticality:  opts.DefaultCriticality,
			Confidence:   opts.DefaultConfidence,
			DiscoveredAt: &now,
			Properties:   baseProperties(opts),
		}
		for k, v := range map[string]any{
			"host": host, "method": u.Method, "source": u.Source,
			"depth": u.Depth, "type": u.Type, "extension": u.Extension,
		} {
			asset.Properties[k] = v
		}
		if u.Parent != "" {
			asset.Properties["parent_url"] = u.Parent
		}
		if u.StatusCode > 0 {
			asset.Properties["status_code"] = u.StatusCode
		}
		if u.Type != "" {
			asset.Tags = append(asset.Tags, u.Type)
		}

		report.Assets = append(report.Assets, asset)
	}
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

// MergeReconReports merges multiple CTIS reports from different recon scanners.
// This is useful when running a recon pipeline (subfinder -> dnsx -> naabu -> httpx).
//
// Assets with the same value are merged into one (tags, properties, DNS
// records, nameservers and ports are combined; the first report's other fields
// win). Assets keep first-seen order and get report-unique IDs. The merged
// tool's capabilities are the union of the inputs' capabilities; the tool
// names are in properties["tools_used"]. The inputs are never modified, and
// the result is always a new report.
func MergeReconReports(reports []*Report) *Report {
	if len(reports) == 0 {
		return nil
	}

	now := time.Now()
	merged := &Report{
		Version: SchemaVersion,
		Schema:  SchemaURL,
		Metadata: ReportMetadata{
			ID:         fmt.Sprintf("merged-recon-%d", now.UnixNano()),
			Timestamp:  now,
			SourceType: "scanner",
		},
		Assets:     make([]Asset, 0),
		Findings:   make([]Finding, 0),
		Properties: make(Properties),
	}

	tools := make([]string, 0)
	var capabilities []string
	capSeen := map[string]bool{}
	totalDuration := 0

	var order []string
	byValue := make(map[string]*Asset)

	for _, report := range reports {
		if report == nil {
			continue
		}
		if report.Tool != nil {
			tools = append(tools, report.Tool.Name)
			for _, c := range report.Tool.Capabilities {
				if !capSeen[c] {
					capSeen[c] = true
					capabilities = append(capabilities, c)
				}
			}
		}
		totalDuration += report.Metadata.DurationMs

		for i := range report.Assets {
			src := &report.Assets[i]
			if existing, ok := byValue[src.Value]; ok {
				mergeAssetProperties(existing, src)
				continue
			}
			c := cloneAsset(src)
			byValue[src.Value] = &c
			order = append(order, src.Value)
		}

		merged.Findings = append(merged.Findings, report.Findings...)
	}

	ids := newAssetIDs()
	for _, v := range order {
		a := *byValue[v]
		if a.ID != "" && !ids[a.ID] {
			ids[a.ID] = true
		} else if a.ID != "" {
			a.ID = ids.next("asset", a.Value)
		}
		merged.Assets = append(merged.Assets, a)
	}

	merged.Metadata.DurationMs = totalDuration
	merged.Properties["tools_used"] = tools
	merged.Tool = &Tool{
		Name:         "recon-pipeline",
		Capabilities: capabilities,
	}

	return merged
}

// cloneAsset copies the parts of an asset that merging writes to, so the
// input reports are left untouched.
func cloneAsset(src *Asset) Asset {
	c := *src
	c.Tags = append([]string(nil), src.Tags...)
	if src.Properties != nil {
		c.Properties = make(Properties, len(src.Properties))
		for k, v := range src.Properties {
			c.Properties[k] = v
		}
	}
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
			ip.Ports = append([]PortInfo(nil), ip.Ports...)
			t.IPAddress = &ip
		}
		c.Technical = &t
	}
	return c
}

// mergeAssetProperties merges properties from src into dst.
func mergeAssetProperties(dst, src *Asset) {
	// Merge tags
	tagSet := make(map[string]bool)
	for _, t := range dst.Tags {
		tagSet[t] = true
	}
	for _, t := range src.Tags {
		if !tagSet[t] {
			dst.Tags = append(dst.Tags, t)
			tagSet[t] = true
		}
	}

	// Merge properties
	if dst.Properties == nil {
		dst.Properties = make(Properties)
	}
	for k, v := range src.Properties {
		if _, exists := dst.Properties[k]; !exists {
			dst.Properties[k] = v
		}
	}

	// Merge technical details (domain)
	if src.Technical != nil && src.Technical.Domain != nil {
		if dst.Technical == nil {
			dst.Technical = &AssetTechnical{}
		}
		if dst.Technical.Domain == nil {
			dst.Technical.Domain = &DomainTechnical{}
		}

		// Merge DNS records
		existingRecords := make(map[string]bool)
		for _, rec := range dst.Technical.Domain.DNSRecords {
			key := rec.Type + ":" + rec.Name + ":" + rec.Value
			existingRecords[key] = true
		}
		for _, rec := range src.Technical.Domain.DNSRecords {
			key := rec.Type + ":" + rec.Name + ":" + rec.Value
			if !existingRecords[key] {
				dst.Technical.Domain.DNSRecords = append(dst.Technical.Domain.DNSRecords, rec)
			}
		}

		// Merge nameservers
		nsSet := make(map[string]bool)
		for _, ns := range dst.Technical.Domain.Nameservers {
			nsSet[ns] = true
		}
		for _, ns := range src.Technical.Domain.Nameservers {
			if !nsSet[ns] {
				dst.Technical.Domain.Nameservers = append(dst.Technical.Domain.Nameservers, ns)
			}
		}
	}

	// Merge technical details (IP)
	if src.Technical != nil && src.Technical.IPAddress != nil {
		if dst.Technical == nil {
			dst.Technical = &AssetTechnical{}
		}
		if dst.Technical.IPAddress == nil {
			dst.Technical.IPAddress = &IPAddressTechnical{}
		}

		// Merge ports
		existingPorts := make(map[string]bool)
		for _, p := range dst.Technical.IPAddress.Ports {
			key := strconv.Itoa(p.Port) + ":" + p.Protocol
			existingPorts[key] = true
		}
		for _, p := range src.Technical.IPAddress.Ports {
			key := strconv.Itoa(p.Port) + ":" + p.Protocol
			if !existingPorts[key] {
				dst.Technical.IPAddress.Ports = append(dst.Technical.IPAddress.Ports, p)
			}
		}
	}

	// Update confidence (take higher)
	if src.Confidence > dst.Confidence {
		dst.Confidence = src.Confidence
	}
}
