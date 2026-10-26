package importer

// The mapping specs of a reconFTW results directory. A bundle has no field
// paths of its own, so a row is a path inside the directory (relative to the
// directory that holds subdomains/, webs/, hosts/ ...), and, for the httpx
// JSON lines, the members of a line below the file's path. Two layouts are
// read:
//
//   - reconftw (v4): a directory with report/report.json;
//   - reconftw_v3: the older layout without the report/ folder.
//
// The rows are written once; v3 is the v4 rows minus the report folder.

const (
	httpxFile    = "/webs/web_full_info*.txt"
	reconTarget  = "assets[] (hostnames and addresses are candidates: properties.import_scope says whether they are inside the target)"
	reconRuleSet = "A recon directory is read as one bundle (ParseBundle). Detection looks at the layout (report/report.json, subdomains/subdomains.txt, webs/webs.txt, hosts/ips.txt), never at a file name. Files may sit under one leading directory (the target name); two recon directories in one archive are refused."
)

var reconRules = []string{
	reconRuleSet,
	"Layout and version: tool.version is the `reconFTW version:` line of a file under .log/ (first 64 KiB), else `unknown-v4` or `unknown-v3`. A directory with report/report.json, or a log that names version 4 or later, is read with the v4 rows; any other directory with the v3 rows.",
	"Candidates: every hostname and address is kept as an asset whether or not it belongs to the target. properties.import_scope is `in_target` (the host is the target domain or below it, or below one of Options.ScopeDomains), `outside_target`, or `unknown` (no target is known, or the asset is an address). A receiver decides scope; the importer never drops an outside host.",
	"Takeovers, buckets and cloud assets are candidates, never findings: the host asset (or a storage asset) carries properties.candidate_exposure (`subdomain_takeover`, `storage_bucket`, `cloud_asset`) and candidate_unverified=true, so the receiver can verify before it alerts.",
	"People and credentials: everything under osint/ is never opened (emails, passwords, names, metadata, dorks). Screenshots are not read. Both are listed in Result.Skipped with the reason.",
	"Every other file is listed in Result.Unmapped with its path; a field of a mapped httpx line that is not in this spec is listed as `<file>/<member>`.",
	"Endpoints: one per origin, method and path template, source `import`, with the names of the query parameters and never their values. A URL that is not a plain http or https URL (javascript:, data:, user info, control characters, CR/LF/NUL) is refused and counted.",
	"Lines: each list file is read line by line. A line over the line limit, with invalid UTF-8, a NUL or another control character, or that does not parse is skipped and counted in one issue per file; CRLF line ends are accepted.",
	"Bundle limits (BundleLimits): 50,000 files listed, 300 files read, 256 MiB per file, 2 GiB read in total, 64 KiB per line, 2,000,000 lines per file, 32 directory levels, decompression ratio 200. A path with `..`, an absolute path, a backslash, a link, an encrypted entry or a nested archive refuses the whole bundle.",
	"Nuclei result files go through the nuclei importer (docs/importers/nuclei.md); each finding is filed on the host asset of its result. Findings on a host outside the target are kept on that candidate asset.",
	"The report is partial coverage by nature: a host missing from a later import says nothing about whether it still exists.",
}

func reconFields(v4 bool) []Field {
	f := []Field{}
	if v4 {
		f = append(f,
			Field{Path: "/report/report.json", Target: Container},
			Field{Path: "/report/report.json/domain", Target: "metadata.scope.name, metadata.source_ref (the target domain)"},
			Field{Path: "/report/report.json/mode", Target: "properties.reconftw_mode"},
			Field{Path: "/report/report.json/generated_at", Target: "metadata.timestamp (clamped to the time of the import), assets[].discovered_at"},
			Field{Path: "/report/report.json/summary", Ignored: "counts reconFTW computed; never trusted, the importer recounts"},
			Field{Path: "/report/report.json/summary/**", Ignored: "counts reconFTW computed; never trusted, the importer recounts"},
			Field{Path: "/report/report.json/delta", Ignored: "change summary against an earlier reconFTW run; the receiver computes its own changes"},
			Field{Path: "/report/report.json/delta/**", Ignored: "change summary against an earlier reconFTW run; the receiver computes its own changes"},
		)
	}
	f = append(f,
		Field{Path: "/.log/*.txt", Target: "tool.version (the `reconFTW version:` line, first 64 KiB)"},
		Field{Path: "/subdomains/subdomains.txt", Target: reconTarget + " as domain or subdomain assets"},
		Field{Path: "/hosts/ips.txt", Target: reconTarget + " as ip_address assets"},
		Field{Path: "/hosts/cdn_providers.txt", Target: "assets[ip_address].properties.cdn"},
		Field{Path: "/hosts/naabu*.txt", Target: "assets[ip_address or host].technical.ip_address.ports (open, tcp)"},
		Field{Path: httpxFile, Target: Container},
	)
	for _, m := range httpxMembers {
		path := httpxFile + "/" + m.name
		switch {
		case m.ignored != "":
			f = append(f, Field{Path: path, Ignored: m.ignored})
		case m.target == "(container)":
			f = append(f, Field{Path: path, Target: Container})
		default:
			f = append(f, Field{Path: path, Target: m.target})
		}
	}
	f = append(f,
		Field{Path: "/webs/webs.txt", Target: "assets[http_service] (only for URLs the httpx file does not hold)"},
		Field{Path: "/webs/webs_uncommon_ports.txt", Target: "assets[http_service] (only for URLs the httpx file does not hold)"},
		Field{Path: "/webs/webs_wafs.txt", Target: "assets[http_service].properties.waf"},
		Field{Path: "/webs/url_extract.txt", Target: "endpoints[] (source import; query parameter names only)"},
		Field{Path: "/webs/urls_by_ext.txt", Target: "endpoints[] (source import)"},
		Field{Path: "/gf/*.txt", Target: "endpoints[] (source import; the class is recomputed, the file's bucket name is not kept)"},
		Field{Path: "/js/js_livelinks.txt", Target: "endpoints[] (kind script, source js)"},
		Field{Path: "/js/js_endpoints.txt", Target: "endpoints[] (source js)"},
		Field{Path: "/webs/takeover.txt", Target: "assets[domain or subdomain].properties.candidate_exposure=subdomain_takeover"},
		Field{Path: "/subdomains/s3buckets.txt", Target: "assets[storage] (candidate_exposure=storage_bucket)"},
		Field{Path: "/subdomains/cloud_assets.txt", Target: "assets[storage] (candidate_exposure=cloud_asset)"},
		Field{Path: "/nuclei_output/*_json.txt", Target: "findings[] through the nuclei importer; assets[] for the hosts they name"},
		Field{Path: "/osint/**", Ignored: "OSINT results hold people data (emails, names, metadata) and credentials: never opened"},
		Field{Path: "/screenshots/**", Ignored: "images are not imported"},
	)
	return f
}

// httpxMembers are the members of one httpx JSON line below a web file.
// Members not listed are reported in Result.Unmapped.
var httpxMembers = func() []httpxMember {
	m := []httpxMember{
		{name: "url", target: "assets[http_service].value and name; endpoints[].origin (query values, user info, fragment and control characters refused)"},
		{name: "host", target: "assets[http_service].properties.ip (when it is an address)"},
		{name: "host_ip", target: "assets[http_service].properties.ip"},
		{name: "scheme", target: "assets[http_service].technical.service.protocol, tls (from the URL)"},
		{name: "status_code", target: "assets[http_service].properties.status_code"},
		{name: "content_length", target: "assets[http_service].properties.content_length"},
		{name: "title", target: "assets[http_service].properties.title"},
		{name: "webserver", target: "assets[http_service].properties.web_server, technical.service.name"},
		{name: "content_type", target: "assets[http_service].properties.content_type"},
		{name: "tech", target: "assets[http_service].properties.technologies"},
		{name: "cdn", target: "assets[http_service].properties.cdn (with cdn_name)"},
		{name: "cdn_name", target: "assets[http_service].properties.cdn, hosted_by"},
		{name: "cdn_type", target: "assets[http_service].properties.cdn_type, waf"},
		{name: "time", target: "assets[http_service].properties.response_time_ms"},
		{name: "location", target: "assets[http_service].properties.redirect_url (no query values)"},
		{name: "favicon", target: "assets[http_service].properties.favicon_mmh3"},
		{name: "jarm", target: "assets[http_service].properties.jarm"},
		{name: "tls", target: "(container)"},
		{name: "tls/tls_version", target: "assets[http_service].properties.tls_version"},
		{name: "tls/subject_cn", target: "assets[certificate].technical.certificate.subject_cn"},
		{name: "tls/subject_an", target: "assets[certificate].technical.certificate.sans"},
		{name: "tls/issuer_cn", target: "assets[certificate].technical.certificate.issuer_cn"},
		{name: "tls/issuer_org", target: "assets[certificate].technical.certificate.issuer_org (first value)"},
		{name: "tls/fingerprint_hash", target: "assets[certificate].value and technical.certificate.fingerprint (sha256 only)"},
		{name: "tls/not_before", target: "assets[certificate].technical.certificate.not_before"},
		{name: "tls/not_after", target: "assets[certificate].technical.certificate.not_after"},
		{name: "tls/self_signed", target: "assets[certificate].technical.certificate.self_signed"},
		{name: "tls/expired", target: "assets[certificate].technical.certificate.expired"},
		{name: "tls/wildcard_certificate", target: "assets[certificate].technical.certificate.wildcard"},
		{name: "tls/mismatched", target: "assets[certificate].properties.host_mismatch"},
		{name: "asn", target: "(container)"},
		{name: "asn/as_number", target: "assets[http_service].properties.asn"},
		{name: "asn/as_name", target: "assets[http_service].properties.asn_org"},
		{name: "asn/as_country", target: "assets[http_service].properties.asn_country"},
		{name: "failed", ignored: "a failed probe has no result; the line is skipped"},
		{name: "input", ignored: "the probe input; url is kept"},
		{name: "port", ignored: "the URL carries the port"},
	}
	for _, k := range []string{"timestamp", "method", "path", "words", "lines", "chain", "chain_status_codes", "final_url",
		"resolvers", "a", "aaaa", "cname", "ns", "knowledgebase", "hash", "header", "raw_header", "request", "response",
		"body", "body_preview", "body_fqdn", "body_domains", "response_time"} {
		reason := "not kept: " + httpxIgnoredReason(k)
		m = append(m, httpxMember{name: k, ignored: reason})
		if k == "knowledgebase" || k == "hash" || k == "header" || k == "chain" {
			m = append(m, httpxMember{name: k + "/**", ignored: reason})
		}
	}
	for _, k := range []string{"host", "port", "probe_status", "cipher", "tls_connection", "subject_org", "issuer_dn", "subject_dn",
		"serial", "ja3_hash", "ja3s_hash", "jarm_hash", "sni", "version"} {
		m = append(m, httpxMember{name: "tls/" + k, ignored: "not kept: handshake detail the platform probes itself"})
	}
	return m
}()

type httpxMember struct {
	name    string
	target  string
	ignored string
}

func httpxIgnoredReason(k string) string {
	switch k {
	case "header", "raw_header", "request", "response", "body", "body_preview", "body_fqdn", "body_domains":
		return "response and request content can hold cookies, tokens and personal data; values are never stored"
	case "hash", "words", "lines":
		return "content statistics of the body"
	case "a", "aaaa", "cname", "ns", "resolvers":
		return "DNS answers; the platform resolves names itself"
	case "chain", "chain_status_codes", "final_url":
		return "redirect chain; location is kept"
	case "knowledgebase":
		return "httpx internal page classification"
	}
	return "no CTIS member"
}

var _ = registerSpec(Spec{
	Format:        FormatReconFTW,
	Title:         "reconFTW results directory (v4)",
	SourceVersion: "reconFTW 4.x results directory with report/report.json",
	Rules:         reconRules,
	Fields:        reconFields(true),
})

var _ = registerSpec(Spec{
	Format:        formatReconFTWv3,
	Title:         "reconFTW results directory (v3)",
	SourceVersion: "reconFTW 3.x results directory (no report/ folder)",
	Rules:         reconRules,
	Fields:        reconFields(false),
})
