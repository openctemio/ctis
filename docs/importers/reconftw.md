# reconFTW results directory (v4) mapping

Generated from `importer/spec_reconftw.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `reconftw`
- Source versions: reconFTW 4.x results directory with report/report.json
- Fields: 52 mapped, 51 ignored on purpose (50% mapped)

## Rules

- A recon directory is read as one bundle (ParseBundle). Detection looks at the layout (report/report.json, subdomains/subdomains.txt, webs/webs.txt, hosts/ips.txt), never at a file name. Files may sit under one leading directory (the target name); two recon directories in one archive are refused.
- Layout and version: tool.version is the `reconFTW version:` line of a file under .log/ (first 64 KiB), else `unknown-v4` or `unknown-v3`. A directory with report/report.json, or a log that names version 4 or later, is read with the v4 rows; any other directory with the v3 rows.
- Candidates: every hostname and address is kept as an asset whether or not it belongs to the target. properties.import_scope is `in_target` (the host is the target domain or below it, or below one of Options.ScopeDomains), `outside_target`, or `unknown` (no target is known, or the asset is an address). A receiver decides scope; the importer never drops an outside host.
- Takeovers, buckets and cloud assets are candidates, never findings: the host asset (or a storage asset) carries properties.candidate_exposure (`subdomain_takeover`, `storage_bucket`, `cloud_asset`) and candidate_unverified=true, so the receiver can verify before it alerts.
- People and credentials: everything under osint/ is never opened (emails, passwords, names, metadata, dorks). Screenshots are not read. Both are listed in Result.Skipped with the reason.
- Every other file is listed in Result.Unmapped with its path; a field of a mapped httpx line that is not in this spec is listed as `<file>/<member>`.
- Endpoints: one per origin, method and path template, source `import`, with the names of the query parameters and never their values. A URL that is not a plain http or https URL (javascript:, data:, user info, control characters, CR/LF/NUL) is refused and counted.
- Lines: each list file is read line by line. A line over the line limit, with invalid UTF-8, a NUL or another control character, or that does not parse is skipped and counted in one issue per file; CRLF line ends are accepted.
- Bundle limits (BundleLimits): 50,000 files listed, 300 files read, 256 MiB per file, 2 GiB read in total, 64 KiB per line, 2,000,000 lines per file, 32 directory levels, decompression ratio 200. A path with `..`, an absolute path, a backslash, a link, an encrypted entry or a nested archive refuses the whole bundle.
- Nuclei result files go through the nuclei importer (docs/importers/nuclei.md); each finding is filed on the host asset of its result. Findings on a host outside the target are kept on that candidate asset.
- The report is partial coverage by nature: a host missing from a later import says nothing about whether it still exists.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/report/report.json` | (container) |  |
| `/report/report.json/domain` | `metadata.scope.name, metadata.source_ref (the target domain)` |  |
| `/report/report.json/mode` | `properties.reconftw_mode` |  |
| `/report/report.json/generated_at` | `metadata.timestamp (clamped to the time of the import), assets[].discovered_at` |  |
| `/report/report.json/summary` |  | counts reconFTW computed; never trusted, the importer recounts |
| `/report/report.json/summary/**` |  | counts reconFTW computed; never trusted, the importer recounts |
| `/report/report.json/delta` |  | change summary against an earlier reconFTW run; the receiver computes its own changes |
| `/report/report.json/delta/**` |  | change summary against an earlier reconFTW run; the receiver computes its own changes |
| `/.log/*.txt` | `tool.version (the `reconFTW version:` line, first 64 KiB)` |  |
| `/subdomains/subdomains.txt` | `assets[] (hostnames and addresses are candidates: properties.import_scope says whether they are inside the target) as domain or subdomain assets` |  |
| `/hosts/ips.txt` | `assets[] (hostnames and addresses are candidates: properties.import_scope says whether they are inside the target) as ip_address assets` |  |
| `/hosts/cdn_providers.txt` | `assets[ip_address].properties.cdn` |  |
| `/hosts/naabu*.txt` | `assets[ip_address or host].technical.ip_address.ports (open, tcp)` |  |
| `/webs/web_full_info*.txt` | (container) |  |
| `/webs/web_full_info*.txt/url` | `assets[http_service].value and name; endpoints[].origin (query values, user info, fragment and control characters refused)` |  |
| `/webs/web_full_info*.txt/host` | `assets[http_service].properties.ip (when it is an address)` |  |
| `/webs/web_full_info*.txt/host_ip` | `assets[http_service].properties.ip` |  |
| `/webs/web_full_info*.txt/scheme` | `assets[http_service].technical.service.protocol, tls (from the URL)` |  |
| `/webs/web_full_info*.txt/status_code` | `assets[http_service].properties.status_code` |  |
| `/webs/web_full_info*.txt/content_length` | `assets[http_service].properties.content_length` |  |
| `/webs/web_full_info*.txt/title` | `assets[http_service].properties.title` |  |
| `/webs/web_full_info*.txt/webserver` | `assets[http_service].properties.web_server, technical.service.name` |  |
| `/webs/web_full_info*.txt/content_type` | `assets[http_service].properties.content_type` |  |
| `/webs/web_full_info*.txt/tech` | `assets[http_service].properties.technologies` |  |
| `/webs/web_full_info*.txt/cdn` | `assets[http_service].properties.cdn (with cdn_name)` |  |
| `/webs/web_full_info*.txt/cdn_name` | `assets[http_service].properties.cdn, hosted_by` |  |
| `/webs/web_full_info*.txt/cdn_type` | `assets[http_service].properties.cdn_type, waf` |  |
| `/webs/web_full_info*.txt/time` | `assets[http_service].properties.response_time_ms` |  |
| `/webs/web_full_info*.txt/location` | `assets[http_service].properties.redirect_url (no query values)` |  |
| `/webs/web_full_info*.txt/favicon` | `assets[http_service].properties.favicon_mmh3` |  |
| `/webs/web_full_info*.txt/jarm` | `assets[http_service].properties.jarm` |  |
| `/webs/web_full_info*.txt/tls` | (container) |  |
| `/webs/web_full_info*.txt/tls/tls_version` | `assets[http_service].properties.tls_version` |  |
| `/webs/web_full_info*.txt/tls/subject_cn` | `assets[certificate].technical.certificate.subject_cn` |  |
| `/webs/web_full_info*.txt/tls/subject_an` | `assets[certificate].technical.certificate.sans` |  |
| `/webs/web_full_info*.txt/tls/issuer_cn` | `assets[certificate].technical.certificate.issuer_cn` |  |
| `/webs/web_full_info*.txt/tls/issuer_org` | `assets[certificate].technical.certificate.issuer_org (first value)` |  |
| `/webs/web_full_info*.txt/tls/fingerprint_hash` | `assets[certificate].value and technical.certificate.fingerprint (sha256 only)` |  |
| `/webs/web_full_info*.txt/tls/not_before` | `assets[certificate].technical.certificate.not_before` |  |
| `/webs/web_full_info*.txt/tls/not_after` | `assets[certificate].technical.certificate.not_after` |  |
| `/webs/web_full_info*.txt/tls/self_signed` | `assets[certificate].technical.certificate.self_signed` |  |
| `/webs/web_full_info*.txt/tls/expired` | `assets[certificate].technical.certificate.expired` |  |
| `/webs/web_full_info*.txt/tls/wildcard_certificate` | `assets[certificate].technical.certificate.wildcard` |  |
| `/webs/web_full_info*.txt/tls/mismatched` | `assets[certificate].properties.host_mismatch` |  |
| `/webs/web_full_info*.txt/asn` | (container) |  |
| `/webs/web_full_info*.txt/asn/as_number` | `assets[http_service].properties.asn` |  |
| `/webs/web_full_info*.txt/asn/as_name` | `assets[http_service].properties.asn_org` |  |
| `/webs/web_full_info*.txt/asn/as_country` | `assets[http_service].properties.asn_country` |  |
| `/webs/web_full_info*.txt/failed` |  | a failed probe has no result; the line is skipped |
| `/webs/web_full_info*.txt/input` |  | the probe input; url is kept |
| `/webs/web_full_info*.txt/port` |  | the URL carries the port |
| `/webs/web_full_info*.txt/timestamp` |  | not kept: no CTIS member |
| `/webs/web_full_info*.txt/method` |  | not kept: no CTIS member |
| `/webs/web_full_info*.txt/path` |  | not kept: no CTIS member |
| `/webs/web_full_info*.txt/words` |  | not kept: content statistics of the body |
| `/webs/web_full_info*.txt/lines` |  | not kept: content statistics of the body |
| `/webs/web_full_info*.txt/chain` |  | not kept: redirect chain; location is kept |
| `/webs/web_full_info*.txt/chain/**` |  | not kept: redirect chain; location is kept |
| `/webs/web_full_info*.txt/chain_status_codes` |  | not kept: redirect chain; location is kept |
| `/webs/web_full_info*.txt/final_url` |  | not kept: redirect chain; location is kept |
| `/webs/web_full_info*.txt/resolvers` |  | not kept: DNS answers; the platform resolves names itself |
| `/webs/web_full_info*.txt/a` |  | not kept: DNS answers; the platform resolves names itself |
| `/webs/web_full_info*.txt/aaaa` |  | not kept: DNS answers; the platform resolves names itself |
| `/webs/web_full_info*.txt/cname` |  | not kept: DNS answers; the platform resolves names itself |
| `/webs/web_full_info*.txt/ns` |  | not kept: DNS answers; the platform resolves names itself |
| `/webs/web_full_info*.txt/knowledgebase` |  | not kept: httpx internal page classification |
| `/webs/web_full_info*.txt/knowledgebase/**` |  | not kept: httpx internal page classification |
| `/webs/web_full_info*.txt/hash` |  | not kept: content statistics of the body |
| `/webs/web_full_info*.txt/hash/**` |  | not kept: content statistics of the body |
| `/webs/web_full_info*.txt/header` |  | not kept: response and request content can hold cookies, tokens and personal data; values are never stored |
| `/webs/web_full_info*.txt/header/**` |  | not kept: response and request content can hold cookies, tokens and personal data; values are never stored |
| `/webs/web_full_info*.txt/raw_header` |  | not kept: response and request content can hold cookies, tokens and personal data; values are never stored |
| `/webs/web_full_info*.txt/request` |  | not kept: response and request content can hold cookies, tokens and personal data; values are never stored |
| `/webs/web_full_info*.txt/response` |  | not kept: response and request content can hold cookies, tokens and personal data; values are never stored |
| `/webs/web_full_info*.txt/body` |  | not kept: response and request content can hold cookies, tokens and personal data; values are never stored |
| `/webs/web_full_info*.txt/body_preview` |  | not kept: response and request content can hold cookies, tokens and personal data; values are never stored |
| `/webs/web_full_info*.txt/body_fqdn` |  | not kept: response and request content can hold cookies, tokens and personal data; values are never stored |
| `/webs/web_full_info*.txt/body_domains` |  | not kept: response and request content can hold cookies, tokens and personal data; values are never stored |
| `/webs/web_full_info*.txt/response_time` |  | not kept: no CTIS member |
| `/webs/web_full_info*.txt/tls/host` |  | not kept: handshake detail the platform probes itself |
| `/webs/web_full_info*.txt/tls/port` |  | not kept: handshake detail the platform probes itself |
| `/webs/web_full_info*.txt/tls/probe_status` |  | not kept: handshake detail the platform probes itself |
| `/webs/web_full_info*.txt/tls/cipher` |  | not kept: handshake detail the platform probes itself |
| `/webs/web_full_info*.txt/tls/tls_connection` |  | not kept: handshake detail the platform probes itself |
| `/webs/web_full_info*.txt/tls/subject_org` |  | not kept: handshake detail the platform probes itself |
| `/webs/web_full_info*.txt/tls/issuer_dn` |  | not kept: handshake detail the platform probes itself |
| `/webs/web_full_info*.txt/tls/subject_dn` |  | not kept: handshake detail the platform probes itself |
| `/webs/web_full_info*.txt/tls/serial` |  | not kept: handshake detail the platform probes itself |
| `/webs/web_full_info*.txt/tls/ja3_hash` |  | not kept: handshake detail the platform probes itself |
| `/webs/web_full_info*.txt/tls/ja3s_hash` |  | not kept: handshake detail the platform probes itself |
| `/webs/web_full_info*.txt/tls/jarm_hash` |  | not kept: handshake detail the platform probes itself |
| `/webs/web_full_info*.txt/tls/sni` |  | not kept: handshake detail the platform probes itself |
| `/webs/web_full_info*.txt/tls/version` |  | not kept: handshake detail the platform probes itself |
| `/webs/webs.txt` | `assets[http_service] (only for URLs the httpx file does not hold)` |  |
| `/webs/webs_uncommon_ports.txt` | `assets[http_service] (only for URLs the httpx file does not hold)` |  |
| `/webs/webs_wafs.txt` | `assets[http_service].properties.waf` |  |
| `/webs/url_extract.txt` | `endpoints[] (source import; query parameter names only)` |  |
| `/webs/urls_by_ext.txt` | `endpoints[] (source import)` |  |
| `/gf/*.txt` | `endpoints[] (source import; the class is recomputed, the file's bucket name is not kept)` |  |
| `/js/js_livelinks.txt` | `endpoints[] (kind script, source js)` |  |
| `/js/js_endpoints.txt` | `endpoints[] (source js)` |  |
| `/webs/takeover.txt` | `assets[domain or subdomain].properties.candidate_exposure=subdomain_takeover` |  |
| `/subdomains/s3buckets.txt` | `assets[storage] (candidate_exposure=storage_bucket)` |  |
| `/subdomains/cloud_assets.txt` | `assets[storage] (candidate_exposure=cloud_asset)` |  |
| `/nuclei_output/*_json.txt` | `findings[] through the nuclei importer; assets[] for the hosts they name` |  |
| `/osint/**` |  | OSINT results hold people data (emails, names, metadata) and credentials: never opened |
| `/screenshots/**` |  | images are not imported |
