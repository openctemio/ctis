# nuclei JSON lines mapping

Generated from `importer/spec_nuclei.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `nuclei`
- Source versions: nuclei v3 -jsonl (one result per line) or -json-export (an array of the same objects)
- Fields: 43 mapped, 10 ignored on purpose (81% mapped)

## Rules

- One finding per result, on a domain or ip_address asset named by host, else matched-at, else ip (ids asset-1, asset-2, ... in order of first appearance). A result that names no host is skipped with an issue.
- Each line (or array element) is checked on its own: invalid JSON, a value over a limit or a wrong type skips that record with an issue at its line; the other records are imported.
- The raw request and response become one http_exchange evidence item (CTIS 1.6), capped (bodies 64 KiB, headers 100 of 8 KiB, the item 256 KiB), with the extracted values (at most 20 of 1 KiB, located in the response body when found there) and the matcher name; the curl command becomes a curl item. Sensitive values (Authorization, Cookie, Set-Cookie, API-key and session headers, sensitive query, form and JSON members, extracted values that look like credentials, and every repetition of them) are marked in the items' sensitive spans, never masked: the receiver masks them.
- An http matched-at becomes finding.web (CTIS 1.6): the URL without user info, fragment or query values (names kept, as name=), the method (fuzzing_method, else the request line's) and, for a DAST result, the fuzzed parameter (fuzzing_parameter at fuzzing_position). A URL is never put in location.path, the code-file field.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/template-id` | `findings[].rule_id, native.vuln_id` |  |
| `/template` | `findings[].source_extra.template_path` |  |
| `/template-path` | `findings[].source_extra.template_path` |  |
| `/template-url` | `findings[].references` |  |
| `/template-encoded` |  | the whole template, base64 |
| `/info` | (container) |  |
| `/info/name` | `findings[].title, message` |  |
| `/info/severity` | `findings[].severity, native.severity` |  |
| `/info/description` | `findings[].description` |  |
| `/info/author` | `findings[].source_extra.authors (template authors)` |  |
| `/info/author[]` | `findings[].source_extra.authors (template authors)` |  |
| `/info/tags` | `findings[].tags` |  |
| `/info/tags[]` | `findings[].tags` |  |
| `/info/reference` | `findings[].references` |  |
| `/info/reference[]` | `findings[].references` |  |
| `/info/remediation` | `findings[].remediation.recommendation` |  |
| `/info/impact` | `findings[].source_extra.impact` |  |
| `/info/metadata` | `findings[].source_extra.template_metadata` |  |
| `/info/metadata/**` | `findings[].source_extra.template_metadata` |  |
| `/info/classification` | (container) |  |
| `/info/classification/cve-id` | `findings[].vulnerability.cve_id, cve_ids, ids` |  |
| `/info/classification/cve-id[]` | `findings[].vulnerability.cve_id, cve_ids, ids` |  |
| `/info/classification/cwe-id` | `findings[].vulnerability.cwe_ids` |  |
| `/info/classification/cwe-id[]` | `findings[].vulnerability.cwe_ids` |  |
| `/info/classification/cvss-metrics` | `findings[].vulnerability.cvss_vector, scores[].vector` |  |
| `/info/classification/cvss-score` | `findings[].vulnerability.cvss_score, scores[]` |  |
| `/info/classification/epss-score` | `findings[].vulnerability.epss_score, scores[] (epss)` |  |
| `/info/classification/epss-percentile` | `findings[].vulnerability.epss_percentile` |  |
| `/info/classification/cpe` | `findings[].vulnerability.cpe` |  |
| `/type` | `findings[].tags (protocol)` |  |
| `/host` | `assets[] (the host), fingerprint input` |  |
| `/port` | `findings[].network.port` |  |
| `/scheme` | `findings[].network.service` |  |
| `/url` |  | the target URL; host and matched-at are kept |
| `/path` |  | template path on the target; matched-at is kept |
| `/matched-at` | `findings[].web.url, message (no user info, fragment or query values)` |  |
| `/fuzzing_method` | `findings[].web.method` |  |
| `/fuzzing_parameter` | `findings[].web.parameter.name` |  |
| `/fuzzing_position` | `findings[].web.parameter.location (query, path, header, cookie, body as form, json, multipart)` |  |
| `/is_fuzzing_result` |  | a DAST result; fuzzing_parameter says which parameter |
| `/ip` | `assets[].properties.ip_address, asset (when no host)` |  |
| `/timestamp` | `findings[].source_extra.timestamp, evidence_items[].captured_at` |  |
| `/matcher-name` | `findings[].source_extra.matcher_name, evidence_items[http_exchange].match[].matcher` |  |
| `/matcher-status` | `findings[].confidence (90 when matched, else 70)` |  |
| `/extractor-name` | `findings[].source_extra.extractor_name` |  |
| `/extracted-results` | (container) |  |
| `/extracted-results[]` | `findings[].evidence_items[http_exchange].extracted, match (sensitive when credential-like)` |  |
| `/curl-command` | `findings[].evidence_items[curl].text (sensitive values marked)` |  |
| `/request` | `findings[].evidence_items[http_exchange].http.request, web.method (sensitive values marked)` |  |
| `/response` | `findings[].evidence_items[http_exchange].http.response (sensitive values marked)` |  |
| `/meta` |  | template variables |
| `/meta/**` |  | template variables |
| `/matcher-line` |  | line numbers of a file match |
| `/matcher-line[]` |  | line numbers of a file match |
| `/interaction` |  | out-of-band interaction data: can hold data of the target |
| `/interaction/**` |  | out-of-band interaction data: can hold data of the target |
