# nuclei JSON lines mapping

Generated from `importer/spec_nuclei.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `nuclei`
- Source versions: nuclei v3 -jsonl (one result per line) or -json-export (an array of the same objects)
- Fields: 36 mapped, 14 ignored on purpose (72% mapped)

## Rules

- One finding per result, on a domain or ip_address asset named by host, else matched-at, else ip (ids asset-1, asset-2, ... in order of first appearance). A result that names no host is skipped with an issue.
- Each line (or array element) is checked on its own: invalid JSON, a value over a limit or a wrong type skips that record with an issue at its line; the other records are imported.
- Raw HTTP requests and responses, the curl command and extracted values are never read: they can hold cookies, tokens and other data of the target.
- User info in matched-at is removed.

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
| `/matched-at` | `findings[].location.path, message (user info removed)` |  |
| `/ip` | `assets[].properties.ip_address, asset (when no host)` |  |
| `/timestamp` | `findings[].source_extra.timestamp` |  |
| `/matcher-name` | `findings[].source_extra.matcher_name` |  |
| `/matcher-status` | `findings[].confidence (90 when matched, else 70)` |  |
| `/extractor-name` | `findings[].source_extra.extractor_name` |  |
| `/extracted-results` |  | values a template extracted from the target: can hold tokens or personal data |
| `/extracted-results[]` |  | values a template extracted from the target: can hold tokens or personal data |
| `/curl-command` |  | the request as a command line: can hold cookies and credentials |
| `/request` |  | raw HTTP request: can hold cookies and credentials |
| `/response` |  | raw HTTP response: can hold data of the target |
| `/meta` |  | template variables |
| `/meta/**` |  | template variables |
| `/matcher-line` |  | line numbers of a file match |
| `/matcher-line[]` |  | line numbers of a file match |
| `/interaction` |  | out-of-band interaction data: can hold data of the target |
| `/interaction/**` |  | out-of-band interaction data: can hold data of the target |
