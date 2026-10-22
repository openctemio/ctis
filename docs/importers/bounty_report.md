# Bug-bounty / disclosure reports (JSON and CSV) mapping

Generated from `importer/spec_bounty_report.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `bounty_report`
- Source versions: the generic bounty report record of OpenCTEM: {"bounty_reports": [...]} as JSON, or one record per CSV row with the nested members flattened (`reward_amount`, `reward_currency`, `reward_status`, `disclosure_state`, `disclosure_agreed_date`)
- Fields: 21 mapped, 0 ignored on purpose (100% mapped)

## Rules

- One finding (type vulnerability) per valid record. A record without a `report_ref` or a `title`, or with an invalid `report_ref` or `intake`, is skipped with an issue.
- JSON is detected by a top-level member `bounty_reports`. CSV is never detected: force it with Options.Format. The parser reads JSON when the first non-space byte (after an optional UTF-8 BOM) is `{`, else CSV (strict quotes, a header row, every row as many cells as the header; the header needs `report_ref` and `title`; unknown columns are listed as unmapped). A cell that starts with `=`, `+`, `-` or `@` is data and is kept as it is.
- Fingerprint: `bounty_report:v1:` + hex(sha256(intake + NUL + report_ref)). The intake is the record's `intake` (lower-cased), else Options.BountyIntake, else `import`. For the same (intake, report_ref) the first record of a file is kept and the others are skipped with an issue.
- Severity: `reported_severity` (critical, high, medium, low, info; `informational` and `none` are info), case-insensitive. Absent or unknown: medium (the library has no CVSS scoring helper). native.severity keeps the word as written; native.status keeps `state` as written; native.instance_id is the report_ref.
- Description: `description` (cut at 64 KiB), then `## Steps to reproduce` + `steps` (64 KiB) and `## Impact` + `impact` (16 KiB). A value over its cap is cut with a marker and an issue. HTML and markdown are kept as data: nothing is rendered, fetched or interpreted here; the consumer sanitizes on render.
- Text hygiene in every field: NUL and other control characters (newline and tab kept in multi-line fields) and the bidirectional controls U+202A-U+202E, U+2066-U+2069, U+200E and U+200F are removed. In `report_ref`, `intake` and `researcher` such a character makes the value invalid instead: a bad `report_ref` or `intake` skips the record, a bad `researcher` is dropped, each with an issue.
- `weakness` is kept (vulnerability.cwe_ids and properties) only as `CWE-<1 to 6 digits>`. `cvss_vector` is kept as a CVSS score only with the prefix `CVSS:3.0/`, `CVSS:3.1/` or `CVSS:4.0/`. Anything else is dropped with an issue.
- Asset: an absolute http or https URL names its host (domain, or ip_address for an IP; id `host-<host>`) and its path, without query or fragment, becomes properties.bounty_report.endpoint_path; credentials in the URL are removed with an issue. A bare host name or IP is that asset. Anything else is an application id: a web_application asset (id `app-<id>`, value the id on one line, at most 255 characters). A URL of another scheme (file, gopher, javascript, data, ...) is refused with an issue. A record without an asset is filed on Options.DefaultAsset, else on an unclassified asset named after the tool. The asset is never resolved or contacted.
- `url` is kept in properties.bounty_report.url only when its scheme is https, it has a host and no credentials, it is printable ASCII without spaces, quotes, angle brackets or backslashes (an internationalised host only in its xn-- form, so a look-alike host shows as such) and it is at most 2048 characters; otherwise it is dropped with an issue. Neither `url` nor the asset URL is ever written to references.
- findings[].properties.bounty_report holds exactly these members when present: intake, ref, researcher, submitted_at (RFC 3339 UTC), reported_severity (critical, high, medium, low, info, none), state (new, triaged, duplicate, informative, not_applicable, resolved; matched case-insensitively with spaces and hyphens as underscores), weakness, endpoint_path, parameter, url, reward {amount (decimal string, at most 12 integer digits and 2 decimals), currency (three capital letters), status (none, pending, paid)}, disclosure {state (private, coordinated, disclosed), agreed_date (YYYY-MM-DD)}. An invalid member is left out with an issue and the record is kept.
- Limits: the input is bounded by Limits.MaxInputBytes (a larger file is refused with the too-large error), every JSON string or CSV cell by Limits.MaxTextBytes (a larger one is refused), and the number of records by Limits.MaxFindings. Texts are cut to their caps as stated above, and the title to 500 characters.
- No network: the importer never resolves a name, opens a connection or follows a URL, whatever a record contains. Nothing in a record becomes a reference. An application id that looks like a host name (a reverse-DNS id such as com.example.app) is read as a host.
- submitted_at must be RFC 3339; it is source_lifecycle.first_found and first_seen_at.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/bounty_reports` | (container) |  |
| `/bounty_reports[]` | `findings[] (one per valid record)` |  |
| `/bounty_reports[]/report_ref` | `findings[].native.instance_id, fingerprint, properties.bounty_report.ref` |  |
| `/bounty_reports[]/intake` | `findings[].fingerprint, properties.bounty_report.intake` |  |
| `/bounty_reports[]/title` | `findings[].title` |  |
| `/bounty_reports[]/submitted_at` | `findings[].source_lifecycle.first_found, first_seen_at, properties.bounty_report.submitted_at` |  |
| `/bounty_reports[]/researcher` | `findings[].properties.bounty_report.researcher` |  |
| `/bounty_reports[]/reported_severity` | `findings[].severity, native.severity, properties.bounty_report.reported_severity` |  |
| `/bounty_reports[]/state` | `findings[].native.status, properties.bounty_report.state` |  |
| `/bounty_reports[]/weakness` | `findings[].vulnerability.cwe_id, cwe_ids, properties.bounty_report.weakness` |  |
| `/bounty_reports[]/cvss_vector` | `findings[].scores[] (cvss vector)` |  |
| `/bounty_reports[]/url` | `findings[].properties.bounty_report.url (https only; never a reference)` |  |
| `/bounty_reports[]/asset` | `assets[] (host, ip or application id), findings[].properties.bounty_report.endpoint_path` |  |
| `/bounty_reports[]/parameter` | `findings[].properties.bounty_report.parameter` |  |
| `/bounty_reports[]/description` | `findings[].description` |  |
| `/bounty_reports[]/steps` | `findings[].description (Steps to reproduce)` |  |
| `/bounty_reports[]/impact` | `findings[].description (Impact)` |  |
| `/bounty_reports[]/reward` | (container) |  |
| `/bounty_reports[]/reward/amount` | `findings[].properties.bounty_report.reward.amount` |  |
| `/bounty_reports[]/reward/currency` | `findings[].properties.bounty_report.reward.currency` |  |
| `/bounty_reports[]/reward/status` | `findings[].properties.bounty_report.reward.status` |  |
| `/bounty_reports[]/disclosure` | (container) |  |
| `/bounty_reports[]/disclosure/state` | `findings[].properties.bounty_report.disclosure.state` |  |
| `/bounty_reports[]/disclosure/agreed_date` | `findings[].properties.bounty_report.disclosure.agreed_date` |  |
