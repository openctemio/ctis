### Added: CTIS 1.6 web members and typed evidence

- `endpoints[]` (top level): the methods and paths web origins serve, as a tool saw them.
  - Fields: normalised `origin`, `origin_ref`, `method`, concrete `path`, `template` hint, `kind`, `source`, redacted `parent`, `status_code`, `content_type`, `auth`, `technologies`.
  - `params[]` holds a `location`, a `name`, a `type_hint` and `required`. Parameters are named, never valued.
- `finding.web`: the redacted `url`, `method`, `endpoint_ref`, `parameter` (`location`, `name`), `request_ref` and `status_code` of a web finding.
- `finding.evidence_items[]` (at most 20): typed evidence. The envelope is `kind`, `version`, `label`, `captured_at`, `content_sha256` and `sensitive` spans.
  - Known kinds: `http_exchange` (request, response, match, extracted), `raw_text`, `curl`, `command_output`, `file_excerpt`, `screenshot`.
  - An unknown kind is validated by its envelope and carries its fields in `data`; it is never refused.
- New schemas `schemas/v1/endpoint.json` and `schemas/v1/evidence-item.json`, spec sections 4.12 and 4.13, the section 7 limits, an example `examples/web-endpoints-evidence.json` and five invalid examples.
- Go: `Endpoint`, `EndpointParam`, `WebLocation`, `WebParameter`, `EvidenceItem` and its parts, `SensitiveSpan`, the enums with their `All*` lists, `KnownEvidenceKinds` and `IsKnownEvidenceKind`.
- Recon converter: a `url_crawl` emits `endpoints[]`. There is one endpoint per origin, method and path template, holding the query parameter names of every URL that fell into it, the kind, source, parent, status and content type. `DiscoveredURLInput` gains `ContentType` and `Params`. The legacy `discovered_url` assets stay for one release train, and `MergeReconReports` combines endpoints.
- nuclei importer: the URL credential helper of the previous release is replaced by `weburl.RedactURL`, which drops every query value instead of only credential-named ones; the fingerprint of a host without credentials is unchanged. An http `matched-at` becomes `finding.web`, holding the URL, the method, and for DAST results the fuzzed parameter (`fuzzing_parameter` at `fuzzing_position`). A URL is no longer put in `location.path`.
- ZAP importer: one finding per alert, method, URL template and parameter (at most 100 per alert), each with `finding.web`, its own instances as evidence (at most 20) and its own `occurrence_count`.
- Recon converter: a `url_crawl` emits `endpoints[]`. There is one endpoint per origin, method and path template, holding the query parameter names of every URL that fell into it, the kind, source, parent, status and content type. `DiscoveredURLInput` gains `ContentType` and `Params`. The legacy `discovered_url` assets stay for one release train, and `MergeReconReports` combines endpoints.
- nuclei importer: an http `matched-at` becomes `finding.web`, holding the URL, the method, and for DAST results the fuzzed parameter (`fuzzing_parameter` at `fuzzing_position`). A URL is no longer put in `location.path`.
- ZAP importer: one finding per alert, method, URL template and parameter (at most 100 per alert), each with `finding.web`, its own instances as evidence (at most 20) and its own `occurrence_count`.

### Upgrade notes

- `SchemaVersion` is `"1.6"`. Reports of 1.0 to 1.5 are unchanged. Receivers upgrade first; producers send the 1.6 members afterwards.

### Security

- A URL in `endpoints` and `finding.web` must carry no query value, user info or fragment, and `Validate` refuses one that does. A parameter value is refused by strict decoding and by the schema.
- No query value, user info or fragment reaches the output of the recon converter or the nuclei and ZAP importers. This covers the legacy `discovered_url` asset values, messages and ZAP evidence lines; names are kept as `name=`.
- No query value, user info or fragment reaches the output of the recon converter or the nuclei and ZAP importers. This covers the legacy `discovered_url` asset values, messages and ZAP evidence lines; names are kept as `name=`.
- `Validate` refuses:
  - hostile ids;
  - unknown enums;
  - control characters in paths, names, header values and labels;
  - dangling `origin_ref` and `endpoint_ref`;
  - every member over its limit.
- Spec 4.8: evidence MAY carry a sensitive value only inside a span it marks, and receivers MUST mask it before display or forwarding. `RedactSecretFinding` masks known raw secrets inside evidence too, except inside marked spans, and shifts a marked span when a masked value before it changes the length. Every other member stays secret-free.
