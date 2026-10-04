# Changelog

All notable changes to CTIS. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Module versions follow [Semantic Versioning](https://semver.org/); module `v1.MINOR.x` implements CTIS spec `1.MINOR` (see [docs/spec.md](docs/spec.md#2-versioning-and-compatibility)).

## [Unreleased]

### Documentation

- Spec: new sections 4.8 (secrets: no member may hold a usable secret; bounds on `masked_value`) and 4.9 (`metadata.source_type` is the channel and a producer claim; results are bound to commands by the request, not the body).
- Spec 4.5: an absent `coverage_type` is not `full`, and receivers MUST NOT auto-resolve from it.
- Spec 4.2: `network.protocol` is the transport; send it whenever `port` is sent.
- Spec 2.2: new enum values are refused by older receivers, the same as new members.
- Spec 7: OpenCTEM's per-field text caps and the v1 body limit.

### Changed

- `FromSARIF` carries `properties.tags` from the result and its rule into `finding.tags` (they were dropped). Tags are deduplicated ignoring case in first-seen order; non-string, empty and over-long (more than 128 bytes) entries are skipped; at most 50 are kept per finding.
- betterleaks (a gitleaks fork) is recognised as a secret scanner: its SARIF findings get type `secret` and the tool gets the `secret` capability (they were typed `vulnerability`).

## [1.3.0] - 2026-10-02

Receivers (OpenCTEM API) must upgrade before producers send `suppression.reason`, `suppression.expires_at` or `dependencies[].properties`.

### Changed

- **License: GPL-3.0 to Apache-2.0.** The schemas and Go types can now be used by any producer without copyleft obligations.
- **Schema and Go types agree, field by field and enum by enum.** A test walks both recursively in both directions (members, JSON types, required members, enums, `additionalProperties`) and fails the build on any difference. There is no exception list.
- Every schema object sets `additionalProperties: false`, except the free-form `properties` bags and typed maps. A typo now fails schema validation the way it already failed strict ingest.
- `version` accepts any `1.<minor>` (it was `const "1.0"`); the schema's `default` is the version it describes. `NewReport()` stamps `1.3` and `$schema`. Receivers accept any 1.x (spec section 2).
- Schema `$id`s moved from the unresolvable `schemas.openctem.io` to `https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/`.
- `epss_percentile` is a 0-1 fraction, as FIRST publishes it (the schema said 0-100, which no producer sent).
- `dependencies[].version` is no longer required (the Go type always allowed it to be empty).
- `services[]` require `port` (the Go type always sends it).
- `finding.asset_type` uses the asset type enum.
- `FromSARIF`:
  - converts every run, not just the first;
  - picks the fingerprint deterministically (lowest key) instead of by map order;
  - reads GitHub `security-severity` (CodeQL, Trivy) before the SARIF level;
  - types findings from rule tags and CVE/GHSA rule IDs, so Trivy CVEs are vulnerabilities, not misconfigurations;
  - reads CWE arrays and `external/cwe/cwe-NNN` tags, and OWASP tags;
  - finds the rule by `rule.id`, `ruleIndex` or `rule.index` too;
  - carries `partialFingerprints`, `correlationGuid` and `baselineState` (matched case-insensitively);
  - reads `result.kind` into `finding.kind`, mapping SARIF's `notApplicable` to `not_applicable` (it was dropped, so a passed or inapplicable check looked like any other finding); values outside SARIF's set are left unset, and `SARIFResult` gains `Kind`;
  - no longer sets the asset's criticality to `high`;
  - capabilities: known SAST tools report `sast`, `ToolType: sca` reports `sca`, and an unknown tool reports `vulnerability` (it reported `vulnerability, secret`, which OpenCTEM read as a secret scan).
- `SARIFResult.RuleIndex` is now `*int` (absent is not index 0).
- `ConvertReconToCTIS`:
  - output validates against the schema: scope type `domain`/`network` (was `web`), capabilities `subdomain`/`dns`/`portscan`/`http_probe`/`crawler` (was the raw recon type), DNS types upper-cased and one record per value (values were joined with ", "), unknown DNS types kept in `properties.other_dns_records`;
  - a port-scan target without an IP is a `host`, not an `ip_address` with `version: 4`;
  - every HTTP probe result is an `http_service`; the type no longer flips to `service` on a 2xx/3xx status;
  - `$schema` is the real schema URL; the vendor is `projectdiscovery` only for ProjectDiscovery tools;
  - asset IDs are unique within the report; assets keep input order;
  - the caller's options are no longer modified.
- `MergeReconReports`: deterministic first-seen order, capabilities are the union of the inputs' capabilities (were tool names), inputs are never modified, and a single report is copied, not returned as is.
- `Report.Validate` also rejects: a zero timestamp, a version that is not `1.<minor>`, a `tool` without a name, duplicate asset/finding/dependency IDs, an `asset_ref` that names no asset, and confidence, rank, CVSS, EPSS and VPR outside their ranges (or NaN/infinite). It lists at most 100 problems.

### Added

- Schema entries for every field the Go types already had: `secret.verified_at`, `revoked_at`, `age_in_days`, `commit_count`; `vulnerability.fixed_versions`, `affected_version_range`, `advisories`, `is_direct`; `suppression.kind`, `status`; `location.context_start_line`; `logical_location.parent_index`; `attachments[].artifact_location.index`; the full `FindingLocation` for `dependencies[].location`.
- Go fields for schema members that had none: `Suppression.Reason`, `Suppression.ExpiresAt`, `Dependency.Properties`.
- Asset type `server` in the schema (the Go enum had it).
- DNS record type `CAA`.
- Capability values OpenCTEM already reads: `dast`, `va`, `easm`, `cspm`, `external`, `import`, `subdomain`, `dns`, `portscan`, `http_probe`, `crawler`, `tech-detect`.
- `ctis.SchemaVersion`, `SchemaMajor`, `SchemaBaseURL`, `SchemaURL`, `ParseVersion`, `IsCompatibleVersion`, `AllDataFlowLocationTypes`.
- `fingerprint.GenerateSASTStable` and `fingerprint.TypeSASTContent`: a line-independent SAST fingerprint (file, rule, enclosing function, normalised snippet).
- `docs/spec.md`: the normative specification, with a field reference generated from the schema (CI fails when it is stale), versioning rules, fingerprint recipes per finding type, receiver limits, and what OpenCTEM stores.
- `docs/proposals-1.4.md`: technique field, web/DAST block, typed relationships, VEX, aliases, KEV detail, scan outcome.
- `examples/`: one report per finding type plus an attack-surface asset report, and `examples/invalid/` with mistakes the schema must reject.
- Fuzz targets: `FuzzValidate`, `FuzzFromSARIF`, `FuzzConvertRecon`, `FuzzParseVersion`.
- Golden tests for `FromSARIF` with Semgrep, CodeQL and Trivy logs.

### Removed

- Schema members no receiver ever accepted (the Go types lacked them, so strict ingest rejected any report using them): `suppression.state` (use `status`), `dependencies[].target_index` (pointed at a `targets` array that does not exist), `dependencies[].location.line`/`column` (use `start_line`/`start_column`), `attachments[].rectangles`.
- Asset type `other` from the schema. The Go types never accepted it; use `unclassified`. OpenCTEM still files `other` as unclassified.

### Fixed

- golangci-lint finding in `fingerprint` tests (QF1001).

### CI

- golangci-lint is blocking and pinned (v2.14.0, `.golangci.yml`).
- Coverage gate enforced at 85% (was a warning at 50%; total is about 95%).
- Schema job: draft-07 meta-validation, `$ref` resolution through the `$id` registry, examples and converter golden files validated with format checks, invalid examples must be rejected.
- Fuzz smoke job.
- Release: the tag must be `vMAJOR.MINOR.PATCH`, match the module path, match `ctis.SchemaVersion` and have a CHANGELOG section; release notes come from that section.
- Third-party actions pinned by commit SHA.

## [1.2.0] - 2026-10-01

### Added

- `asset.identifiers`: stable identifiers (`machine_id`, `cloud_resource_id`, `bios_uuid`, `serial_number`, `mac_addresses`, `scm_repo_id`) so a renamed or readdressed asset keeps its history.

### CI

- Release notes escape stray `@mentions` and drop email addresses.

## [1.1.0] - 2026-06-05

### Added

- Nessus/Tenable fields: `vulnerability.cve_ids`, `vulnerability.vpr_score`, `finding.network` (host, port, protocol, service), `finding.evidence`.
- `Report.Validate()`: required fields and enum membership, zero dependencies.
- `severity.FromCVSSWithVersion`: CVSS v2 has no critical band.

### Fixed

- `FindingStatus` gained `suppressed`, matching the schema.
- `FromSARIF` falls back to the rule's `defaultConfiguration.level` when a result has no level.
- `truncateString` no longer panics on small limits; `itoa` handles `math.MinInt`.

### Changed

- `Severity.Score` documents its fail-safe: an unknown severity scores as medium.

## [1.0.0] - 2026-04-15

### Added

- Initial module: CTIS report, asset, finding and dependency types; Web3 assets and findings; JSON Schemas in `schemas/v1`; `severity` and `fingerprint` packages; SARIF and recon converters; CI, release and security workflows.

[1.3.0]: https://github.com/openctemio/ctis/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/openctemio/ctis/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/openctemio/ctis/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/openctemio/ctis/releases/tag/v1.0.0
