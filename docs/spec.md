# CTIS 1.3 specification

CTIS (CTEM Ingest Schema) is the JSON format security tools use to send assets, findings and dependencies to a CTEM platform such as OpenCTEM. This document is normative. The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as described in RFC 2119.

The format has three descriptions, and they are kept identical by tests:

- the JSON Schema in [`schemas/v1`](../schemas/v1);
- the Go types in the root package of `github.com/openctemio/ctis`;
- the field reference at the end of this document, generated from the schema.

Worked examples are in [`examples/`](../examples). CI validates every one of them against the schema, decodes it strictly into the Go types, and runs `Report.Validate` on it.

## 1. Document

A CTIS document is one JSON object, the **report**:

| Member | Required | Meaning |
|---|---|---|
| `version` | yes | Specification version, `MAJOR.MINOR` (section 2) |
| `$schema` | no | URL of the report schema |
| `metadata` | yes | When and how the data was produced; `metadata.timestamp` is required |
| `tool` | no | The producing tool; `tool.name` is required when `tool` is present |
| `assets` | no | Things that exist (hosts, domains, repositories, cloud resources, ...) |
| `findings` | no | Security findings, each optionally tied to an asset |
| `dependencies` | no | Software components (SBOM) |
| `properties` | no | Free-form producer data |

The encoding MUST be UTF-8 JSON (RFC 8259). Duplicate member names MUST NOT be used; strict receivers reject them.

## 2. Versioning and compatibility

### 2.1 Wire version

`version` is the specification version the producer wrote the report against, as `MAJOR.MINOR` without leading zeros: `1.0`, `1.1`, `1.2`, `1.3`. Producers SHOULD send the version of the specification they implement. The Go module sets it for you: `ctis.NewReport()` stamps `ctis.SchemaVersion` (currently `1.3`) and `ctis.SchemaURL`.

| Spec version | Module | Added |
|---|---|---|
| 1.0 | v1.0.0 | Initial format |
| 1.1 | v1.1.0 | `vulnerability.cve_ids`, `vulnerability.vpr_score`, `finding.network`, `finding.evidence` |
| 1.2 | v1.2.0 | `asset.identifiers` |
| 1.3 | v1.3.0 | Schema/Go reconciliation (see CHANGELOG): `suppression.reason`, `suppression.expires_at`, `dependencies[].properties`, asset type `server`, the schema entries for every field the Go types already had |

Reports produced before 1.3 often carry `"1.0"` regardless of the fields they use. Receivers MUST NOT infer the field set from the version.

### 2.2 Compatibility rule

- A **minor** release only adds optional members or enum values, or loosens a constraint. It never removes or renames a member, and never makes an optional member required.
- A **major** release may break anything. It gets a new schema directory (`schemas/v2`) and a new Go module path (`github.com/openctemio/ctis/v2`).
- A receiver MUST accept a report whose major equals its own, whatever the minor (`ctis.IsCompatibleVersion`). It MUST reject other majors.
- Receivers decode strictly: a member the receiver does not know is an error, not something to drop (section 3.2). So a newer minor is compatible only if the producer does not use members newer than the receiver's minor.
- Therefore a producer MUST NOT send members introduced after the receiver's minor, unless it knows the receiver ignores unknown members. When it cannot know, it SHOULD stay within the members of the oldest receiver it talks to.
- **Rollout order:** upgrade receivers first, then producers. For OpenCTEM this means the API before the sensors.

The Go module version follows the specification: module `v1.MINOR.x` implements CTIS `1.MINOR`. Patch releases change code, tests and docs, never the format. The release workflow refuses a tag whose `MAJOR.MINOR` differs from `ctis.SchemaVersion`.

## 3. Validation

### 3.1 Schema

The schemas are JSON Schema draft-07. Each has a resolvable `$id`:

```
https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/report.json
https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/asset.json
https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/finding.json
https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/dependency.json
https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/web3-asset.json
https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/web3-finding.json
```

`main` always serves the latest 1.x schema. For an immutable copy, replace `main` with a release tag, for example `.../ctis/v1.3.0/schemas/v1/report.json`.

`report.json` references the other five files by relative `$ref`, so a validator needs all six loaded (see the README for Python and Node recipes, and `scripts/validate_schemas.py`).

Definitions live under `$defs`. Draft-07 does not define that keyword, but every draft-07 validator resolves `#/$defs/...` as a plain JSON pointer, so the schemas work unchanged.

### 3.2 additionalProperties policy

Every object in the schema sets `"additionalProperties": false`, except the free-form bags:

- `properties` (report, metadata, tool, asset, finding, dependency) accepts any JSON;
- maps with typed values: `partial_fingerprints`, `vendor_severity`, `whois`, `languages`, `technical.cloud.tags`, `technical.service.details`.

This matches how receivers decode. OpenCTEM decodes into the Go types with unknown members rejected, so a typo such as `"sevrity"` fails at the schema exactly as it fails at ingest, instead of passing one and failing the other. Producer-specific data belongs in `properties`.

### 3.3 Report.Validate

Schema validation checks shape. `Report.Validate()` (Go) checks what the schema cannot:

- `version` is `1.<minor>`; `metadata.timestamp` is not the zero time;
- `tool.name` is set when `tool` is present;
- asset, finding and dependency `id`s are unique within their array;
- `finding.asset_ref` names an asset `id` of the same report;
- ranges: confidence 0-100, rank 0-100, `cvss_score` 0-10, `epss_score` 0-1, `epss_percentile` 0-1, `vpr_score` 0-10, and none of them NaN or infinite;
- enum members (type, severity, status, criticality) and required strings.

Producers SHOULD run `Validate` before sending; receivers SHOULD run it at their ingest boundary.

## 4. Semantics

### 4.1 Assets and references

- `assets[].id` is a report-local identifier. It has no meaning outside the report. It SHOULD be set whenever a finding refers to the asset.
- A finding names its asset either by `asset_ref` (an `assets[].id` in the same report) or by `asset_value` plus `asset_type`. `asset_ref` MUST resolve.
- `assets[].value` is the asset's primary key in the producer's eyes: a domain name, an IP address, `github.com/org/repo`, an ARN. Receivers normalise it (lower-case DNS names, canonical IP form, repository URL without scheme and `.git`); `ctis.NormalizeAssetName` implements the same rules.
- `assets[].identifiers` carries identifiers that survive renames (host ID, cloud resource ID, BIOS UUID, serial, MAC addresses, SCM repository ID). Producers MUST send only values read from the asset itself and MUST NOT guess.
- `asset.type` uses the enum in `asset.json`. Use `unclassified` when nothing fits. A hostname without a known address is a `host`, not an `ip_address`.
- `criticality` is business context. Scanners and converters SHOULD NOT set it; it belongs to the asset owner.

### 4.2 Findings

- `type`, `title` and `severity` are required.
- `severity` is the producer's assessment: `critical`, `high`, `medium`, `low` or `info`. Producers that score with CVSS SHOULD map with `severity.FromCVSSWithVersion` (CVSS v2 has no critical band).
- `status` is the producer's view (`open`, `resolved`, `suppressed`, `false_positive`, `accepted_risk`, `in_progress`). Receivers MAY treat it as a hint only; OpenCTEM does today.
- `suppression` follows SARIF: `kind` is `in_source` (a code comment or annotation) or `external` (a baseline file, a scanner console); `status` is the review state (`accepted`, `under_review`, `rejected`); `reason`, `justification`, `suppressed_by`, `suppressed_at` and `expires_at` describe it. A finding with an accepted suppression SHOULD also carry `status: suppressed`.
- `first_seen_at` and `last_seen_at` are when the producer first and last observed the finding, not when the report was written.
- `location` is for code and files. `network` is for findings observed on a host and port. Neither is for URLs: until a web location block exists (see `docs/proposals-1.4.md`), DAST tools SHOULD put the URL in `properties` and the host in `asset_value`.

### 4.3 Scores

| Member | Range | Scale |
|---|---|---|
| `confidence` | 0-100 | Producer's confidence in the finding or asset |
| `rank` | 0-100 | SARIF rank |
| `vulnerability.cvss_score` | 0-10 | CVSS base score of `cvss_version` |
| `vulnerability.epss_score` | 0-1 | EPSS probability, as FIRST publishes it |
| `vulnerability.epss_percentile` | 0-1 | EPSS percentile **as a fraction**, as FIRST publishes it: `0.97` is the 97th percentile. Sending `97` is invalid. |
| `vulnerability.vpr_score` | 0-10 | Tenable VPR |

### 4.4 Booleans

Boolean members are optional, and the Go types omit `false`. An absent boolean therefore means "false or unknown", and a receiver cannot tell the two apart. Only `secret.valid` is a tri-state today (absent, `true`, `false`). Making the other CTEM booleans tri-state is proposed for 1.4.

### 4.5 Scan coverage and branches

- `metadata.coverage_type` is `full` (the whole scope was scanned), `incremental` (changed files only) or `partial` (part of the scope). Receivers MAY auto-resolve findings missing from a report only when it is `full`. Producers MUST NOT send `full` for a scan that failed part-way.
- `metadata.branch.is_default_branch` decides whether a code scan describes the default branch. OpenCTEM auto-resolves only from full scans of the default branch.

### 4.6 Timestamps

Every timestamp is an RFC 3339 `date-time` with an offset (`2026-10-02T08:15:00Z`). Producers SHOULD use UTC. A strict receiver rejects the whole report when one timestamp does not parse.

### 4.7 Tool capabilities

`tool.capabilities` says what the tool does, from the enum in `report.json`. OpenCTEM derives a report's detection technique from the first value it recognises: `sast`, `sca`, `dast`, `secret`, `iac`, `container`, `va`, `easm`, `cspm`, `external`, `import`, `misconfiguration`, `web3`, `subdomain`, `dns`, `portscan`, `crawler`, `tech-detect`. Generic values (`vulnerability`) fall through to the tool name. The technique is per report; a per-finding technique is proposed for 1.4.

## 5. Fingerprints

`finding.fingerprint` is the producer's identity for a finding: the same issue in the same place MUST get the same fingerprint in every scan, and different issues MUST get different ones. Receivers use it to deduplicate across scans and to carry triage (false positive, accepted risk) forward. A fingerprint that changes when nothing about the issue changed reopens it as a new finding and loses its triage.

### 5.1 Format

- Fingerprints SHOULD be a lowercase hex SHA-256 digest (64 characters). The `fingerprint` package returns exactly that.
- OpenCTEM uses a producer fingerprint only when it is hexadecimal and at least 16 characters long; otherwise it computes its own from the finding. Values such as CodeQL's `39fa2ee980eb94b0:1` are therefore not used as fingerprints; put them in `partial_fingerprints`.
- Receivers scope fingerprints to the tenant and asset: two assets may share a fingerprint without colliding.
- `partial_fingerprints` carries SARIF `partialFingerprints` (for example `primaryLocationLineHash`) unchanged. It is evidence for the receiver, not a replacement for `fingerprint`.

### 5.2 Recipes

Use the generator for the finding's type. The inputs listed are the identity; anything else (titles, messages, severities, timestamps, scanner versions) MUST NOT go into a fingerprint, or every rescan produces new findings.

| Finding | Recipe (Go: `github.com/openctemio/ctis/fingerprint`) | Notes |
|---|---|---|
| SAST (code) | `GenerateSASTStable(path, ruleID, logicalLocation, snippet)` | **Recommended.** No line numbers: inserting code above the finding does not change it. Whitespace in the snippet is ignored. `logicalLocation` is the enclosing function, fully qualified when known. Returns `""` without a snippet. |
| SAST without a snippet | `GenerateSAST(path, ruleID, startLine, endLine)` | Fallback only. It changes whenever code above the finding moves, so the finding is resolved and reopened on unrelated edits. |
| SCA (dependency) | `GenerateSCA(package, version, vulnID)` | `vulnID` is the CVE when there is one, else the advisory ID. |
| Container image | `GenerateContainer(image, package, version, vulnID)` | `image` is the repository without the tag when the same image is rebuilt in place, or the digest when every build is a distinct asset. |
| Secret | `GenerateSecret(path, ruleID, line, secretRef)` | `secretRef` MUST NOT be the raw secret: pass the masked value or an HMAC of the secret with a producer-held key. The generator keeps only a 16-character unsalted hash prefix. |
| Misconfiguration / IaC / CSPM | `GenerateMisconfiguration(resourceType, resourceName, ruleID, path)` | `resourceName` is the stable resource ID (ARN, Terraform address), not a display name. |
| DAST / web | `GenerateDAST(templateID, host, path, parameter)` | Query strings and fragments are dropped; `parameter` is the parameter name, never its value. |
| Network / VA (host and port) | `fingerprint.Hash("va:" + assetValue + ":" + pluginID + ":" + port + "/" + protocol)` | `assetValue` is the normalised asset value; `port` is `0` for host-level findings. |
| Compliance | `fingerprint.Hash("compliance:" + framework + ":" + controlID + ":" + assetValue)` | |
| Web3 | `GenerateWeb3(contractAddress, chainID, swcID, functionSignature)` | |

Producers in other languages MUST reproduce the same input strings and hash them with SHA-256; the exact concatenations are in `fingerprint/fingerprint.go`.

## 6. Converters (Go)

### 6.1 SARIF: `ctis.FromSARIF`

- Converts every run. With more than one run, each finding names its run's tool in `properties.sarif_tool`.
- Severity: GitHub's `security-severity` (result, then rule) through `severity.FromCVSS`; else the result `level`, else the rule's `defaultConfiguration.level`; else `medium`.
- Type: `ConvertOptions.ToolType` (`sast`, `sca`, `secret`, `iac`, `web3`); else the rule tags `vulnerability`, `misconfiguration` or `secret` (Trivy); else a CVE or GHSA rule ID means `vulnerability`; else the tool name (secret scanners: gitleaks, betterleaks, trufflehog, detect-secrets, or any name containing `secret`).
- CWE: the rule's `cwe` property (string or array) and tags such as `external/cwe/cwe-079` (CodeQL) or `CWE-89: ...` (Semgrep). OWASP Top 10 IDs from tags such as `OWASP-A03:2021 - Injection`.
- Fingerprint: the result `fingerprints` entry with the lowest key; values longer than 64 characters are SHA-256 hashed. `partialFingerprints`, `correlationGuid` and `baselineState` are carried as `partial_fingerprints`, `correlation_id` and `baseline_state`.
- `kind` is carried as `kind`, with SARIF's camelCase `notApplicable` written as `not_applicable` (matching ignores case and underscores). `baselineState` matching ignores case. A value outside SARIF's set is left unset; an absent `kind` is not defaulted to SARIF's implicit `fail`.
- Tags: `properties.tags` of the result, then of the rule, are carried as `tags` (a string or an array of strings). Order is first seen; whitespace is trimmed; duplicates are dropped ignoring case, keeping the first spelling; empty and non-string entries are skipped. At most 50 tags are kept per finding, and a tag longer than 128 bytes is dropped, not truncated.
- The rule is found by `ruleId`, `rule.id`, `ruleIndex` or `rule.index`.
- Suppressions: the result's `suppressions` become `suppression`. The suppression carried is the first rejected one, else the first under review, else the first accepted one (an absent SARIF status means accepted); `inSource` is written `in_source`, `underReview` `under_review`. `status` is `suppressed` only when SARIF calls the result suppressed: at least one accepted suppression and none under review or rejected. The justification loses control characters and is cut at 2048 bytes.
- The fingerprint placeholder `requires login` (Semgrep OSS) is ignored.
- The asset the options describe gets no criticality.

### 6.2 Recon: `ctis.ConvertReconToCTIS` and `ctis.MergeReconReports`

Output always validates against the schema (tested). Subdomains become `domain` or `subdomain` assets, DNS results `domain` assets with one record per value (types outside the schema enum are kept in `properties.other_dns_records`), port scans `ip_address` assets or, for a target with no IP, `host` assets, HTTP probes `http_service` assets whatever their status code, and crawled URLs `discovered_url` assets. Merging keeps first-seen order, combines assets with the same value, and never modifies its inputs.

## 7. Limits

The schema sets no size limits. OpenCTEM enforces these (API develop, 2026-10):

| Limit | Value |
|---|---|
| Findings per report | 100,000 |
| Assets per report | 100,000 |
| Findings or assets per v2 segment | 10,000 |
| Request body (v2, compressed / decompressed) | 16 MiB / 64 MiB |
| JSON nesting depth (v2) | 64 |
| Size of one property value | 1 MiB |
| Properties per asset / tags per asset | 100 / 50 |

Producers SHOULD split larger results into several reports (or v2 segments).

## 8. What OpenCTEM stores

CTIS carries more than OpenCTEM persists today. As of API develop (2026-10), these members are accepted and validated but not stored or not used. Producers MAY send them; they are informational until the platform reads them:

- `finding.evidence`, `vulnerability.vpr_score`
- `finding.first_seen_at`, `finding.last_seen_at` (imported findings start their age at import time)
- `finding.status`, `finding.suppression`
- `vulnerability.cve_ids` beyond the first CVE (used for network deduplication only)
- `asset.related_assets`, `asset.services`
- `finding.category`, `author`, `author_email`, `commit_date`
- `vulnerability.cvss_version`, `cvss_source`, `severity_source`, `vendor_severity`, `dependency_path`, `layer`, `avd_id`, `vuln_status`
- `vulnerability.in_cisa_kev`, `epss_score`, `epss_percentile` (deliberately: OpenCTEM takes KEV and EPSS from its own threat-intelligence feeds)
- `remediation.fix_available`, `remediation.auto_fixable`
- `data_flow.tainted`, `taint_type`, `vulnerability_type`, `call_path`
- `metadata.source_ref`, `scope.includes`, `scope.excludes`, `branch.pull_request_*`
- `tool.vendor`, `tool.info_url`, `dependency.uid`
- `finding.partial_fingerprints`

## 9. Field reference

Generated from `schemas/v1`. "Required" marks members the schema requires; every other member is optional.

<!-- BEGIN GENERATED FIELD REFERENCE: go test -run TestSpecFieldReference -update -->

### CTIS Report (`report.json`)

CTEM Ingest Schema (CTIS) - Standard format for ingesting security data into OpenCTEM. Normative field semantics: docs/spec.md in https://github.com/openctemio/ctis

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `$schema` | string (uri) |  |  | JSON Schema URL for validation, normally https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/report.json |
| `assets` | array of `asset.json` |  |  | Discovered assets |
| `dependencies` | array of `dependency.json` |  |  | Software dependencies (SBOM) |
| `findings` | array of `finding.json` |  |  | Security findings |
| `metadata` | `ReportMetadata` | yes |  |  |
| `properties` | `Properties` |  |  |  |
| `tool` | `Tool` |  |  |  |
| `version` | string | yes | pattern `^1\.(0\|[1-9][0-9]{0,3})$` | CTIS specification version as MAJOR.MINOR. Receivers accept any minor of their own major; a producer must not send fields newer than the receiver's minor (docs/spec.md, Versioning). The default is the version this schema describes. |

#### BranchInfo

Git branch context for CI/CD scans. Used for branch-aware finding lifecycle management.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `base_branch` | string |  |  | Base branch for PR/MR scans (e.g., 'main' when scanning a PR targeting main) |
| `commit_sha` | string |  |  | Commit SHA being scanned |
| `is_default_branch` | boolean |  |  | Whether this is the default branch (main/master). Auto-resolve only applies to default branch scans. |
| `name` | string |  |  | Branch name (e.g., 'main', 'feature/xyz') |
| `pull_request_number` | integer |  |  | PR/MR number if this is a pull request scan |
| `pull_request_url` | string (uri) |  |  | PR/MR URL if this is a pull request scan |
| `repository_url` | string |  |  | Repository URL for context. Format: domain/owner/repo (e.g., github.com/org/repo) |

#### Properties

Custom properties

Type: object (free-form). 

#### ReportMetadata

Report metadata

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `branch` | `BranchInfo` |  |  |  |
| `coverage_type` | string |  | one of: full, incremental, partial | Coverage type: full (complete scan), incremental (diff scan), partial (specific directories) |
| `duration_ms` | integer |  | minimum 0 | Scan duration in milliseconds |
| `id` | string |  |  | Unique report/scan identifier |
| `properties` | `Properties` |  |  |  |
| `scope` | `Scope` |  |  |  |
| `source_ref` | string |  |  | External reference (job ID, scan ID) |
| `source_type` | string |  | one of: scanner, collector, integration, manual | Type of data source |
| `timestamp` | string (date-time) | yes |  | When the report was generated (ISO 8601) |

#### Scope

Target scope of the scan/collection

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `excludes` | array of string |  |  | Excluded targets |
| `includes` | array of string |  |  | Included targets |
| `name` | string |  |  | Scope name or identifier |
| `type` | string |  | one of: domain, network, repository, cloud_account, blockchain | Scope type |

#### Tool

Tool that generated this report

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `capabilities` | array of string |  | items: one of: vulnerability, secret, misconfiguration, compliance, web3, domain, ip_address, repository, certificate, cloud, container, sast, code_analysis, vulnerability_detection, code_quality, taint_tracking, cross_file_analysis, secrets_detection, supply_chain, sca, dependency_scanning, iac, dast, va, easm, cspm, external, import, subdomain, dns, portscan, http_probe, crawler, tech-detect | What the tool does. OpenCTEM derives a report's detection technique from the first value it recognises (sast, sca, dast, secret, iac, container, va, easm, cspm, external, import, misconfiguration, web3, subdomain, dns, portscan, crawler, tech-detect) and falls back to the tool name. |
| `info_url` | string (uri) |  |  | Tool information URL |
| `name` | string | yes |  | Tool name |
| `properties` | `Properties` |  |  |  |
| `vendor` | string |  |  | Tool vendor/organization |
| `version` | string |  |  | Tool version |

### CTIS Asset (`asset.json`)

Asset schema for CTEM Ingest Schema

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `compliance` | `AssetCompliance` |  |  |  |
| `confidence` | integer |  | minimum 0; maximum 100 | Confidence score (0-100) |
| `criticality` | `Criticality` |  |  |  |
| `description` | string |  |  | Asset description |
| `discovered_at` | string (date-time) |  |  | When asset was discovered |
| `id` | string |  |  | Unique identifier within the report |
| `identifiers` | `AssetIdentifiers` |  |  |  |
| `is_internet_accessible` | boolean |  |  | Is the asset directly accessible from the internet (CTEM) |
| `name` | string |  |  | Human-readable name |
| `properties` | object (free-form) |  |  |  |
| `related_assets` | array of string |  |  | Related asset IDs within this report |
| `services` | array of `ServiceInfo` |  |  | Services running on this asset (CTEM) |
| `tags` | array of string |  |  | Categorization tags |
| `technical` | `AssetTechnical` |  |  |  |
| `type` | `AssetType` | yes |  |  |
| `value` | string | yes |  | Primary value (domain name, IP address, contract address, etc.) |

#### AssetCompliance

CTEM compliance context for an asset

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `data_classification` | string |  | one of: public, internal, confidential, restricted, secret | Data classification level |
| `frameworks` | array of string |  |  | Compliance frameworks this asset is in scope for: PCI-DSS, HIPAA, SOC2, GDPR, ISO27001 |
| `phi_exposed` | boolean |  |  | Asset contains Protected Health Information |
| `pii_exposed` | boolean |  |  | Asset contains Personally Identifiable Information |
| `regulatory_owner` | string |  |  | Regulatory owner email/username |

#### AssetIdentifiers

Identifiers that stay the same when the asset is renamed or readdressed. In order of trust: machine_id, cloud_resource_id, bios_uuid, serial_number, mac_addresses. scm_repo_id identifies a repository.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `bios_uuid` | string |  |  | SMBIOS system UUID |
| `cloud_resource_id` | string |  |  | Cloud instance ID, VM ID or resource ARN |
| `mac_addresses` | array of string |  |  | MAC addresses of the host's network interfaces. Receivers ignore locally administered, multicast and known shared addresses. |
| `machine_id` | string |  |  | Host ID read by a sensor on the host: /etc/machine-id (Linux), MachineGuid (Windows), IOPlatformUUID (macOS) |
| `scm_repo_id` | string |  |  | Repository ID assigned by the source-code host (GitHub repository ID, GitLab project ID) |
| `serial_number` | string |  |  | Hardware serial number |

#### AssetTechnical

Type-specific technical details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `certificate` | `CertificateTechnical` |  |  |  |
| `cloud` | `CloudTechnical` |  |  |  |
| `domain` | `DomainTechnical` |  |  |  |
| `ip_address` | `IPAddressTechnical` |  |  |  |
| `repository` | `RepositoryTechnical` |  |  |  |
| `service` | `ServiceTechnical` |  |  |  |
| `web3` | `web3-asset.json` |  |  |  |

#### AssetType

Asset type. Use unclassified when no type fits. (The deprecated value other was removed in 1.3: the Go types never accepted it; OpenCTEM still files it as unclassified.)

Type: string. one of: domain, subdomain, ip_address, certificate, website, web_application, api, mobile_app, service, repository, cloud_account, compute, storage, database, serverless, container_registry, host, server, container, kubernetes, kubernetes_cluster, kubernetes_namespace, network, vpc, subnet, load_balancer, firewall, iam_user, iam_role, service_account, http_service, open_port, discovered_url, smart_contract, wallet, token, nft_collection, defi_protocol, blockchain, unclassified

#### CertificateTechnical

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `expired` | boolean |  |  |  |
| `fingerprint` | string |  |  |  |
| `issuer_cn` | string |  |  |  |
| `issuer_org` | string |  |  |  |
| `key_algorithm` | string |  |  |  |
| `key_size` | integer |  |  |  |
| `not_after` | string (date-time) |  |  |  |
| `not_before` | string (date-time) |  |  |  |
| `sans` | array of string |  |  |  |
| `self_signed` | boolean |  |  |  |
| `serial_number` | string |  |  |  |
| `signature_algorithm` | string |  |  |  |
| `subject_cn` | string |  |  |  |
| `wildcard` | boolean |  |  |  |

#### CloudTechnical

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `account_id` | string |  |  |  |
| `arn` | string |  |  |  |
| `provider` | string |  | one of: aws, gcp, azure, alibaba, oracle |  |
| `region` | string |  |  |  |
| `resource_id` | string |  |  |  |
| `resource_type` | string |  |  |  |
| `tags` | map of string |  |  |  |
| `zone` | string |  |  |  |

#### Criticality

Asset criticality level

Type: string. one of: critical, high, medium, low, info

#### DNSRecord

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string | yes |  |  |
| `ttl` | integer |  | minimum 0 |  |
| `type` | string | yes | one of: A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV, CAA |  |
| `value` | string | yes |  |  |

#### DomainTechnical

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `dns_records` | array of `DNSRecord` |  |  |  |
| `expires_at` | string (date-time) |  |  |  |
| `nameservers` | array of string |  |  |  |
| `registered_at` | string (date-time) |  |  |  |
| `registrar` | string |  |  |  |
| `whois` | map of string |  |  |  |

#### Geolocation

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `accuracy` | number |  | minimum 0 |  |
| `latitude` | number | yes | minimum -90; maximum 90 |  |
| `longitude` | number | yes | minimum -180; maximum 180 |  |

#### IPAddressTechnical

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `asn` | integer |  |  |  |
| `asn_org` | string |  |  |  |
| `city` | string |  |  |  |
| `country` | string |  | maxLength 2 |  |
| `geolocation` | `Geolocation` |  |  |  |
| `hostname` | string |  |  |  |
| `ports` | array of `PortInfo` |  |  |  |
| `version` | integer |  | one of: 4, 6 |  |

#### PortInfo

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `banner` | string |  |  |  |
| `port` | integer | yes | minimum 1; maximum 65535 |  |
| `protocol` | string |  | one of: tcp, udp |  |
| `service` | string |  |  |  |
| `state` | string |  | one of: open, filtered, closed |  |
| `version` | string |  |  |  |

#### RepositoryTechnical

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `clone_url` | string (uri) |  |  |  |
| `default_branch` | string |  |  |  |
| `forks` | integer |  | minimum 0 |  |
| `languages` | map of integer |  |  |  |
| `last_commit_at` | string (date-time) |  |  |  |
| `last_commit_sha` | string |  |  |  |
| `name` | string |  |  |  |
| `owner` | string |  |  |  |
| `platform` | string |  | one of: github, gitlab, bitbucket, azure_devops |  |
| `stars` | integer |  | minimum 0 |  |
| `url` | string (uri) |  |  |  |
| `visibility` | string |  | one of: public, private, internal |  |

#### ServiceInfo

Network service discovered on an asset (CTEM)

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `banner` | string |  |  | Service banner |
| `cpe` | string |  |  | Common Platform Enumeration identifier |
| `is_public` | boolean |  |  | Is this service publicly accessible from the internet |
| `port` | integer | yes | minimum 1; maximum 65535 | Port number |
| `product` | string |  |  | Product name: Apache, nginx, OpenSSH, etc. |
| `protocol` | string |  | one of: tcp, udp | Transport protocol |
| `service_type` | string |  |  | Service type: http, https, ssh, ftp, mysql, postgresql, etc. |
| `state` | string |  | one of: active, inactive, filtered | Service state |
| `tls_enabled` | boolean |  |  | TLS enabled |
| `tls_version` | string |  |  | TLS version: TLS 1.2, TLS 1.3 |
| `version` | string |  |  | Product version |

#### ServiceTechnical

Technical details for network services (SSH, SMTP, FTP, DNS, HTTP, database services, etc.)

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `anonymous_access` | boolean |  |  | Anonymous access allowed (for FTP, SMB, etc.) |
| `auth_methods` | array of string |  |  | Supported authentication methods (e.g., password, publickey for SSH) |
| `auth_required` | boolean |  |  | Authentication required |
| `banner` | string |  |  | Service banner/fingerprint |
| `cpe` | string |  |  | Common Platform Enumeration (CPE) identifier |
| `default_credentials` | boolean |  |  | Default credentials detected |
| `details` | object (free-form) |  |  | Protocol-specific details (HTTP headers, SMTP extensions, SSH algorithms, etc.) |
| `extra_info` | string |  |  | Additional service information |
| `last_seen` | string (date-time) |  |  | Last seen timestamp |
| `name` | string |  |  | Service name |
| `port` | integer |  | minimum 1; maximum 65535 | Port number |
| `product` | string |  |  | Product name (e.g., OpenSSH, nginx, Apache, Postfix) |
| `protocol` | string |  |  | Application-layer protocol: http, https, ssh, smtp, ftp, dns, ldap, smb, rdp, mysql, postgresql, mongodb, redis, etc. |
| `response_time_ms` | integer |  | minimum 0 | Response time in milliseconds |
| `state` | string |  | one of: open, filtered, closed | Service state |
| `tls` | boolean |  |  | SSL/TLS enabled |
| `tls_cert_expiry` | string (date-time) |  |  | TLS certificate expiry date |
| `tls_cert_issuer` | string |  |  | TLS certificate issuer |
| `tls_cert_subject` | string |  |  | TLS certificate subject |
| `tls_version` | string |  | one of: ssl3, tls1.0, tls1.1, tls1.2, tls1.3 | TLS version |
| `transport` | string |  | one of: tcp, udp | Transport protocol |
| `version` | string |  |  | Service version |

### CTIS Finding (`finding.json`)

Security finding schema for CTEM Ingest Schema

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `asset_ref` | string |  |  | Reference to asset ID within this report |
| `asset_type` | `AssetType` |  |  |  |
| `asset_value` | string |  |  | Direct asset value (if not using asset_ref) |
| `attachments` | array of `Attachment` |  |  | Relevant artifacts or evidence files |
| `author` | string |  |  | Git author name |
| `author_email` | string (email) |  |  | Git author email |
| `baseline_state` | string |  | one of: new, unchanged, updated, absent | Status relative to previous scan (SARIF baselineState) |
| `business_impact` | `BusinessImpact` |  |  |  |
| `category` | string |  |  | Finding category/class |
| `commit_date` | string (date-time) |  |  | Git commit date |
| `compliance` | `ComplianceDetails` |  |  |  |
| `confidence` | integer |  | minimum 0; maximum 100 | Confidence score (0-100) |
| `correlation_id` | string |  |  | Groups logically identical results across runs |
| `data_flow` | `DataFlow` |  |  |  |
| `description` | string |  |  | Detailed description |
| `evidence` | string |  |  | Scanner raw proof/output for this finding (e.g. Nessus plugin_output) |
| `exposure` | `FindingExposure` |  |  |  |
| `fingerprint` | string |  |  | Producer-computed identity of this finding for deduplication, stable across scans. Send a lowercase hex SHA-256 (64 characters); OpenCTEM ignores values that are not hex of at least 16 characters and computes its own. See docs/spec.md, Fingerprints, for the recipe per finding type. |
| `first_seen_at` | string (date-time) |  |  |  |
| `hosted_viewer_uri` | string (uri) |  |  | URI to view this finding in a hosted viewer |
| `id` | string |  |  | Unique identifier within the report |
| `impact` | string |  | one of: critical, high, medium, low | Impact level for risk assessment |
| `kind` | string |  | one of: not_applicable, pass, fail, review, open, informational | Evaluation state of the finding (SARIF kind) |
| `last_seen_at` | string (date-time) |  |  |  |
| `likelihood` | string |  | one of: high, medium, low | Likelihood level for risk assessment |
| `location` | `FindingLocation` |  |  |  |
| `message` | string |  |  | Primary message to display (the main human-readable finding message). If not set, title will be used as the message. |
| `misconfiguration` | `MisconfigurationDetails` |  |  |  |
| `network` | `NetworkLocation` |  |  |  |
| `occurrence_count` | integer |  | minimum 1 | Number of times this result was observed |
| `partial_fingerprints` | map of string |  |  | Contributing identity components for fingerprint calculation |
| `properties` | object (free-form) |  |  |  |
| `rank` | number |  | minimum 0; maximum 100 | Priority/importance score (0-100, SARIF rank) |
| `references` | array of string (uri) |  |  | Reference URLs |
| `related_locations` | array of `FindingLocation` |  |  | Additional locations related to this finding |
| `remediation` | `Remediation` |  |  |  |
| `remediation_context` | `RemediationContext` |  |  |  |
| `rule_id` | string |  |  | Rule/check ID that detected this finding |
| `rule_name` | string |  |  | Rule name |
| `secret` | `SecretDetails` |  |  |  |
| `severity` | `Severity` | yes |  |  |
| `stacks` | array of `StackTrace` |  |  | Call stacks relevant to the finding |
| `status` | `FindingStatus` |  |  |  |
| `subcategory` | array of string |  |  | Subcategories (e.g., audit, vuln, secure default) |
| `suppression` | `Suppression` |  |  |  |
| `tags` | array of string |  |  |  |
| `title` | string | yes |  | Short title |
| `type` | `FindingType` | yes |  |  |
| `vulnerability` | `VulnerabilityDetails` |  |  |  |
| `vulnerability_class` | array of string |  |  | Vulnerability classes (e.g., SQL Injection, XSS) |
| `web3` | `web3-finding.json` |  |  |  |
| `work_item_uris` | array of string (uri) |  |  | URIs of work items (issues, tickets) associated with this finding |

#### ASVSInfo

OWASP ASVS (Application Security Verification Standard) compliance info

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `control_id` | string |  |  | Control ID (e.g., 2.1.1) |
| `control_url` | string (uri) |  |  | Link to ASVS documentation for this control |
| `level` | integer |  | minimum 1; maximum 3 | ASVS level (1, 2, or 3) |
| `section` | string |  |  | ASVS section (e.g., V2: Authentication) |

#### ArtifactLocation

Location of an artifact (SARIF artifactLocation)

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `index` | integer |  | minimum 0 | Index within the producer's artifacts list |
| `uri` | string (uri-reference) |  |  | Absolute or relative URI of the artifact |
| `uri_base_id` | string |  |  | Base URI id the uri is relative to |

#### Attachment

Artifact or evidence attachment (SARIF attachment)

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `artifact_location` | `ArtifactLocation` |  |  |  |
| `description` | string |  |  |  |
| `regions` | array of `FindingLocation` |  |  | Relevant regions within the artifact |

#### BusinessImpact

CTEM business impact assessment for a finding

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `compliance_impact` | array of string |  |  | Compliance frameworks impacted: PCI-DSS, HIPAA, SOC2, GDPR, ISO27001 |
| `data_exposure_risk` | string |  | one of: none, low, medium, high, critical | Data exposure risk level |
| `reputational_impact` | boolean |  |  | Has potential reputational impact |

#### ComplianceDetails

Compliance-specific details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `control_description` | string |  |  |  |
| `control_id` | string |  |  |  |
| `control_name` | string |  |  |  |
| `framework` | string |  | one of: pci-dss, hipaa, soc2, cis, nist, iso27001, gdpr, fedramp |  |
| `framework_version` | string |  |  |  |
| `result` | string |  | one of: pass, fail, manual, not_applicable |  |

#### ContainerLayer

Container layer information for image scans

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `diff_id` | string |  |  | Layer diff ID |
| `digest` | string |  |  | Layer digest (sha256:...) |

#### DataFlow

Taint tracking data flow from source to sink (SARIF codeFlows)

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `call_path` | array of string |  |  | Call graph path (function names in order) |
| `confidence` | integer |  | minimum 0; maximum 100 | Flow confidence score (0-100) |
| `cross_file` | boolean |  |  | Whether data flows across multiple files |
| `intermediates` | array of `DataFlowLocation` |  |  | Intermediate propagation steps |
| `interprocedural` | boolean |  |  | Whether flow crosses function boundaries |
| `sanitizers` | array of `DataFlowLocation` |  |  | Sanitizer locations (where data is cleaned/escaped) |
| `sinks` | array of `DataFlowLocation` |  |  | Taint sink locations (where data reaches dangerous function) |
| `sources` | array of `DataFlowLocation` |  |  | Taint source locations (where untrusted data enters) |
| `summary` | string |  |  | Human-readable summary of the flow |
| `taint_type` | string |  | one of: user_input, file_read, env_var, network, database, header, cookie, session, argv, external | Type of taint origin |
| `tainted` | boolean |  |  | Whether data is still tainted at the sink (false if properly sanitized) |
| `vulnerability_type` | string |  | one of: sql_injection, xss, command_injection, path_traversal, ssrf, ldap_injection, xpath_injection, code_injection, template_injection, deserialization, open_redirect, log_injection, header_injection, xxe, regex_dos | Vulnerability type this flow leads to |

#### DataFlowLocation

Location in data flow trace (SARIF threadFlowLocation)

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `called_function` | string |  |  | For function calls: the function being called |
| `class` | string |  |  | Class/struct name (if applicable) |
| `column` | integer |  | minimum 1 | Column number (1-indexed) |
| `content` | string |  |  | Code content at this location |
| `end_column` | integer |  | minimum 1 | End column |
| `end_line` | integer |  | minimum 1 | End line for multi-line spans |
| `function` | string |  |  | Function/method name containing this location |
| `index` | integer |  | minimum 0 | Step index in the flow (0-indexed) |
| `label` | string |  |  | Variable or expression name being tracked |
| `line` | integer |  | minimum 1 | Line number (1-indexed) |
| `module` | string |  |  | Module/namespace |
| `notes` | string |  |  | Notes for human understanding |
| `operation` | string |  |  | Operation performed: assignment, call, return, parameter, concat, etc. |
| `parameter_index` | integer |  | minimum 0 | For parameters: the parameter index (0-indexed) |
| `path` | string |  |  | File path |
| `taint_state` | string |  | one of: tainted, sanitized, unknown | Taint state at this location |
| `transformation` | string |  |  | Transformation applied: encode, decode, escape, hash, encrypt, etc. |
| `type` | string |  | one of: source, sink, propagator, sanitizer, transform | Location type in the flow |

#### FindingExposure

CTEM exposure information for a finding

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `attack_prerequisites` | string |  |  | Prerequisites for exploitation: auth_required, mfa_required, local_access, etc. |
| `is_internet_accessible` | boolean |  |  | Is the finding directly reachable from the internet |
| `is_network_accessible` | boolean |  |  | Is the finding reachable from the network |
| `vector` | string |  | one of: network, local, physical, adjacent_net | Exposure vector |

#### FindingLocation

Location information for code-based findings

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `branch` | string |  |  | Git branch |
| `commit_sha` | string |  |  | Git commit SHA |
| `context_snippet` | string |  |  | Broader context snippet |
| `context_start_line` | integer |  | minimum 1 | Line where context_snippet starts |
| `end_column` | integer |  | minimum 1 |  |
| `end_line` | integer |  | minimum 1 |  |
| `logical_location` | `LogicalLocation` |  |  |  |
| `path` | string |  |  | File path |
| `snippet` | string |  |  | Code snippet |
| `start_column` | integer |  | minimum 1 |  |
| `start_line` | integer |  | minimum 1 | Start line (1-indexed) |

#### FindingStatus

Finding status

Type: string. one of: open, resolved, suppressed, false_positive, accepted_risk, in_progress

#### FindingType

Finding type

Type: string. one of: vulnerability, secret, misconfiguration, compliance, web3

#### FixRegex

Regex-based auto-fix pattern (for tools like Semgrep)

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `count` | integer |  | minimum 0 | Number of replacements to make (0 = all) |
| `regex` | string |  |  | Regular expression pattern to match |
| `replacement` | string |  |  | Replacement string (may contain capture group references like $1, $2) |

#### LogicalLocation

Logical location within code structure

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `fully_qualified_name` | string |  |  | Fully qualified name |
| `kind` | string |  | one of: function, method, class, module, namespace, type, property | Symbol kind |
| `name` | string |  |  | Symbol name (function, class, method) |
| `parent_index` | integer |  | minimum 0 | Index of the enclosing logical location (SARIF logicalLocation.parentIndex) |

#### MisconfigurationDetails

Misconfiguration-specific details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `actual` | string |  |  |  |
| `avd_id` | string |  | pattern `^AVD-[A-Z]+-\d+$` | Aqua Vulnerability Database ID |
| `cause` | string |  |  |  |
| `expected` | string |  |  |  |
| `namespace` | string |  |  | Policy namespace (builtin.aws.s3) |
| `policy_id` | string |  |  |  |
| `policy_name` | string |  |  |  |
| `provider` | string |  |  | Cloud provider (AWS, GCP, Azure) |
| `query` | string |  |  | Rego query path |
| `resource_name` | string |  |  |  |
| `resource_type` | string |  |  |  |
| `service` | string |  |  | Service name (S3, EC2, IAM) |

#### NetworkLocation

Where a network/host finding was observed (Nessus/Tenable and other network scanners)

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `host` | string |  |  | Host the finding was observed on (IP or hostname) |
| `port` | integer |  | minimum 0; maximum 65535 | Port number; 0 or absent means not port-specific |
| `protocol` | string |  |  | Transport protocol: tcp, udp |
| `service` | string |  |  | Service on the port: https, ssh, smb, mysql, ... |

#### Remediation

Remediation guidance

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `auto_fixable` | boolean |  |  |  |
| `effort` | string |  | one of: trivial, low, medium, high |  |
| `fix_available` | boolean |  |  |  |
| `fix_code` | string |  |  | Suggested fix code - the actual code to replace the vulnerable code (for SAST auto-fix) |
| `fix_regex` | `FixRegex` |  |  |  |
| `recommendation` | string |  |  |  |
| `references` | array of string (uri) |  |  |  |
| `steps` | array of string |  |  |  |

#### RemediationContext

CTEM remediation context for a finding

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `complexity` | string |  | one of: simple, moderate, complex | Fix complexity |
| `estimated_minutes` | integer |  | minimum 0 | Estimated time to fix in minutes |
| `remedy_available` | boolean |  |  | Is a remedy (patch/fix) available |
| `type` | string |  | one of: patch, upgrade, workaround, config_change, mitigate, accept_risk | Remediation type |

#### SecretDetails

Secret-specific details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `age_in_days` | integer |  | minimum 0 | Age of the secret in days, if known |
| `commit_count` | integer |  | minimum 0 | Number of commits the secret appears in |
| `entropy` | number |  | minimum 0 |  |
| `expires_at` | string (date-time) |  |  | When the secret expires |
| `in_history_only` | boolean |  |  | Secret only exists in git history (not current code) |
| `length` | integer |  | minimum 1 |  |
| `masked_value` | string |  |  | Masked value (first/last chars) |
| `revoked` | boolean |  |  |  |
| `revoked_at` | string (date-time) |  |  | When the secret was revoked |
| `rotation_due_at` | string (date-time) |  |  | When secret rotation is due |
| `scopes` | array of string |  |  | API scopes/permissions associated with the secret |
| `secret_type` | string |  | one of: api_key, password, token, certificate, private_key, oauth, jwt, ssh_key, aws_key, gcp_key, azure_key, generic_secret, database_credential, encryption_key |  |
| `service` | string |  |  | Associated service (aws, github, stripe, etc.) |
| `valid` | boolean |  |  | Secret is valid (if verified) |
| `verified_at` | string (date-time) |  |  | When validity was checked |

#### Severity

Severity level

Type: string. one of: critical, high, medium, low, info

#### StackFrame

Single frame in a call stack

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `location` | `FindingLocation` |  |  |  |
| `module` | string |  |  | Module/library name |
| `parameters` | array of string |  |  | Function parameters |
| `thread_id` | integer |  |  |  |

#### StackTrace

Call stack trace (SARIF stack)

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `frames` | array of `StackFrame` |  |  | Stack frames from innermost to outermost |
| `message` | string |  |  | Stack description |

#### Suppression

Finding suppression information (follows SARIF suppression: kind + status)

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `expires_at` | string (date-time) |  |  | When suppression expires |
| `justification` | string |  |  | Detailed justification |
| `kind` | string |  | one of: in_source, external | in_source: suppressed by a comment or annotation in the code; external: suppressed outside the code (a baseline file, a scanner console) |
| `reason` | string |  |  | Short reason code or phrase (false_positive, test_code, risk_accepted, ...) |
| `status` | string |  | one of: accepted, under_review, rejected | Review state of the suppression |
| `suppressed_at` | string (date-time) |  |  |  |
| `suppressed_by` | string |  |  | Who suppressed (user/email) |

#### VulnDataSource

Vulnerability data source information

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string |  |  | Data source ID (nvd, ghsa, osv, etc.) |
| `name` | string |  |  | Data source name |
| `url` | string (uri) |  |  | Data source URL |

#### VulnerabilityDetails

Vulnerability-specific details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `advisories` | array of string (uri) |  |  | Advisory URLs |
| `affected_version` | string |  |  |  |
| `affected_version_range` | string |  |  | Affected version range, e.g. ">=1.0.0, <1.2.5" |
| `asvs` | `ASVSInfo` |  |  |  |
| `avd_id` | string |  | pattern `^AVD-[A-Z]+-\d+$` | Aqua Vulnerability Database ID |
| `cpe` | string |  |  |  |
| `cve_id` | string |  | pattern `^CVE-\d{4}-\d+$` | CVE identifier |
| `cve_ids` | array of string |  | items: pattern `^CVE-\d{4}-\d+$` | All CVEs for this finding (network scanners group multiple per plugin) |
| `cvss_score` | number |  | minimum 0; maximum 10 |  |
| `cvss_source` | string |  | one of: nvd, ghsa, redhat, bitnami, vendor | Source of CVSS score |
| `cvss_vector` | string |  |  |  |
| `cvss_version` | string |  | one of: 2.0, 3.0, 3.1, 4.0 |  |
| `cwe_id` | string |  | pattern `^CWE-\d+$` | Primary CWE identifier |
| `cwe_ids` | array of string |  | items: pattern `^CWE-\d+$` | All related CWE identifiers |
| `data_source` | `VulnDataSource` |  |  |  |
| `dependency_path` | array of string |  |  | Dependency path from root to vulnerable package |
| `ecosystem` | string |  | one of: npm, pip, maven, gradle, nuget, cargo, go, composer, rubygems, hex, pub, swift, cocoapods |  |
| `epss_percentile` | number |  | minimum 0; maximum 1 | EPSS percentile as a fraction 0-1, exactly as FIRST publishes it (0.97 = 97th percentile). Do not send 0-100. |
| `epss_score` | number |  | minimum 0; maximum 1 | EPSS probability of exploitation in the next 30 days, 0-1 (FIRST scale) |
| `exploit_available` | boolean |  |  |  |
| `exploit_maturity` | string |  | one of: none, poc, functional, weaponized |  |
| `fixed_version` | string |  |  |  |
| `fixed_versions` | array of string |  |  | All versions that fix the vulnerability |
| `in_cisa_kev` | boolean |  |  | In CISA Known Exploited Vulnerabilities |
| `is_direct` | boolean |  |  | The vulnerable package is a direct dependency (not transitive) |
| `layer` | `ContainerLayer` |  |  |  |
| `modified_at` | string (date-time) |  |  | Vulnerability last modified date |
| `owasp_ids` | array of string |  | items: pattern `^A\d{2}:\d{4}` | OWASP Top 10 identifiers (e.g., A01:2021, A03:2021) |
| `package` | string |  |  | Affected package |
| `published_at` | string (date-time) |  |  | Vulnerability published date |
| `purl` | string |  |  | Package URL (purl spec) |
| `severity_source` | string |  |  | Source of severity rating (nvd, ghsa, redhat, etc.) |
| `vendor_severity` | map of integer |  |  | Per-vendor severity mapping (vendor name -> severity level 1-5) |
| `vpr_score` | number |  | minimum 0; maximum 10 | Tenable Vulnerability Priority Rating (0-10) |
| `vuln_status` | string |  | one of: affected, fixed, under_investigation, will_not_fix | Vulnerability status |

### CTIS Dependency (`dependency.json`)

Software component or library dependency (SBOM)

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `depends_on` | array of string |  |  | IDs of the dependencies this component depends on |
| `ecosystem` | string |  |  | Package ecosystem (npm, pypi, maven, gomod, etc.) |
| `id` | string |  |  | Unique identifier for the dependency within the report; other dependencies reference it in depends_on |
| `licenses` | array of string |  |  | List of licenses |
| `location` | `FindingLocation` |  |  |  |
| `locations` | array of `DependencyLocation` |  |  | All locations where this dependency is defined |
| `name` | string | yes |  | Component name |
| `path` | string |  |  | File path where defined (manifest file) |
| `properties` | object (free-form) |  |  | Custom properties |
| `purl` | string |  |  | Package URL (PURL) identifier |
| `relationship` | string |  |  | Relationship to the project (direct, indirect, root, transit) |
| `type` | string |  |  | Component type (library, framework, application, os) |
| `uid` | string |  |  | Unique identifier from the scanner (e.g., Trivy UID) |
| `version` | string |  |  | Component version. Recommended; omit only when the version is genuinely unknown. |

#### DependencyLocation

A place where the dependency is declared

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `end_column` | integer |  | minimum 1 | End column number |
| `end_line` | integer |  | minimum 1 | End line number |
| `path` | string |  |  | File path |
| `start_column` | integer |  | minimum 1 | Start column number |
| `start_line` | integer |  | minimum 1 | Start line number |

### Web3 Asset Technical Details (`web3-asset.json`)

Web3-specific technical details for smart contracts, wallets, tokens, and DeFi protocols

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `address` | string |  | pattern `^0x[a-fA-F0-9]{40}$` | Contract/wallet address (EVM format) |
| `chain` | string |  | one of: ethereum, polygon, bsc, arbitrum, optimism, avalanche, fantom, base, solana, near, cosmos | Blockchain network name |
| `chain_id` | integer |  |  | EVM Chain ID (1=mainnet, 137=polygon, 56=bsc, etc.) |
| `contract` | `SmartContractDetails` |  |  |  |
| `defi` | `DeFiDetails` |  |  |  |
| `network_type` | string |  | one of: mainnet, testnet, devnet | Network type |
| `nft` | `NFTCollectionDetails` |  |  |  |
| `token` | `TokenDetails` |  |  |  |
| `wallet` | `WalletDetails` |  |  |  |

#### AuditReport

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `auditor` | string | yes | one of: trail_of_bits, openzeppelin, consensys_diligence, certik, hacken, peckshield, slowmist, quantstamp, cyfrin |  |
| `critical_count` | integer |  | minimum 0 |  |
| `date` | string (date-time) |  |  |  |
| `high_count` | integer |  | minimum 0 |  |
| `low_count` | integer |  | minimum 0 |  |
| `medium_count` | integer |  | minimum 0 |  |
| `report_url` | string (uri) |  |  |  |
| `scope` | string |  |  |  |

#### CoreContract

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `address` | string | yes | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `name` | string | yes |  |  |
| `role` | string |  | one of: router, factory, vault, controller, oracle, governance, timelock |  |

#### DeFiDetails

DeFi protocol-specific details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `audit_reports` | array of `AuditReport` |  |  |  |
| `audited` | boolean |  |  |  |
| `bug_bounty_platform` | string |  | one of: immunefi, hackerone, code4rena, sherlock, hats |  |
| `core_contracts` | array of `CoreContract` |  |  |  |
| `governance_token` | string |  | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `has_bug_bounty` | boolean |  |  |  |
| `max_bounty_usd` | number |  | minimum 0 |  |
| `paused` | boolean |  |  |  |
| `protocol_name` | string |  |  |  |
| `protocol_type` | string |  | one of: dex, lending, yield, bridge, derivatives, insurance, staking, liquid_staking |  |
| `supported_chains` | array of string |  |  |  |
| `timelock_duration` | integer |  | minimum 0 | Timelock in seconds |
| `tvl_usd` | number |  | minimum 0 |  |
| `version` | string |  |  |  |

#### NFTCollectionDetails

NFT collection-specific details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `base_uri` | string |  |  |  |
| `creator` | string |  | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `floor_price` | string |  |  |  |
| `floor_price_usd` | number |  | minimum 0 |  |
| `holder_count` | integer |  | minimum 0 |  |
| `marketplaces` | array of string |  | items: one of: opensea, blur, looksrare, x2y2, rarible, foundation |  |
| `max_supply` | integer |  | minimum 0 |  |
| `metadata_storage` | string |  | one of: ipfs, arweave, centralized, onchain |  |
| `name` | string |  |  |  |
| `revealed` | boolean |  |  |  |
| `royalty_percent` | number |  | minimum 0; maximum 100 |  |
| `royalty_recipient` | string |  | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `standard` | string |  | one of: erc721, erc1155 |  |
| `symbol` | string |  |  |  |
| `total_supply` | integer |  | minimum 0 |  |
| `total_volume` | string |  |  |  |
| `total_volume_usd` | number |  | minimum 0 |  |

#### SmartContractDetails

Smart contract-specific details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `abi` | string |  |  | Contract ABI (JSON string) |
| `address` | string |  | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `balance` | string |  |  | Contract balance in wei |
| `bytecode_hash` | string |  |  |  |
| `compiler_version` | string |  |  |  |
| `contract_type` | string |  | one of: erc20, erc721, erc1155, proxy, multisig, defi, governance, custom |  |
| `deployed_at` | string (date-time) |  |  |  |
| `deployer_address` | string |  | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `deployment_block` | integer |  | minimum 0 |  |
| `deployment_tx_hash` | string |  | pattern `^0x[a-fA-F0-9]{64}$` |  |
| `evm_version` | string |  |  |  |
| `implementation_address` | string |  | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `interfaces` | array of string |  |  | Implemented interfaces (ERC20, ERC721, etc.) |
| `is_proxy` | boolean |  |  |  |
| `is_upgradeable` | boolean |  |  |  |
| `libraries` | array of object |  |  |  |
| `license` | string |  |  |  |
| `name` | string |  |  |  |
| `optimization_enabled` | boolean |  |  |  |
| `optimization_runs` | integer |  |  |  |
| `owner_address` | string |  | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `ownership_renounced` | boolean |  |  |  |
| `proxy_type` | string |  | one of: transparent, uups, beacon, diamond, minimal |  |
| `source_code_hash` | string |  |  |  |
| `source_code_url` | string (uri) |  |  |  |
| `tx_count` | integer |  | minimum 0 |  |
| `verified` | boolean |  |  | Verified on block explorer |

#### TokenBalance

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `balance` | string | yes |  |  |
| `balance_formatted` | string |  |  |  |
| `contract_address` | string | yes | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `decimals` | integer |  | minimum 0; maximum 18 |  |
| `name` | string |  |  |  |
| `symbol` | string |  |  |  |
| `usd_value` | number |  | minimum 0 |  |

#### TokenDetails

Token-specific details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `burnable` | boolean |  |  |  |
| `decimals` | integer |  | minimum 0; maximum 18 |  |
| `has_blacklist` | boolean |  |  |  |
| `has_transfer_fee` | boolean |  |  |  |
| `holder_count` | integer |  | minimum 0 |  |
| `honeypot_reason` | string |  |  |  |
| `is_honeypot` | boolean |  |  |  |
| `liquidity_usd` | number |  | minimum 0 |  |
| `market_cap_usd` | number |  | minimum 0 |  |
| `max_supply` | string |  |  |  |
| `mintable` | boolean |  |  |  |
| `name` | string |  |  |  |
| `pausable` | boolean |  |  |  |
| `price_usd` | number |  | minimum 0 |  |
| `standard` | string |  | one of: erc20, erc721, erc1155, bep20, spl |  |
| `symbol` | string |  |  |  |
| `total_supply` | string |  |  |  |
| `trading_pairs` | array of `TradingPair` |  |  |  |
| `transfer_fee_percent` | number |  | minimum 0; maximum 100 |  |

#### TradingPair

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `dex` | string | yes | one of: uniswap_v2, uniswap_v3, sushiswap, pancakeswap, curve, balancer |  |
| `liquidity_usd` | number |  | minimum 0 |  |
| `pair_address` | string | yes | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `quote_token` | string | yes |  |  |

#### WalletDetails

Wallet-specific details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `balance` | string |  |  | Native token balance in wei |
| `ens_name` | string |  |  |  |
| `first_tx_at` | string (date-time) |  |  |  |
| `labels` | array of string |  | items: one of: exchange, whale, hacker, contract, bridge, defi, nft_trader |  |
| `last_tx_at` | string (date-time) |  |  |  |
| `nft_count` | integer |  | minimum 0 |  |
| `owners` | array of string |  | items: pattern `^0x[a-fA-F0-9]{40}$` |  |
| `provider` | string |  | one of: metamask, ledger, safe, argent, coinbase, rainbow, trustwallet |  |
| `required_signatures` | integer |  | minimum 1 |  |
| `token_balances` | array of `TokenBalance` |  |  |  |
| `total_owners` | integer |  | minimum 1 |  |
| `tx_count` | integer |  | minimum 0 |  |
| `wallet_type` | string |  | one of: eoa, multisig, smart_wallet, mpc |  |

### Web3 Vulnerability Details (`web3-finding.json`)

Web3/Smart contract vulnerability-specific details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `access_control` | `AccessControlIssue` |  |  |  |
| `affected_value_usd` | number |  | minimum 0 |  |
| `attack_vector` | string |  |  | Attack vector description |
| `attacker_addresses` | array of string |  | items: pattern `^0x[a-fA-F0-9]{40}$` |  |
| `bytecode_offset` | integer |  | minimum 0 | Bytecode offset |
| `chain` | string |  |  | Chain name |
| `chain_id` | integer |  |  | EVM Chain ID |
| `contract_address` | string |  | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `detection_confidence` | string |  | one of: high, medium, low |  |
| `detection_tool` | string |  | one of: slither, mythril, securify, manticore, echidna, foundry, aderyn, wake, 4naly3er, solhint, mythx, certora, custom |  |
| `estimated_impact_usd` | number |  | minimum 0 |  |
| `exploitable_on_mainnet` | boolean |  |  |  |
| `flash_loan` | `FlashLoanIssue` |  |  |  |
| `function_selector` | string |  | pattern `^0x[a-fA-F0-9]{8}$` | Function selector (4 bytes) |
| `function_signature` | string |  |  | Affected function signature (e.g., withdraw(uint256)) |
| `gas_issue` | `GasIssue` |  |  |  |
| `is_false_positive` | boolean |  |  |  |
| `oracle_manipulation` | `OracleManipulationIssue` |  |  |  |
| `poc` | `Web3POC` |  |  |  |
| `reentrancy` | `ReentrancyIssue` |  |  |  |
| `related_tx_hashes` | array of string |  | items: pattern `^0x[a-fA-F0-9]{64}$` |  |
| `swc_id` | string |  | pattern `^SWC-\d{3}$` | SWC Registry ID (e.g., SWC-107) |
| `vulnerability_class` | `Web3VulnerabilityClass` |  |  |  |
| `vulnerable_pattern` | string |  |  | Vulnerable code pattern |

#### AccessControlIssue

Access control vulnerability details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `callable_by` | string |  | one of: anyone, owner_only, role_based, whitelist |  |
| `escalation_path` | string |  |  |  |
| `missing_modifier` | string |  |  |  |
| `missing_role_check` | string |  |  |  |
| `unprotected_function` | string |  |  |  |

#### FlashLoanIssue

Flash loan attack vulnerability details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `attack_steps` | array of string |  |  |  |
| `attack_type` | string |  | one of: price_manipulation, governance_attack, collateral_theft, arbitrage, liquidation |  |
| `potential_profit_usd` | number |  | minimum 0 |  |
| `provider` | string |  | one of: aave, dydx, uniswap, balancer, compound, maker |  |
| `required_capital_usd` | number |  | minimum 0 |  |

#### GasIssue

Gas optimization issue details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `current_gas` | integer |  | minimum 0 |  |
| `optimized_gas` | integer |  | minimum 0 |  |
| `savings_percent` | number |  | minimum 0; maximum 100 |  |
| `suggestion` | string |  |  |  |

#### OracleManipulationIssue

Oracle manipulation vulnerability details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `manipulation_method` | string |  | one of: flash_loan, sandwich, time_manipulation, multi_block |  |
| `missing_checks` | array of string |  | items: one of: staleness_check, min_answer_check, max_answer_check, sequencer_check, deviation_check |  |
| `oracle_address` | string |  | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `oracle_type` | string |  | one of: chainlink, uniswap_twap, uniswap_spot, band, tellor, custom |  |
| `price_impact_percent` | number |  | minimum 0 |  |

#### ReentrancyIssue

Reentrancy vulnerability details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `callback` | string |  |  |  |
| `entry_point` | string |  |  |  |
| `external_call` | string |  |  | Vulnerable external call |
| `max_depth` | integer |  | minimum 1 |  |
| `state_modified_after_call` | string |  |  |  |
| `type` | string |  | one of: cross_function, cross_contract, read_only, single_function |  |

#### Web3POC

Proof of concept details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `code` | string |  |  | POC code or script |
| `expected_outcome` | string |  |  |  |
| `fork_block_number` | integer |  | minimum 0 |  |
| `tested_on` | string |  | one of: mainnet_fork, testnet, local |  |
| `tx_data` | string |  |  | Transaction data |
| `type` | string |  | one of: transaction, script, foundry_test, hardhat_test |  |

#### Web3VulnerabilityClass

Web3 vulnerability classification

Type: string. one of: reentrancy, integer_overflow, integer_underflow, access_control, unchecked_call, delegate_call, self_destruct, tx_origin, timestamp_dependence, blockhash_dependence, flash_loan_attack, oracle_manipulation, front_running, sandwich_attack, slippage_attack, price_manipulation, governance_attack, liquidity_drain, mev_vulnerability, honeypot, hidden_mint, hidden_fee, blacklist_abuse, fake_renounce, storage_collision, uninitialized_proxy, upgrade_vulnerability, weak_randomness, signature_malleability, replay_attack, dos_gas_limit, unbounded_loop, dos_block_stuffing, business_logic, invariant_violation

<!-- END GENERATED FIELD REFERENCE -->
