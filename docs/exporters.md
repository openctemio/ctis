# Exporters

The Go module writes a CTIS report out in three standard formats:

| Function | Output | Target version |
|---|---|---|
| `ToSARIF(r *Report) ([]byte, error)` | SARIF log (JSON) | SARIF 2.1.0 |
| `ToCycloneDX(r *Report, opts *CycloneDXOptions) ([]byte, error)` | BOM with vulnerabilities (VDR/VEX), JSON | CycloneDX 1.6 |
| `ToOCSF(r *Report, opts *OCSFOptions) ([]OCSFEvent, error)` | one event per finding | OCSF 1.3.0 (`OCSFVersion`), classes Vulnerability Finding (2002) and Compliance Finding (2003) |

The mapping is based on the CTIS 1.6 types. The code is in `export.go` (shared rules), `export_sarif.go`, `export_cyclonedx.go` and `export_ocsf.go`. Each CTIS object is mapped by its own function (`sarifRuleOf`, `sarifResultOf`, `sarifLocationOf`, `sarifSuppressionsOf`, `sarifCodeFlowOf`, `sarifWebOf`; `cdxComponentOf`, `cdxSubjectOf`, `cdxVulnOf`, `cdxVersionsOf`; `ocsfEventOf`, `ocsfResourceOf`, `ocsfComplianceOf`, `ocsfVulnerabilitiesOf`, `ocsfScoresOf`, `ocsfCodeOf`), so a rename of CTIS members changes one function per object.

## Rules common to every exporter

- **Deterministic.** The same report gives the same bytes. Findings keep the report's order. The SARIF rules catalog is sorted by rule id. CycloneDX components and vulnerabilities are in first-seen order. Maps are written with sorted keys. No exporter reads the clock: a time the output needs and the report lacks comes from the options, else from `metadata.timestamp`. The CycloneDX serial number, when neither the options nor the report give one, is a UUID derived from the report's content.
- **No network.** URL members (`info_url`, `references`, advisory URLs, `repository_url`) are written as given and never fetched.
- **Secrets stay masked.** Every finding is copied and a finding of type `secret` goes through `RedactSecretFinding` before any of it is written. A raw match in the snippet, `secret.masked_value`, the title, the description or a property is masked the way the importers mask it. In HTTP evidence (SARIF `webRequest`/`webResponse`), values under a sensitive span and the values of sensitive headers (`IsSensitiveHeader`) are masked. The caller's report is never modified.
- **Bounded.** The encoded output is refused above `MaxExportBytes` (256 MiB, the importer's default input limit) with `ErrExportTooLarge`. The per-member limits of CTIS (`MaxScores`, `MaxVulnerabilityIDs`, `MaxAdvisories`, `MaxDataFlowSteps`) also bound what is written.
- **No receiver context.** The exporters write what the report says about the scan: tool, assets, findings, dependencies. They never add a tenant or receiver identifier.

## SARIF 2.1.0

One report is one run. When `FromSARIF` read a multi-run log, it recorded each finding's tool in `properties["sarif_tool"]`, and the exporter writes one run per tool again.

| CTIS | SARIF |
|---|---|
| `tool.name`, `tool.version`, `tool.info_url` | `run.tool.driver.name`, `version`, `informationUri` (`ctis` when the report has no tool) |
| `metadata.branch` (`repository_url`, `commit_sha`, `name`) | `run.versionControlProvenance[0]` (`repositoryUri`, `revisionId`, `branch`) |
| `rule_id` | `result.ruleId` and `ruleIndex`. `run.tool.driver.rules[]` is built from the findings: one rule per id, defined by the first finding of that id, sorted by id. A finding without a rule id is reported under `ctis/<type>` |
| `rule_name` | `rule.name` |
| `description` | `rule.shortDescription.text` |
| `references[0]` | `rule.helpUri` |
| `remediation.recommendation` | `rule.help.text` |
| `severity` | `result.level` (critical, high: error; medium: warning; low, info: note) and `properties["security-severity"]`. The value is the finding's CVSS score when it bands to the same severity, else 9.5, 8.0, 5.5, 2.0 or 0.0. The rule carries the same values as `defaultConfiguration.level` and `security-severity` |
| `confidence` 95, 85, 70, 50 | `rule.properties.precision` very-high, high, medium, low |
| `vulnerability.cwe_ids` (or `cwe_id`) | `rule.properties.cwe` |
| `vulnerability.owasp_ids` | `rule.properties.owasp` |
| `type` | `rule.properties.tags` holds `vulnerability`, `misconfiguration` or `secret` only when the rule id and tool name would not give the type back |
| `title` (else `message`) | `result.message.text` |
| `tags` | `result.properties.tags` |
| `location` (path, lines, columns, snippet, logical location) | `result.locations[0]` |
| `fingerprint` | `result.fingerprints["ctis/v1"]` |
| `partial_fingerprints` | `result.partialFingerprints` |
| `correlation_id` | `result.correlationGuid` |
| `baseline_state` | `result.baselineState` |
| `kind` | `result.kind` (`not_applicable` is written `notApplicable`) |
| `suppression` (kind, status, justification) | `result.suppressions[0]`. Status `suppressed`, `false_positive` or `accepted_risk` without a suppression becomes an external, accepted suppression whose justification is the status |
| `data_flow` | `result.codeFlows[0].threadFlows[0]`: steps in index order, `kinds` source, sink or sanitizer, function as the logical location, label as the message |
| first `http_exchange` evidence item | `result.webRequest`, `result.webResponse` |

Accepted losses (members SARIF cannot carry, or that `FromSARIF` does not read back):

- `id` (FromSARIF numbers findings `finding-N`), `asset_ref` and the location's `branch`/`commit_sha`: these come from `ConvertOptions` on import.
- `references` after the first. Message arguments and markdown are not written.
- `confidence` other than 95, 85, 70 and 50. It reads back as `ConvertOptions.DefaultConfidence`.
- `message`, when the finding also has a title: `result.message` carries the title.
- `remediation`: the recommendation is written as `rule.help`, which FromSARIF does not read. Steps, fix code and advisories are not written.
- `status` other than the suppressed states. Also `suppression.reason`, `suppressed_by`, `suppressed_at` and `expires_at`.
- `category`, `vulnerability_class`, `author`, `author_email`, `commit_date`, `secret` details, `scores`, `vex`, `native`, `source_extra`, `properties`, and the vulnerability details other than CWE, OWASP and a CVE rule id.
- Data flow members beyond location, function, label and role (`summary`, `taint_type`, `called_function`, `taint_state`, ...).
- Findings of several rules that share an id: the rule's description, CWE and help come from the first one.
- The `compliance` and `web3` types have no SARIF tag. They come back from the tool name only.

Round-trip fixtures: `testdata/export/sarif/features.sarif` and the SARIF fixtures of `testdata/sarif/`. Each goes fixture → `FromSARIF` → `ToSARIF` → `FromSARIF` and must give the same report. No member that `FromSARIF` produces is lost; the sidecars `testdata/export/sarif/<fixture>.losses.json` are empty. `examples/sast.json` and `examples/secret.json` go CTIS → `ToSARIF` → `FromSARIF`, and the losses above are listed in `ctis-sast.losses.json` and `ctis-secret.losses.json`. The golden output is `testdata/export/sarif/features.golden.sarif`.

## CycloneDX 1.6

| CTIS | CycloneDX |
|---|---|
| `metadata.properties` `bom_serial_number`, `bom_version`, `bom_timestamp` (set by the importer) | `serialNumber`, `version`, `metadata.timestamp`. Without them: `CycloneDXOptions.SerialNumber` else a content-derived UUID; version 1; `CycloneDXOptions.Timestamp` else `metadata.timestamp` |
| `tool` | `metadata.tools.components[0]` |
| subject asset (`CycloneDXOptions.SubjectAssetID`, else the first asset) | `metadata.component`: bom-ref = asset id, name, version and cpe from the asset properties written by the importer, `purl` when the value is a package URL, type from `component_type`, else from the asset type |
| `dependencies[]` | `components[]`: bom-ref = `id` (else purl, else name@version), `name`, `version`, `type` (default library), `purl`, `licenses` (an SPDX-shaped value as `expression`, anything else as `license.name`) |
| dependency properties `group`, `cpe`, `scope`, `publisher`, `supplier`, `description`, `hash_<alg>`, `property:<name>` | the CycloneDX members of that name, `hashes[]`, `properties[]`. Other string properties are written as `ctis:<key>` |
| `relationship`, `depends_on` | `dependencies[]`: the subject's `dependsOn` lists the direct dependencies; each component lists what it depends on |
| vulnerability findings (type vulnerability) | `vulnerabilities[]`: one per vulnerability id (a CVE, GHSA or OSV `rule_id`, else `vulnerability.ids[0]`, else `cve_id`), with every affected component in `affects[]` |
| `native.instance_id` | `vulnerabilities[].bom-ref` |
| `vulnerability.data_source` | `source` |
| `vulnerability.ids`, `cve_ids` other than the id | `references[]` (with the issuer as `source.name`) |
| `scores` (cvss, ssvc, vendor) | `ratings[]`: method CVSSv2, CVSSv3, CVSSv31, CVSSv4, SSVC or other, `score`, `vector`, `source.name`, the label as `severity` when it is a CycloneDX severity. Without scores: the legacy `cvss_*` members, else the finding's severity |
| `scores` (epss, epss_percentile, vpr) | `properties[]` `ctis:score:<system>` (CycloneDX has no rating method for them) |
| `vulnerability.cwe_ids` | `cwes` |
| `message`, `description` | `description`, `detail` (the importer joins them again) |
| `remediation.recommendation`, a `Workaround: ` step, `remediation.advisories` | `recommendation`, `workaround`, `advisories[]` |
| `vulnerability.published_at`, `modified_at` | `published`, `updated` |
| `vex` | `analysis`: status → state (not_affected, exploitable, resolved, in_triage), justification → the source's CycloneDX word when it has one, else the inverse of `NormalizeVEXJustification` (component_not_present and vulnerable_code_not_present → code_not_present, not_in_execute_path → code_not_reachable, cannot_be_controlled_by_adversary → requires_environment, inline_mitigations_already_exist → protected_by_mitigating_control), statement → detail, as_of → lastUpdated |
| `status` false_positive without `vex` | `analysis.state` false_positive |
| `vulnerability.package`, `affected_version`, `purl` | the affected component: matched to a dependency by purl, else by name@version, else a component is added for it |
| `source_extra` written by the importer (`affects_versions`, `analysis_response`, `rating_justification:*`, `created`, `rejected`, `property:*`) | `affects[].versions[]`, `analysis.response`, `ratings[].justification`, `created`, `rejected`, `properties[]` |
| `references` not derived from the source or advisories | `properties[]` `ctis:references` |

Findings of type secret, misconfiguration, compliance and web3 are not part of a BOM and are not written.

Accepted losses:

- A not_affected or resolved analysis: the importer turns it into a VEX statement (`importer.Result.VEX`) and drops the finding. The exporter only sees the report, so it cannot write that statement again (sidecar `vdr.losses.json`).
- `id`, `title`, `fingerprint`, `confidence`, `location`, `asset_ref`. The importer builds the title and asset itself.
- `exploit_available`, `exploit_maturity`, `in_cisa_kev`, `is_direct`, `fixed_version(s)`, the legacy `epss_*` members, `advisories` (plain URLs), and `remediation.fix_available`.
- `affected_version_range`: it is written as `affects[].versions[].range` and comes back in `source_extra`.
- `dependencies[].path`, `locations`, `uid`.
- `relationship` values `root` and `transit`. On import they read as indirect.
- VEX `source`: on import it becomes the BOM serial number.
- The justification component_not_present comes back as vulnerable_code_not_present, with native_justification code_not_present.
- The CVSS v3 method: a `CVSSv3` rating with a 3.1 vector comes back as `CVSSv31`.

Round-trip fixture: `testdata/export/cyclonedx/vdr.cdx.json` goes through the importer, `ToCycloneDX` and the importer again. The report, its findings and dependencies, the VEX statements kept in the report and the unmapped paths come back equal, except for the documented loss in `vdr.losses.json`. `examples/vulnerability-sca.json` goes CTIS → `ToCycloneDX` → importer, with its losses in `ctis-vulnerability-sca.losses.json`. Golden files: `vdr.golden.cdx.json`, `vulnerability-sca.golden.cdx.json`.

## OCSF 1.3.0

Every finding is one event of the Findings category (`category_uid` 2). Vulnerability, secret and web3 findings are Vulnerability Finding events (2002). Compliance and misconfiguration findings are Compliance Finding events (2003). `type_uid` = `class_uid` × 100 + `activity_id`.

| CTIS | OCSF |
|---|---|
| `fingerprint` (else `id`) | `finding_info.uid` |
| `title` (else `rule_id`), `description` | `finding_info.title`, `finding_info.desc` |
| `category` | `finding_info.types[0]` |
| `rule_id`, `rule_name` | `finding_info.analytic` (`uid`, `name`, type Rule) |
| `first_seen_at`, `last_seen_at` | `finding_info.first_seen_time`, `last_seen_time` (epoch milliseconds) |
| `last_seen_at`, else `first_seen_at`, else `OCSFOptions.Time`, else `metadata.timestamp` | `time` |
| `severity` | `severity_id` (critical 5, high 4, medium 3, low 2, info 1, else 0 Unknown) and `severity` |
| `status` | `status_id` (open 1 New, in_progress 2, suppressed 3, resolved 4, false_positive and accepted_risk 99 with the status name) and `status` |
| `status` resolved | `activity_id` 3 (Close), else 1 (Create) |
| `confidence`, `message` | `confidence_score`, `message` |
| `tool` | `metadata.product` (`name`, `vendor_name`, `version`, `url_string`); `metadata.version` = 1.3.0 |
| the finding's asset (`asset_ref` resolved in the report, else `asset_value`/`asset_type`) | `resources[0]` (`uid`, `name`, `type`) |
| `vulnerability.cve_id`, `cve_ids`, CVE `ids` | `vulnerabilities[i].cve.uid`: one vulnerability object per CVE. The first object carries title, description, packages, code, references and remediation |
| `vulnerability.cwe_ids` (or `cwe_id`) | `vulnerabilities[i].cwe.uid` |
| `scores` cvss (else the legacy `cvss_*`) | `vulnerabilities[0].cve.cvss[]` (`version`, `base_score`, `vector_string`) |
| `scores` epss, epss_percentile | `vulnerabilities[0].cve.epss` (`score`, `percentile`) |
| `vulnerability.package`, `affected_version`, `purl`, `fixed_version` | `vulnerabilities[0].affected_packages[0]` |
| `location` (path, start and end line) | `vulnerabilities[0].affected_code[0]` |
| `references` | `vulnerabilities[0].references` |
| `vulnerability.exploit_available` | `vulnerabilities[0].is_exploit_available` |
| `remediation.recommendation`, `remediation.references` | `remediation` (in the vulnerability for 2002, on the event for 2003) |
| `compliance.framework`, `control_id`, `result` | `compliance.standards[0]`, `control`, `status_id` (pass 1, fail 3, else 99 with the result) |
| `compliance.framework_version` | `unmapped["compliance_framework_version"]` |
| `misconfiguration.provider`, `policy_id` | `compliance.standards[0]`, `control`, status Fail |
| `type` | `unmapped["ctis_type"]` |
| `secret.secret_type`, `service`, `masked_value` | `unmapped["secret_type"]`, `secret_service`, `secret_masked_value` (masked) |

Accepted losses: everything not in the table. The full list, with reasons, is in `testdata/export/ocsf/*.losses.json`. In short: identity and lifecycle members (`id`, `native`, `source_lifecycle`, `source_extra`, `partial_fingerprints`, suppression details, `vex`), the code context (`data_flow`, columns, snippet, logical location, commit), `evidence`, exposure and business impact, most misconfiguration, secret and remediation details, non-CVE vulnerability ids, `exploit_maturity`, `in_cisa_kev`, `is_direct`, `owasp_ids`, `fixed_versions`, `affected_version_range`, and the CVSS source. Scores of a finding without a CVE have no OCSF place.

OCSF has no importer in this module. The round-trip test reads the events back with a test-only reverse mapper (`ocsfToCTIS` in `export_ocsf_test.go`). The mapped members of the examples `vulnerability-sca`, `network-vulnerability-interop`, `sast`, `secret`, `compliance` and `misconfiguration` must come back equal. Golden files: `testdata/export/ocsf/<example>.golden.json`.

## Testing

- `go test ./ -run Export` runs the round trips, goldens, determinism and secret tests. `-update` rewrites the golden files.
- Sidecar `*.losses.json`: a list of member paths into the compared JSON, each with a reason. `findings[].x` drops a member of every element. `vex[vex.status=not_affected]` drops the elements whose member equals the value. The comparison drops these paths on both sides, so a member that should survive cannot be hidden by accident in another fixture.

## Table-driven parts

Most of the mapping is field to field with a named transform. It can move to declarative mapping files per format and upstream version (one file per adapter version, run by a small engine like `importer/mapping`). This table is the guide for that conversion:

| Part | Table-able | Named transforms it needs |
|---|---|---|
| SARIF driver, result scalars (`message`, `correlationGuid`, `baselineState`, `kind`, `fingerprints`, `partialFingerprints`, `tags`), location and region | yes | `severity_to_sarif_level`, `severity_to_security_severity`, `snake_to_camel` (kind, suppression kind/status), `confidence_to_precision` |
| SARIF rules catalog (group by rule id, first wins, sort, `ruleIndex`) | engine feature: group-by plus index | `first_by_key`, `sort_by` |
| SARIF type tag, decided by the rule id and tool name | no: a code hook (`detectResultType`) |  |
| SARIF code flow (merge four step lists, order by index, role to kinds) | partly: needs list concat and sort | `concat`, `sort_by`, `enum_map` |
| SARIF web request and response (header list to map, sensitive masking) | partly | `headers_to_map`, `mask_sensitive_spans`, `split_http_version` |
| CycloneDX component from a dependency, subject from an asset | yes | `license_to_cdx`, `hash_alg_canonical`, `prefix_strip` (`property:`, `hash_`) |
| CycloneDX dependency graph | engine feature: reference resolution |  |
| CycloneDX vulnerability grouping and affects resolution | no: a code hook (group by vulnerability id, match by purl or name@version) |  |
| CycloneDX ratings, analysis, ids and references | yes | `score_system_to_cdx_method`, `vex_status_to_cdx_state`, `vex_justification_to_cdx`, `cwe_to_int`, `time_rfc3339` |
| CycloneDX description/detail split, affects versions parse | yes, with a string transform | `cut_prefix`, `parse_affects_versions` |
| OCSF event scalars, finding_info, resources, compliance | yes | `severity_to_ocsf_id`, `status_to_ocsf_id`, `time_to_epoch_ms`, `class_of_type` |
| OCSF vulnerabilities fan-out (one object per CVE, CWE zip) | engine feature: zip of lists |  |
| Shared rules (copy, secret redaction, size bound, no clock) | stays in the engine |  |

## Follow-ups for CTIS 1.7 members

Once the 1.7 members land, the exporters need these mappings:

- `finding.rule_ref` and a `rules[]` catalog in the report: SARIF `rules[]` comes from the catalog instead of being built from the findings, and `ruleIndex` follows the catalog. CycloneDX and OCSF use the rule name and help from it.
- `finding.dependency_ref`: CycloneDX `affects[].ref` from the reference instead of the purl or name match. OCSF `affected_packages` from the referenced dependency. SPDX export, when it is added.
- `finding.validation`: OCSF `finding_info` / `confidence_id` and the SARIF `result.properties`. CycloneDX `analysis` when the validation states exploitability.
- New finding types: pick the OCSF class for each (Detection Finding, Data Security Finding where they fit) and the SARIF type tag. Decide whether CycloneDX writes them (only vulnerability-like types belong in a VDR).
- `relationships` (dependency DEPENDS_ON / CONTAINS types): the CycloneDX `dependencies[]` graph and nested components from the relationships instead of `depends_on`.
- `threat_signals`: OCSF `vulnerabilities[].cve.epss`, `kb_article_list` and an exploit indicator. A CycloneDX property, or a rating where one fits.
- `extensions`: written unchanged under a CTIS namespace (SARIF `properties["ctis/extensions"]`, CycloneDX `ctis:ext:*` properties, OCSF `unmapped`), and read back by the importers for a lossless pass-through.
- The `unknown` severity: SARIF level `none` with no security-severity, CycloneDX rating severity `unknown`, OCSF `severity_id` 0.
