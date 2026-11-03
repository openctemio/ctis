# Exporters

The interoperability adapters ([interop.md](interop.md)) write a CTIS report out in three standard formats:

| Function | Output | Target version |
|---|---|---|
| `sarif.Export(r *ctis.Report, opts *sarif.ExportOptions) ([]byte, error)` (`interop/sarif`) | SARIF log (JSON) | SARIF 2.1.0 |
| `cyclonedx.Export(r *ctis.Report, opts *cyclonedx.ExportOptions) ([]byte, error)` (`interop/cyclonedx`) | BOM with vulnerabilities (VDR/VEX), JSON | CycloneDX 1.6 |
| `ocsf.Events(r *ctis.Report, opts *ocsf.Options) ([]ocsf.Event, error)`, `ocsf.Export` (`interop/ocsf`) | one event per finding (`Export`: a JSON array) | OCSF 1.3.0 (`ocsf.Version`), classes Vulnerability Finding (2002) and Compliance Finding (2003) |

The mapping is based on the CTIS 2.0 types. Each exporter's export mapping (`interop/<format>/<version>/export.json`) lists every member it writes, its source and the hook that writes it, and holds its value tables (SARIF levels, security-severity scores, precision; CycloneDX hash algorithms, VEX states, justifications, CVSS methods; OCSF severity and status ids). The shared rules are in `internal/exportkit`. Each CTIS object is mapped by its own function (`sarifRuleOf`, `sarifResultOf`, `sarifLocationOf`, `sarifSuppressionsOf`, `sarifCodeFlowOf`, `sarifWebOf`; `cdxComponentOf`, `cdxSubjectOf`, `cdxVulnOf`, `cdxVersionsOf`; `ocsfEventOf`, `ocsfResourceOf`, `ocsfComplianceOf`, `ocsfVulnerabilitiesOf`, `ocsfScoresOf`, `ocsfCodeOf`), so a rename of CTIS members changes one function per object.

## Rules common to every exporter

- **Deterministic.** The same report gives the same bytes. Findings keep the report's order. The SARIF rules catalog is sorted by rule id. CycloneDX components and vulnerabilities are in first-seen order. Maps are written with sorted keys. No exporter reads the clock: a time the output needs and the report lacks comes from the options, else from `metadata.generated_at`. The CycloneDX serial number, when neither the options nor the report give one, is a UUID derived from the report's content.
- **No network.** URL members (`info_url`, `references`, advisory URLs, `repository_url`) are written as given and never fetched.
- **Secrets stay masked.** Every finding is copied and a finding of type `secret` goes through `RedactSecretFinding` before any of it is written. A raw match in the snippet, `secret.masked_value`, the title, the description or a property is masked the way the importers mask it. In HTTP evidence (SARIF `webRequest`/`webResponse`), values under a sensitive span and the values of sensitive headers (`IsSensitiveHeader`) are masked. The caller's report is never modified.
- **Bounded.** The encoded output is refused above `MaxBytes` (256 MiB, the importer's default input limit) with `ErrTooLarge` (the same values in every adapter). The per-member limits of CTIS (`MaxScores`, `MaxVulnerabilityIDs`, `MaxAdvisories`, `MaxDataFlowSteps`) also bound what is written.
- **No receiver context.** The exporters write what the report says about the scan: tool, assets, findings, dependencies. They never add a tenant or receiver identifier.
- **Passthrough.** The members an import kept under `extensions["org.ctis.interop.<format>"]` are written back where the exporter writes nothing and its export mapping does not own the place, after the scrub rules again (interop.md, Passthrough). `NoPassthrough` in the options turns it off.

## SARIF 2.1.0

One report is one run per tool: findings that carry their own `tool` (as `sarif.Import` records for a multi-run log) are written in a run of that tool, with its version.

| CTIS | SARIF |
|---|---|
| `tool.name`, `tool.version`, `tool.info_url` | `run.tool.driver.name`, `version`, `informationUri` (`ctis` when the report has no tool) |
| `metadata.branch` (`repository_url`, `commit_sha`, `name`) | `run.versionControlProvenance[0]` (`repositoryUri`, `revisionId`, `branch`) |
| `rules[]` (the catalog) | `run.tool.driver.rules[]`: every rule with one run, else the rules the run's findings name, in catalog order: `rule_id` → `id`, `name`, `short_description`, `full_description`, `help` → `help.text`, `help_uri` → `helpUri`, `default_severity` → `defaultConfiguration.level` and `security-severity`, `tags`, `cwe_ids` → `properties.cwe`, `id` → `properties["ctis/id"]`. Import reads every one back |
| `rule_ref`, `rule_id` | `result.ruleId` and `ruleIndex` (the catalog rule the finding names, else its rule id). A finding without a catalog rule gets a rule built from it, after the catalog rules: one rule per id, defined by the first finding of that id, sorted by id. A finding without a rule id is reported under `ctis/<type>` |
| `rule_name` | `rule.name` (when the catalog has none) |
| `description` | `rule.shortDescription.text` (when the catalog has none) |
| `references[0]` | `rule.helpUri` (when the catalog has none) |
| `remediation.recommendation` | `rule.help.text` (when the catalog has none) |
| `severity` | `result.level` (critical, high: error; medium: warning; low, info: note) and `properties["security-severity"]`. The value is the finding's CVSS score when it bands to the same severity, else 9.5, 8.0, 5.5, 2.0 or 0.0. The rule carries the same values as `defaultConfiguration.level` and `security-severity` |
| `confidence` 95, 85, 70, 50 | `rule.properties.precision` very-high, high, medium, low |
| `vulnerability.cwe_ids` | `rule.properties.cwe` |
| `vulnerability.owasp_ids` | `rule.properties.owasp` |
| `type` | `rule.properties.tags` holds `vulnerability`, `weakness`, `misconfiguration` or `secret` only when the rule id and tool name would not give the type back |
| `title` (else `message`) | `result.message.text` |
| `tags` | `result.properties.tags` |
| `location` (path, lines, columns, snippet, logical location) | `result.locations[0]` |
| `fingerprint` | `result.fingerprints["ctis/v2"]` |
| `partial_fingerprints` | `result.partialFingerprints` |
| `correlation_id` | `result.correlationGuid` |
| `baseline_state` | `result.baselineState` |
| `kind` | `result.kind` (`not_applicable` is written `notApplicable`) |
| `suppression` (kind, status, justification) | `result.suppressions[0]`. Status `suppressed`, `false_positive` or `accepted_risk` without a suppression becomes an external, accepted suppression whose justification is the status |
| `data_flow` | `result.codeFlows[0].threadFlows[0]`: steps in index order, `kinds` source, sink or sanitizer, function as the logical location, label as the message |
| first `http_exchange` evidence item | `result.webRequest`, `result.webResponse` |

Accepted losses (members SARIF cannot carry, or that `sarif.Import` does not read back):

- `metadata.id`: a converted document is a new document with its own UUIDv7.
- `id` (sarif.Import numbers findings `finding-N`), `asset_ref` and the location's `branch`/`commit`: these come from `sarif.Options` on import.
- `references` after the first. Message arguments and markdown are not written.
- `confidence` other than 95, 85, 70 and 50. It reads back as `sarif.Options.DefaultConfidence`.
- `message`, when the finding also has a title: `result.message` carries the title.
- `remediation`: the recommendation is written as `rule.help`, which sarif.Import does not read. Steps, fix code and advisories are not written.
- `status` other than the suppressed states. Also `suppression.reason`, `suppressed_by`, `suppressed_at` and `expires_at`.
- `category`, `vulnerability_classes`, `location.commit` authors, `secret` details, `scores`, `vex`, `native`, `source_extra`, `properties`, and the vulnerability details other than CWE, OWASP and a CVE or GHSA rule id.
- Data flow members beyond location, function, label and role (`summary`, `taint_type`, `called_function`, `taint_state`, ...).
- Findings of several rules that share an id: the rule's description, CWE and help come from the first one.
- The `compliance`, `exposure`, `malware` and `license` types have no SARIF tag. They come back from the tool name only.

Round-trip fixtures: `interop/sarif/testdata/export/features.sarif` and the SARIF fixtures of `interop/sarif/testdata/sarif/`. Each goes fixture → `sarif.Import` → `sarif.Export` → `sarif.Import` and must give the same report. No member that `sarif.Import` produces is lost; the sidecars `interop/sarif/testdata/export/<fixture>.losses.json` are empty. `examples/sast.json` and `examples/secret.json` go CTIS → `sarif.Export` → `sarif.Import`, and the losses above are listed in `ctis-sast.losses.json` and `ctis-secret.losses.json`. The golden output is `interop/sarif/testdata/export/features.golden.sarif`. Import catalogs the rules results name (rules no result names are not copied) and repeats the rule's text on each finding, so a CTIS → SARIF → CTIS round trip adds `description`, `rule_name`, `references` and `tags` to findings that named a catalog rule (listed in `ctis-sast.losses.json`).

## CycloneDX 1.6

| CTIS | CycloneDX |
|---|---|
| `metadata.properties` `bom_serial_number`, `bom_version`, `bom_timestamp` (set by the importer) | `serialNumber`, `version`, `metadata.timestamp`. Without them: `cyclonedx.ExportOptions.SerialNumber` else a content-derived UUID; version 1; `cyclonedx.ExportOptions.Timestamp` else `metadata.timestamp` |
| `tool` | `metadata.tools.components[0]` |
| subject asset (`cyclonedx.ExportOptions.SubjectAssetID`, else the first asset) | `metadata.component`: bom-ref = asset id, name, version and cpe from the asset properties written by the importer, `purl` when the value is a package URL, type from `component_type`, else from the asset type |
| `dependencies[]` | `components[]`: bom-ref = `id` (else purl, else name@version), `name`, `version`, `type` (default library), `purl`, `licenses` (an SPDX-shaped value as `expression`, anything else as `license.name`) |
| dependency properties `group`, `cpe`, `scope`, `publisher`, `supplier`, `description`, `hash_<alg>`, `property:<name>` | the CycloneDX members of that name, `hashes[]`, `properties[]`. Other string properties are written as `ctis:<key>` |
| `relationship`, `depends_on` | `dependencies[]`: the subject's `dependsOn` lists the direct dependencies; each component lists what it depends on |
| vulnerability findings (type vulnerability) | `vulnerabilities[]`: one per vulnerability id (a CVE, GHSA or OSV `rule_id`, else `vulnerability.ids[0]`), with every affected component in `affects[]` |
| `native.instance_id` | `vulnerabilities[].bom-ref` |
| `vulnerability.data_source` | `source` |
| `vulnerability.ids` other than the id | `references[]` (with the issuer as `source.name`) |
| `scores` (cvss, ssvc, vendor) | `ratings[]`: method CVSSv2, CVSSv3, CVSSv31, CVSSv4, SSVC or other, `score`, `vector`, `source.name`, the label as `severity` when it is a CycloneDX severity. Without scores: the finding's severity |
| `scores` (epss, epss_percentile) | `properties[]` `ctis:score:<system>` (CycloneDX has no rating method for them) |
| `vulnerability.cwe_ids` | `cwes` |
| `message`, `description` | `description`, `detail` (the importer joins them again) |
| `remediation.recommendation`, a `Workaround: ` step, `remediation.advisories` | `recommendation`, `workaround`, `advisories[]` |
| `vulnerability.published_at`, `modified_at` | `published`, `updated` |
| `vex` | `analysis`: status → state (not_affected, exploitable, resolved, in_triage), justification → the source's CycloneDX word when it has one, else the inverse of `NormalizeVEXJustification` (component_not_present and vulnerable_code_not_present → code_not_present, not_in_execute_path → code_not_reachable, cannot_be_controlled_by_adversary → requires_environment, inline_mitigations_already_exist → protected_by_mitigating_control), statement → detail, as_of → lastUpdated |
| `status` false_positive without `vex` | `analysis.state` false_positive |
| `vulnerability.package_name`, `installed_version`, `purl` | the affected component: matched to a dependency by purl, else by name@version, else a component is added for it |
| `source_extra` written by the importer (`affects_versions`, `analysis_response`, `rating_justification:*`, `created`, `rejected`, `property:*`) | `affects[].versions[]`, `analysis.response`, `ratings[].justification`, `created`, `rejected`, `properties[]` |
| `references` not derived from the source or advisories | `properties[]` `ctis:references` |

Only findings of type vulnerability are part of a BOM; the other types are not written.

Accepted losses:

- A not_affected or resolved analysis: the importer turns it into a VEX statement (`importer.Result.VEX`) and drops the finding. The exporter only sees the report, so it cannot write that statement again (sidecar `vdr.losses.json`).
- `id`, `title`, `fingerprint`, `confidence`, `location`, `asset_ref`. The importer builds the title and asset itself.
- `threat_signals`, `is_direct`, `fixed_versions` and `remediation.is_fix_available`.
- `affected_version_range`: it is written as `affects[].versions[].range` and comes back in `source_extra`.
- `dependencies[].locations`, `source_id`.
- `relationship` value `root`: on import it reads as direct.
- VEX `source`: on import it becomes the BOM serial number.
- The justification component_not_present comes back as vulnerable_code_not_present, with native_justification code_not_present.
- The CVSS v3 method: a `CVSSv3` rating with a 3.1 vector comes back as `CVSSv31`.

Round-trip fixture: `interop/cyclonedx/testdata/export/vdr.cdx.json` goes through the importer, `cyclonedx.Export` and the importer again. The report, its findings and dependencies, the VEX statements kept in the report and the unmapped paths come back equal, except for the documented loss in `vdr.losses.json`. `examples/vulnerability-sca.json` goes CTIS → `cyclonedx.Export` → importer, with its losses in `ctis-vulnerability-sca.losses.json`. Golden files: `vdr.golden.cdx.json`, `vulnerability-sca.golden.cdx.json`.

## OCSF 1.3.0

Every finding is one event of the Findings category (`category_uid` 2). Vulnerability, weakness, secret, exposure, malware and license findings are Vulnerability Finding events (2002). Compliance and misconfiguration findings are Compliance Finding events (2003). `type_uid` = `class_uid` × 100 + `activity_id`.

| CTIS | OCSF |
|---|---|
| `fingerprint` (else `id`) | `finding_info.uid` |
| `title` (else `rule_id`), `description` | `finding_info.title`, `finding_info.desc` |
| `category` | `finding_info.types[0]` |
| `rule_id`, `rule_name` | `finding_info.analytic` (`uid`, `name`, type Rule) |
| `first_seen_at`, `last_seen_at` | `finding_info.first_seen_time`, `last_seen_time` (epoch milliseconds) |
| `last_seen_at`, else `first_seen_at`, else `ocsf.Options.Time`, else `metadata.generated_at` | `time` |
| `severity` | `severity_id` (critical 5, high 4, medium 3, low 2, info 1, else 0 Unknown) and `severity` |
| `status` | `status_id` (open 1 New, in_progress 2, suppressed 3, resolved 4, false_positive and accepted_risk 99 with the status name) and `status` |
| `status` resolved | `activity_id` 3 (Close), else 1 (Create) |
| `confidence`, `message` | `confidence_score`, `message` |
| `tool` | `metadata.product` (`name`, `vendor_name`, `version`, `url_string`); `metadata.version` = 1.3.0 |
| the finding's asset (`asset_ref` resolved in the report) | `resources[0]` (`uid`, `name`, `type`) |
| CVE `vulnerability.ids` | `vulnerabilities[i].cve.uid`: one vulnerability object per CVE. The first object carries title, description, packages, code, references and remediation |
| `vulnerability.cwe_ids` | `vulnerabilities[i].cwe.uid` |
| `scores` cvss | `vulnerabilities[0].cve.cvss[]` (`version`, `base_score`, `vector_string`) |
| `scores` epss, epss_percentile | `vulnerabilities[0].cve.epss` (`score`, `percentile`) |
| `vulnerability.package_name`, `installed_version`, `purl`, first of `fixed_versions` | `vulnerabilities[0].affected_packages[0]` |
| `location` (path, start and end line) | `vulnerabilities[0].affected_code[0]` |
| `references` | `vulnerabilities[0].references` |
| a `kev`, `exploited_in_wild`, `public_exploit` or `weaponized` threat signal | `vulnerabilities[0].is_exploit_available` |
| `remediation.recommendation`, `references` | `remediation` (in the vulnerability for 2002, on the event for 2003) |
| `compliance.framework`, `control_id`, `kind` | `compliance.standards[0]`, `control`, `status_id` (pass 1, fail 3, else 99 with the kind) |
| `compliance.framework_version` | `unmapped["compliance_framework_version"]` |
| `misconfiguration.provider`, `policy_id` | `compliance.standards[0]`, `control`, status Fail |
| `type` | `unmapped["ctis_type"]` |
| `secret.type`, `service`, `masked_value` | `unmapped["secret_type"]`, `secret_service`, `secret_masked_value` (masked) |

Accepted losses: everything not in the table. The full list, with reasons, is in `interop/ocsf/testdata/export/*.losses.json`. In short: identity and lifecycle members (`id`, `native`, `source_lifecycle`, `source_extra`, `partial_fingerprints`, suppression details, `vex`), the code context (`data_flow`, columns, snippet, logical location, commit), `evidence_items`, exposure, most misconfiguration, secret and remediation details, non-CVE vulnerability ids, threat signal details, `is_direct`, `owasp_ids`, `fixed_versions` beyond the first, `affected_version_range`, and the CVSS source. Scores of a finding without a CVE have no OCSF place.

OCSF has no importer. The round-trip test reads the events back with a test-only reverse mapper (`ocsfToCTIS` in `interop/ocsf/export_test.go`). The mapped members of the examples `vulnerability-sca`, `network-vulnerability-interop`, `sast`, `secret`, `compliance` and `misconfiguration` must come back equal. Golden files: `interop/ocsf/testdata/export/<example>.golden.ocsf.json` (not `*.golden.json`, which the schema check validates as CTIS reports), and the vectors of `conformance/interop/ocsf/1.3.0`.

## Testing

- `go test ./...` in `interop/sarif`, `interop/cyclonedx` and `interop/ocsf` runs the round trips, goldens, determinism, secret and passthrough tests and the conformance vectors. `-update` rewrites the golden files.
- Sidecar `*.losses.json`: a list of member paths into the compared JSON, each with a reason. `findings[].x` drops a member of every element. `vex[vex.status=not_affected]` drops the elements whose member equals the value. The comparison drops these paths on both sides, so a member that should survive cannot be hidden by accident in another fixture.

## Mapping files

The conversion moved from code to the export mappings where it is field to field:
- the value tables (SARIF `severity_level`, `severity_score`, `confidence_precision`, `kind_out`; CycloneDX `hash_alg`, `justification`, `justification_of_ctis`, `vex_state`, `cvss_method`, `rating_severity`; OCSF `severity`, `status`);
- the complete list of output members, which also fixes where passthrough may be written back.

Structural parts are hooks named in the mapping: the SARIF run, rule catalog, code flow, web exchange and suppressions; the CycloneDX components, dependency graph, vulnerability grouping and VEX analysis; the OCSF event, resources, vulnerabilities, compliance and remediation.

## Follow-ups

The 2.0 members not yet mapped by the exporters:

- CycloneDX and OCSF use the rule name and help of the `rules[]` catalog (SARIF maps it).
- `finding.dependency_ref`: CycloneDX `affects[].ref` from the reference instead of the purl or name match. OCSF `affected_packages` from the referenced dependency. SPDX export, when it is added.
- `finding.validation`: OCSF `finding_info` / `confidence_id` and the SARIF `result.properties`. CycloneDX `analysis` when the validation states exploitability.
- New finding types: pick the OCSF class for each (Detection Finding, Data Security Finding where they fit) and the SARIF type tag. Decide whether CycloneDX writes them (only vulnerability-like types belong in a VDR).
- `relationships` (dependency DEPENDS_ON / CONTAINS types): the CycloneDX `dependencies[]` graph and nested components from the relationships instead of `depends_on`.
- `threat_signals`: OCSF `vulnerabilities[].cve.epss`, `kb_article_list` and an exploit indicator. A CycloneDX property, or a rating where one fits.
- `extensions` of other namespaces than the adapter's own passthrough: written under a CTIS namespace of each format (SARIF `properties`, CycloneDX `ctis:ext:*` properties, OCSF `unmapped`).
- The `unknown` severity is written as SARIF level `none` without security-severity, CycloneDX rating severity `unknown` and OCSF `severity_id` 0 (done).
