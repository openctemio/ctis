# Proposals for CTIS 1.7 and 2.0

Status: design record, not part of the specification. It comes from a review of CTIS 1.6 against what continuous threat exposure management needs, and against what CTIS needs to be a format that many tools and platforms share.

The record has two parts. Items marked **1.7** are additive, so they fit a minor release under the rule in [spec.md section 2.2](spec.md#22-compatibility-rule). Items marked **2.0** rename or remove members. They ship as one cleanup in a new major version (`schemas/v2`, module `github.com/openctemio/ctis/v2`), never as aliases.

**Decision (maintainers, 2026-11-03).** The plan is adopted:

- a 1.6.x patch release fixes the defects found in the review and adds conformance vectors and a validator CLI. It is the last 1.x release;
- the items marked 1.7 are not released as a separate minor: they ship inside 2.0, so producers and receivers change once;
- 2.0 is cut now, as one breaking release, while CTIS has no outside implementers. There are no aliases on the wire and no 1.x intake after the cut: producers and receivers move to 2.0 together;
- contributions to this repository are made under the Developer Certificate of Origin (P10).

## P1. Receiver-neutral specification (1.7, text only)

The normative text names one receiver in several places (sections 4.7, 4.9, 4.11, 5.1 and 7). That behaviour moves to [profiles/openctem.md](profiles/openctem.md), and the specification keeps only what every receiver must do. Closed enums that list products or vendors become open strings with a documented list of known values: `native.scheme`, `vulnerability.cvss_source`, `technical.cloud.provider`, and the auditor, analysis tool, marketplace, wallet, exchange, flash-loan and bug-bounty enums of the web3 schemas. Loosening an enum is additive.

## P2. Forward compatibility across many receivers (1.7)

**Status: done** (additive half of 2.0): spec section 2.2, `ctis.Decode`, `ctis.Unknown`, `ctis.EnumFallback`. There is no conversion between majors.

Today a producer must not send a member newer than the receiver's minor (section 2.2). That works with one receiver, but not when many producers talk to many receivers. Proposal: **version-gated must-ignore**.

- A document that declares the receiver's own minor or an older one is decoded strictly, as today. A typo is still an error.
- In a document that declares a newer minor of the same major, the receiver ignores members it does not know. It maps an enum value it does not know to the member's documented fallback (`unclassified`, `other`, `unknown`).
- Another major is still refused.

The Go module adds `ctis.Decode`, which returns the report and the list of ignored members.

## P3. Extensions instead of reserved properties (1.7, then 2.0)

**Status: the additive part is done**: `extensions` on report, metadata, asset, finding, dependency, endpoint and relationship (spec section 4.14), `schemas/extensions/io.openctem/1.json`. Moving the converters and importers off `properties` is open: receivers read both places for one release train.

Several receivers and converters give meaning to keys inside `properties`. Producers in other projects cannot discover them. Proposal:

- an `extensions` object on the report, metadata, asset, finding, dependency, endpoint and relationship, keyed by reverse-DNS namespace (`io.openctem`, `com.example.scanner`); each namespace may publish a JSON Schema, which a receiver validates when it knows the namespace and otherwise ignores;
- every key that a receiver interprets today becomes a typed member when it is general, or moves to its namespace;
- from 2.0, receivers give no meaning to `properties`.

## P4. CTEM coverage (1.7)

**Status: done except `rules[]`/`finding.rule_ref`** (spec sections 4.15 and 4.16). The rule catalog is open.

- Finding types `exposure` (something reachable that should not be), `weakness` (a code or design weakness without an advisory id), `malware` (malicious code or package) and `license`; severity value `unknown`.
- `finding.validation`:
  - `status`: `exploited`, `not_exploited`, `blocked`, `detected`, `not_reproducible` or `not_tested`;
  - `method`: `pentest`, `bas`, `automated_exploit`, `retest` or `manual_review`;
  - plus `validated_at`, `validator`, `evidence_refs` and `notes`. This covers the validation stage, retests and manual reports.
- `finding.tool`, which overrides the report's tool for merged or imported reports.
- Relationship types `contains`, `runs_on`, `depends_on`, `deployed_from`, `member_of`, `routes_to` and `has_access_to`. Each type has one direction, read as "from <type> to", with no inverse duplicates.
- `dependencies[].asset_ref` (where the component was found) and `finding.dependency_ref` (which component the finding affects).
- Asset context: `environment` (`production`, `staging`, `development`, `test`, `unknown`) and `owners[]` (`kind`, `ref`, `role`). Assets also get `first_seen_at` and `last_seen_at`.
- Asset types that have no equivalent today: `package`, `container_image`, `identity`, `saas_application`, `endpoint_device`, `iot_device`, `ot_device`, `network_device`, `autonomous_system`, `cloud_resource`, `kubernetes_workload`, `ai_model`.
- `vulnerability.capec_ids`.
- `vulnerability.threat_signals[]`: `type` (`kev`, `exploited_in_wild`, `public_exploit`, `ransomware_use`, `weaponized`), `source`, `as_of`, `ref` and `due_on`. These are assertions with a source and a date; receivers prefer their own intelligence.
- A top-level `rules[]` catalog (id, name, descriptions, help URL, CWE ids, tags) with `finding.rule_ref`. Findings stop repeating rule text, and a round trip through SARIF keeps rule metadata.

## P5. Completeness and absence (1.7)

**Status: done** (spec section 4.17), with asset `state`/`state_reason` for the authoritative gone signal.

`metadata.coverage_type` is report-wide. What happened to each target lives outside the report. Proposal:

- `metadata.targets[]`: `target`, `kind`, `state` (`done`, `failed`, `skipped`, `unfinished`), `class` and `cause`, in the vocabulary of the `outcome` package;
- `metadata.started_at`, `metadata.ended_at`;
- `metadata.segment` (`index`, `count`) for a result split over several documents that share one `metadata.id`.

Normative rule:

- Something seen earlier on target T is **gone** only when a report with `coverage_type: full` lists T with state `done` and does not contain it. Every other absence means **not seen**.
- An asset may carry `state: gone` only on an authoritative signal: a name that no longer exists, or a resource the provider reports deleted.
- A report is a set of observations, never a patch.

## P6. Canonical forms and keys (1.7, text and test vectors)

The canonical value of each asset type becomes normative, with test vectors every implementation runs:

- domain names: lowercase, IDNA A-label, no trailing dot;
- IP addresses: RFC 5952 for IPv6, mapped IPv4 as IPv4, no zone; ranges in CIDR form;
- services as `host:port/transport`; web origins and URLs keep the path's case, carry no user info, fragment or query values, and drop the default port;
- repositories, versionless purls, CPE 2.3 formatted strings, cloud resource ids per provider, image digests, and certificate SHA-256 of the DER.

The asset key is `uuidv5(namespace, type + 0x1F + canonical value)`. A finding's correlation key is (asset key, preferred vulnerability id or `rule:<tool>/<rule_id>`, location key). The location key also reads `finding.web`. Receivers compute both; producers never send them.

## P7. Fingerprints, recipe version 2 (2.0)

- Recipes join their fields with 0x1F and carry a version prefix.
- Case-sensitive paths keep their case.
- No recipe hashes a message.
- The secret recipe takes only a keyed hash (HMAC) of the secret.
- The network and compliance recipes become functions instead of prose.

During the switch, producers also send the version 1 value in `partial_fingerprints`, so receivers carry triage over without reopening findings.

## P8. Renames and removals (2.0)

| Current | Proposed | Reason |
|---|---|---|
| `metadata.timestamp` | `metadata.generated_at` | timestamps end in `_at` |
| `metadata.source_type` | `metadata.channel` | it is the channel a report came through |
| `metadata.id` (equals the receiver's id) | producer-generated UUID, the idempotency key | binding to a job belongs to the transport |
| `metadata.capability` | `extensions["io.openctem"].capability` | a receiver's taxonomy, not interchange |
| `metadata.scope` | `metadata.targets[]` | per-target outcome |
| `tool.capabilities` | `tool.techniques[]` and `finding.technique` | one axis per member, no synonyms |
| `asset.discovered_at` | `asset.first_seen_at` | pair with `last_seen_at` |
| `asset.related_assets` | `relationships[]` | typed edges |
| `asset.services[]`, `technical.service`, `technical.ip_address.ports[]` | one `service` asset and an `exposes` edge | three shapes for one thing |
| `protocol` meaning tcp or udp | `transport` | one name per concept |
| `technical.service.protocol`, `services[].service_type` | `app_protocol` | not the transport |
| `tls`, `tls_enabled` | `is_tls` | boolean naming |
| `technical.service.last_seen` | `last_seen_at` | timestamps end in `_at` |
| certificate `fingerprint`, `sans` | `sha256_fingerprint`, `subject_alt_names` | algorithm and meaning in the name |
| certificate `self_signed`, `wildcard`, `expired` | `is_self_signed`, `is_wildcard`; `expired` removed | boolean naming; derived state goes stale |
| asset types `domain`, `subdomain` | `domain_name` | one name has one type |
| asset types `website`, `http_service` | `web_origin` | one origin has one type |
| asset type `discovered_url` | `endpoints[]` | endpoints exist since 1.6 |
| asset types `server`, `compute` | `host` | overlap |
| asset type `open_port` | `service` | overlap |
| asset types `iam_user`, `iam_role`, `service_account` | `identity` with a kind | one type |
| asset types `kubernetes`, `network` | `kubernetes_cluster`, `ip_range` | say what they are |
| criticality `info` | removed | not a business criticality |
| finding type `web3` | removed; web3 becomes a profile | a domain, not a kind of finding |
| `finding.asset_value`, `finding.asset_type` | `asset_ref` required | one way to name an asset |
| `vulnerability.cve_id`, `cve_ids` | `vulnerability.ids[]` | one list |
| `cwe_id`, `cwe_ids` | `cwe_ids` | duplicate |
| `cvss_*`, `epss_*`, `vpr_score`, `vendor_severity`, `severity_source` | `scores[]` | one list with source and date |
| `in_cisa_kev`, `exploit_available`, `exploit_maturity` | `threat_signals[]` | assertions with source and date |
| `vulnerability.advisories` (URLs) | `remediation.advisories[]` | two shapes |
| `vulnerability.ecosystem` | purl type | one package vocabulary |
| `vulnerability.package`, `affected_version` | `package_name`, `installed_version` | "affected version" reads as a range |
| `fixed_version`, `fixed_versions` | `fixed_versions` | duplicate |
| `avd_id` (vulnerability and misconfiguration) | `ids[]` with type `vendor` | a product name in a member |
| `vuln_status` | `vex.status` | duplicate vocabulary |
| `vulnerability.asvs` | `compliance` with framework `owasp_asvs` | it is a control |
| `remediation_context` | merged into `remediation` | duplicate object, conflicting enums |
| `remediation.solution_type` values | CSAF remediation categories plus `config_change`, `upgrade` | lossless CSAF round trip |
| `fix_available`, `auto_fixable` | `is_fix_available`, `is_auto_fixable` | boolean naming |
| `remediation.references` | finding `references` | duplicate |
| `impact`, `likelihood`, `business_impact` | removed | receivers derive risk |
| `exposure.vector` `adjacent_net` | `adjacent` | the CVSS term |
| compliance framework spellings | one list: `pci_dss`, `hipaa`, `soc2`, `iso27001`, `nist_csf`, `nist_800_53`, `cis`, `gdpr`, `fedramp`, `owasp_asvs` | three vocabularies today |
| `compliance.result` | `kind` | one evaluation member |
| `subcategory`, `vulnerability_class` | `subcategories`, `vulnerability_classes` | arrays are plural |
| `attack` | `attack_technique_ids` | ids end in `_ids` |
| `author`, `author_email`, `commit_date` | `location.commit` with `committed_at` | grouping, timestamps end in `_at` |
| `evidence` | `evidence_items` of kind `raw_text` | duplicate |
| `secret.secret_type`, `valid`, `revoked`, `in_history_only`, `age_in_days` | `type`, `is_valid`, `is_revoked`, `is_history_only`, `age_days` | naming rules |
| `data_flow.vulnerability_type` | removed | CWE says it |
| data flow location `class` | `class_name` | a reserved word in most languages |
| `web.method` value `""` | removed | an empty enum value |
| `dependency.relationship`, `type` (free text) | enums `root`/`direct`/`transitive` and the CycloneDX component types | one vocabulary |
| `dependency.path`, `location`, `locations` | `locations[]` | three members |
| `timelock_duration` | `timelock_seconds` | durations name their unit |
| `$id` on `raw.githubusercontent.com/.../main` | versioned `$id` on the project's own domain, JSON Schema 2020-12 | immutable, neutral |

Version 2.0 also gives every member a size limit in the schema, restricts URL members to `http` and `https`, and marks members that hold personal data.

## P9. Interoperability

The Go module gains exporters to SARIF, CycloneDX (vulnerability and VEX) and OCSF, next to its importers. Each format gets round-trip fixtures that list the losses it accepts. Conformance vectors (canonical forms, keys, fingerprints, valid and invalid documents) live in `conformance/`, and implementations in other languages run the same files.

## P10. Governance

A shared format needs a home that no single implementer controls:

- the specification repository separate from receiver-specific code;
- specification text under CC BY 4.0 and schemas and code under Apache-2.0;
- a patent commitment for implementers;
- contributions under the Developer Certificate of Origin (adopted 2026-11-03, see GOVERNANCE.md);
- a public proposal process;
- maintainers from more than one organisation once there are other implementers;
- a validator CLI and a conformance suite that every implementation, including the original one, passes.
