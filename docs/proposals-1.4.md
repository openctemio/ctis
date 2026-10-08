# Proposals for CTIS 1.4

Status: design record. These proposals came out of a review of CTIS 1.2 and were left out of 1.3, which only reconciles the schema with the Go types and hardens the tooling. Several have since shipped in 1.4 to 1.6, as noted under each heading; the others are open and are not part of the specification. Each item is additive, so it fits a minor release under the rule in [spec.md section 2.2](spec.md#22-compatibility-rule), and each needs receivers (OpenCTEM API) upgraded before producers send it.

## 1. Detection technique

**Superseded** by the capability taxonomy: `metadata.capability` (1.5, spec section 4.11) names the act a report answers, and the capability carries the technique. `tool.techniques` and `finding.technique` were not added. The text below is the original proposal.

**Problem.** OpenCTEM derives the technique (SAST, SCA, DAST, VA, EASM, ...) from report-level `tool.capabilities`. That list mixes three axes (technique, finding type, asset type), contains synonyms (`secret` / `secrets_detection`), and is per report, so a merged or imported report cannot say "finding A is VA, finding B is DAST". OpenCTEM's own producers already send values outside the enum (`smart-contract`, `custom`, `vulnerability_scanning`, `vuln-scan`).

**Proposal.**
- `tool.techniques`: closed enum `sast | sca | secret | iac | container | dast | va | easm | cspm | external`.
- `finding.technique`: optional per-finding override with the same enum.
- Freeze `tool.capabilities` as descriptive and free-form (drop the enum) once receivers read `techniques`.
- Document `metadata.source_type` as the channel (scanner, collector, integration, manual), separate from the technique.

## 2. Web / DAST location

**Implemented in 1.6** as `finding.web`, top-level `endpoints[]` and typed evidence `finding.evidence_items` (spec sections 4.12 and 4.13). The text below is the original proposal.

**Problem.** There is nowhere to put a URL, an HTTP method, a parameter or request/response evidence. A DAST producer had to put the URL in `location.path` (a file path) and fingerprints with the SAST recipe, so every endpoint of one host with the same template collapses into one finding.

**Proposal.** `finding.web`: `url`, `method`, `parameter`, `request`, `response` (each capped, e.g. 64 KiB), `matcher`. Receivers fingerprint with `GenerateDAST(template, host, path, parameter)`.

## 3. Typed relationships

**Implemented in 1.5** as report-level `relationships[]` with the types `subdomain_of`, `resolves_to`, `cname_of`, `exposes`, `serves_certificate` and `hosted_by` (spec section 4.11). `related_assets` is kept. The text below is the original proposal.

**Problem.** `asset.related_assets` is an untyped list of IDs, and OpenCTEM drops it. Attack-path analysis needs typed edges from discovery tools (domain resolves to IP, IP hosts service, service exposes application).

**Proposal.** Report-level `relationships[]`: `{from, to, type}` with `type` in `resolves_to | hosts | runs_on | exposes | member_of | depends_on | contains`, `from`/`to` being asset IDs of the report. Deprecate `related_assets`.

## 4. Exploitability (VEX)

**Implemented in 1.4** as `finding.vex` with the CSAF / OpenVEX status and justification vocabulary (CycloneDX values map through `NormalizeVEXJustification`), plus `statement`, `source` and `as_of`. See spec section 4.10. The text below is the original proposal.

**Problem.** No way to say "this component is present but the vulnerability is not reachable / not affected". CTEM validation and prioritisation need it.

**Proposal.** `vulnerability.analysis`: `state` (`exploitable | not_affected | in_triage | resolved | false_positive`), `justification` (CycloneDX/OpenVEX vocabulary: `code_not_present`, `code_not_reachable`, `requires_configuration`, ...), `detail`.

## 5. Vulnerability aliases

**Implemented in 1.4** as typed `vulnerability.ids[]` (`cve`, `ghsa`, `osv`, `vendor`) with `VulnerabilityIDs` and `PreferredVulnerabilityID`. See spec section 4.10. The text below is the original proposal.

**Problem.** The same vulnerability arrives as CVE, GHSA and OSV IDs from different scanners and is not deduplicated.

**Proposal.** `vulnerability.aliases`: array of IDs (`CVE-...`, `GHSA-...`, `OSV-...`, vendor IDs). Receivers deduplicate on any shared alias.

## 6. KEV detail

**Open.**

**Problem.** `in_cisa_kev` is a boolean; the KEV due date (which drives SLAs) and ransomware use are lost.

**Proposal.** `vulnerability.kev`: `date_added`, `due_date`, `known_ransomware_use`.

## 7. Scan outcome

**Open.** Spec section 4.5 already forbids auto-resolving from a report without `coverage_type`.

**Problem.** `coverage_type: full` drives auto-resolve, but a crashed full scan looks like "everything fixed".

**Proposal.** `metadata.execution`: `successful` (boolean), `errors[]`, and per-target coverage. Receivers MUST NOT auto-resolve from a report whose execution was not successful.

## 8. Smaller items

**Open**, except the size limits, which the 1.4 to 1.6 members state in the schema.

- Tri-state booleans: make the CTEM booleans (`exposure.is_internet_accessible`, `asset.is_internet_accessible`, `remediation_context.remedy_available`, `services[].is_public`, `vulnerability.exploit_available`) `*bool` in Go so "verified false" differs from "unknown". This changes Go field types, so it needs a migration note for Go consumers.
- `dependencies[].asset_ref`, so a dependency names its asset instead of receivers guessing from the manifest path.
- Size limits in the schema (`maxLength`, `maxItems`) matching the receiver limits in spec.md section 7. (1.4 states them for its own new members; the older members still have none.)
- Severity unknown rule: `severity.Level.Priority(Unknown)` sorts below Info while `Severity.Score` treats unknown as Medium; pick one fail-safe rule.
- `owasp_ids`: anchor the pattern once producers send bare IDs (Semgrep tags carry a title after the ID today).
- Move the schemas to draft 2020-12, where `$defs` is a real keyword.
