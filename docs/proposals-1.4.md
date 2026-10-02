# Proposals for CTIS 1.4

Status: draft, not implemented. These came out of the 2026-10 review of CTIS 1.2 and were left out of 1.3, which only reconciles the schema with the Go types and hardens the tooling. Each item is additive, so it fits a minor release under the rule in [spec.md section 2.2](spec.md#22-compatibility-rule), and each needs receivers (OpenCTEM API) upgraded before producers send it.

## 1. Detection technique

**Problem.** OpenCTEM derives the technique (SAST, SCA, DAST, VA, EASM, ...) from report-level `tool.capabilities`. That list mixes three axes (technique, finding type, asset type), contains synonyms (`secret` / `secrets_detection`), and is per report, so a merged or imported report cannot say "finding A is VA, finding B is DAST". OpenCTEM's own producers already send values outside the enum (`smart-contract`, `custom`, `vulnerability_scanning`, `vuln-scan`).

**Proposal.**
- `tool.techniques`: closed enum `sast | sca | secret | iac | container | dast | va | easm | cspm | external`.
- `finding.technique`: optional per-finding override with the same enum.
- Freeze `tool.capabilities` as descriptive and free-form (drop the enum) once receivers read `techniques`.
- Document `metadata.source_type` as the channel (scanner, collector, integration, manual), separate from the technique.

## 2. Web / DAST location

**Problem.** There is nowhere to put a URL, an HTTP method, a parameter or request/response evidence. The OpenCTEM Nuclei adapter puts the URL in `location.path` (a file path) and fingerprints with the SAST recipe, so every endpoint of one host with the same template collapses into one finding.

**Proposal.** `finding.web`: `url`, `method`, `parameter`, `request`, `response` (each capped, e.g. 64 KiB), `matcher`. Receivers fingerprint with `GenerateDAST(template, host, path, parameter)`.

## 3. Typed relationships

**Problem.** `asset.related_assets` is an untyped list of IDs, and OpenCTEM drops it. Attack-path analysis needs typed edges from discovery tools (domain resolves to IP, IP hosts service, service exposes application).

**Proposal.** Report-level `relationships[]`: `{from, to, type}` with `type` in `resolves_to | hosts | runs_on | exposes | member_of | depends_on | contains`, `from`/`to` being asset IDs of the report. Deprecate `related_assets`.

## 4. Exploitability (VEX)

**Problem.** No way to say "this component is present but the vulnerability is not reachable / not affected". CTEM validation and prioritisation need it.

**Proposal.** `vulnerability.analysis`: `state` (`exploitable | not_affected | in_triage | resolved | false_positive`), `justification` (CycloneDX/OpenVEX vocabulary: `code_not_present`, `code_not_reachable`, `requires_configuration`, ...), `detail`.

## 5. Vulnerability aliases

**Problem.** The same vulnerability arrives as CVE, GHSA and OSV IDs from different scanners and is not deduplicated.

**Proposal.** `vulnerability.aliases`: array of IDs (`CVE-...`, `GHSA-...`, `OSV-...`, vendor IDs). Receivers deduplicate on any shared alias.

## 6. KEV detail

**Problem.** `in_cisa_kev` is a boolean; the KEV due date (which drives SLAs) and ransomware use are lost.

**Proposal.** `vulnerability.kev`: `date_added`, `due_date`, `known_ransomware_use`.

## 7. Scan outcome

**Problem.** `coverage_type: full` drives auto-resolve, but a crashed full scan looks like "everything fixed".

**Proposal.** `metadata.execution`: `successful` (boolean), `errors[]`, and per-target coverage. Receivers MUST NOT auto-resolve from a report whose execution was not successful.

## 8. Smaller items

- Tri-state booleans: make the CTEM booleans (`exposure.is_internet_accessible`, `asset.is_internet_accessible`, `remediation_context.remedy_available`, `services[].is_public`, `vulnerability.exploit_available`) `*bool` in Go so "verified false" differs from "unknown". This changes Go field types, so it needs a migration note for Go consumers.
- `dependencies[].asset_ref`, so a dependency names its asset instead of receivers guessing from the manifest path.
- Size limits in the schema (`maxLength`, `maxItems`) matching the receiver limits in spec.md section 7.
- Severity unknown rule: `severity.Level.Priority(Unknown)` sorts below Info while `Severity.Score` treats unknown as Medium; pick one fail-safe rule.
- `owasp_ids`: anchor the pattern once producers send bare IDs (Semgrep tags carry a title after the ID today).
- Move the schemas to draft 2020-12, where `$defs` is a real keyword.
