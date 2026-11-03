# Migrating to CTIS 2.0

CTIS 2.0 is a one-time breaking cleanup. There is no compatibility layer: a
2.0 receiver rejects every 1.x document (`ctis.Decode` returns an error that
says to upgrade the producer), and there are no aliases on the wire.
**Upgrade together: producers and receivers move to 2.0 at the same time.**

This page lists every change a producer, a receiver or a Go consumer of
`github.com/openctemio/ctis` has to make. Each row reads old → new.

## Module, packages, files

| Old | New |
|---|---|
| module `github.com/openctemio/ctis` | `github.com/openctemio/ctis/v2` (every import path gains `/v2`) |
| packages `capability`, `tooloption`, `settings`, `outcome`, `politeness`, `edgeprotect`, `addrscope`, `source`, `transfer` (+ `transfer/bundle`) | removed; they live in `github.com/openctemio/contract` v1.0.0 with the same package names. CTIS does not depend on contract |
| `schemas/v1/*.json` (draft-07, `$id` on raw.githubusercontent.com) | `schemas/v2/*.json` (JSON Schema 2020-12, `$id` `https://schemas.openctem.io/ctis/2.0/<file>.json`; identifiers, never fetched) |
| `schemas/extensions/io.openctem/1.json` | `schemas/extensions/io.openctem/2.json` |
| `ctis.SchemaVersion = "1.6"`, `SchemaMajor = 1` | `"2.0"`, `2` |
| media type `application/vnd.openctem.ctis.v1+json` (OpenCTEM transport) | `ctis.MediaType` = `application/vnd.ctis+json`; send `ctis.MediaTypeVersioned` = `application/vnd.ctis+json; version=2.0` |
| file name `*.json` | `ctis.FileSuffix` = `*.ctis.json` |
| `conformance/v1` | `conformance/v2` (v1 vectors stay on branch `release/v1`) |
| `docs/capabilities.md` | moved to the contract module |

## Identifiers (no receiver keys in a document)

| Old | New |
|---|---|
| `metadata.id` optional, "MUST equal the receiver-assigned report id" | **required**, a producer-generated **UUIDv7** (`ctis.NewReportID()`, checked by `ctis.IsReportID`). A retry re-sends the same id; receivers deduplicate on (credential, id). Its binding to a receiver's command or delivery lives only in the receiver profile (`docs/profiles/openctem.md`) |
| `id` / `*_ref` free strings | document-local references: `ctis.DocumentRefPattern`, at most 255 characters, and **never UUID-shaped** (`ctis.IsUUIDShaped`). `asset.id` is required |
| producer ids in `properties` / `metadata.source_ref` | `source_refs[] {system, id}` on metadata, asset and finding (`ctis.SourceRef`) |
| `finding.asset_value` + `finding.asset_type` | removed; `finding.asset_ref` is **required** and names an asset of the document |

## Report and metadata

| Old JSON / Go | New JSON / Go |
|---|---|
| `metadata.timestamp` / `Metadata.Timestamp` | `metadata.generated_at` / `Metadata.GeneratedAt` |
| `metadata.source_type` / `SourceType string` | `metadata.channel` / `Channel ctis.Channel` (`ChannelScanner`, `ChannelCollector`, `ChannelIntegration`, `ChannelManual`) |
| `metadata.source_ref` / `SourceRef` | `metadata.source_refs[]` / `SourceRefs []SourceRef` |
| `metadata.coverage_type` string | `CoverageType ctis.CoverageType` (`CoverageFull`, `CoverageIncremental`, `CoveragePartial`) |
| `metadata.scope` / `Scope` type | removed; per-target outcomes go in `metadata.targets[]` |
| `metadata.capability` / `Metadata.Capability`, `IsCapabilityRef`, `MaxCapabilityRefLen` | removed; `extensions["io.openctem"].capability` on metadata |
| — | `metadata.profiles[]` / `Profiles []Profile` (`core`, `discovery`, `vulnerability`, `code`, `sbom`, `validation`, `web3`) |
| `tool.capabilities` / `Tool.Capabilities []string` | `tool.techniques` / `Tool.Techniques []Technique` (closed: `sast`, `sca`, `secret`, `iac`, `container`, `dast`, `va`, `easm`, `cspm`, `bas`, `pentest`, `manual`) |
| `tool.properties` | removed |
| — | `finding.technique` / `Finding.Technique` (overrides the tool's techniques) |
| `properties` carried receiver meaning | `properties` is an opaque bag: receivers MUST NOT give meaning to it. Namespaced data goes in `extensions` |
| `properties.sarif_tool` | `finding.tool` |

## Assets

| Old JSON / Go | New JSON / Go |
|---|---|
| `asset.discovered_at` / `DiscoveredAt` | `asset.first_seen_at` / `FirstSeenAt` (and `last_seen_at`) |
| `asset.related_assets` / `RelatedAssets` | removed; `relationships[]` |
| `asset.services[]` / `ServiceInfo` | removed; a `service` asset per port, linked from its host by an `exposes` relationship |
| `technical.ip_address.ports[]` / `PortInfo` | removed; `service` assets + `exposes` |
| `asset.is_internet_accessible` bool | `*bool` (absent = unknown; `ctis.Bool(false)` = verified not reachable) |
| `asset.compliance.frameworks` free text (`PCI-DSS`) | `[]ComplianceFramework` registry tokens (`pci_dss`, `hipaa`, `soc2`, `iso27001`, `nist_csf`, `nist_800_53`, `cis`, `gdpr`, `fedramp`, `owasp_asvs`; open token) |
| `compliance.data_classification` string | `DataClassification` enum (`public`, `internal`, `confidential`, `restricted`; `secret` removed) |
| `compliance.pii_exposed`, `phi_exposed` | `has_pii`, `has_phi` |
| `compliance.regulatory_owner` | removed; `owners[]` with `role` |
| `criticality` value `info` / `CriticalityInfo` | removed |
| asset value as the producer wrote it | the **canonical form** of its type (`ctis.CanonicalAssetValue(type, value)`); `Validate` rejects a non-canonical value. Identity = `ctis.AssetKey(type, canonical value)` |
| `NormalizeAssetName(type, name)` (lightweight) | the canonical-form dispatcher (returns the trimmed input when there is no canonical form) |

### Asset types

| Old | New |
|---|---|
| `domain`, `subdomain` (`AssetTypeDomain`, `AssetTypeSubdomain`) | `domain_name` (`AssetTypeDomainName`); the apex is derived |
| `website`, `http_service` (`AssetTypeWebsite`, `AssetTypeHTTPService`) | `web_origin` (`AssetTypeWebOrigin`), value `scheme://host[:port]` |
| `discovered_url` (`AssetTypeDiscoveredURL`) | removed; `endpoints[]` of the `web_origin` |
| `server`, `compute` (`AssetTypeServer`, `AssetTypeCompute`) | `host` (`AssetTypeHost`) |
| `open_port` (`AssetTypeOpenPort`), `service` | `service` (`AssetTypeService`), value `host:port/transport` |
| `iam_user`, `iam_role`, `service_account` | `identity` (`AssetTypeIdentity`) with `technical.identity.kind` (`user`, `role`, `service_account`, `group`, `workload`) |
| `kubernetes` (`AssetTypeKubernetes`) | `kubernetes_cluster` |
| `network` (`AssetTypeNetwork`) | `ip_range` (`AssetTypeIPRange`), value a CIDR |

The 2.0 asset types: `domain_name`, `ip_address`, `ip_range`, `certificate`,
`autonomous_system`, `web_origin`, `web_application`, `api`, `mobile_app`,
`saas_application`, `service`, `repository`, `package`, `container_image`,
`ai_model`, `cloud_account`, `cloud_resource`, `storage`, `database`,
`serverless`, `container_registry`, `host`, `container`,
`kubernetes_cluster`, `kubernetes_namespace`, `kubernetes_workload`,
`endpoint_device`, `iot_device`, `ot_device`, `network_device`, `vpc`,
`subnet`, `load_balancer`, `firewall`, `identity`, `smart_contract`,
`wallet`, `nft_collection`, `defi_protocol`, `token`, `blockchain`,
`unclassified`.

### Technical details

| Old JSON / Go | New JSON / Go |
|---|---|
| `ServiceTechnical.protocol` (application) / `Protocol` | `app_protocol` / `AppProtocol` (IANA service name) |
| `ServiceTechnical.transport` string | `Transport ctis.Transport` (`tcp`, `udp`, `sctp`), required with `port` |
| `ServiceTechnical.name` | removed (`app_protocol`, `product`) |
| `tls` / `TLS`, `tls_enabled` | `is_tls` / `IsTLS` |
| `tls_version` free text | `TLSVersion` enum (`ssl3`, `tls1.0`, `tls1.1`, `tls1.2`, `tls1.3`) |
| `tls_cert_subject`, `tls_cert_issuer`, `tls_cert_expiry` | removed; a `certificate` asset + `serves_certificate` |
| service `state` `active|inactive|filtered` / string | `PortState` (`open`, `closed`, `filtered`) |
| `ServiceTechnical.last_seen` | removed (the asset's `last_seen_at`) |
| `auth_required`, `default_credentials`, `anonymous_access` | `is_auth_required`, `has_default_credentials`, `has_anonymous_access` |
| `ServiceTechnical.details` map[string]any | `map[string]string` |
| certificate `fingerprint` / `Fingerprint` | `sha256_fingerprint` / `SHA256Fingerprint` (equals the asset value) |
| certificate `sans` / `SANs` | `subject_alt_names` / `SubjectAltNames` |
| certificate `self_signed`, `wildcard` | `is_self_signed`, `is_wildcard` |
| certificate `expired` | removed (derive from `not_after`) |
| `repository.clone_url` | removed |
| `ip_address.country` free text | ISO 3166-1 alpha-2 (`^[A-Z]{2}$`) |
| `properties.http_posture` (`HTTPPostureProperty`) | `technical.http.security_headers` / `HTTPTechnical.SecurityHeaders` (cookies as `CookieFlags`) |
| `properties.status_code`, `title`, `web_server`, `content_type`, `redirect_url`, `cdn`, `waf`, `jarm`, `favicon_mmh3`, `tls_version` on http_service | `technical.http` / `HTTPTechnical` on `web_origin` |
| `properties.technologies` | `asset.technologies[]` (typed) |
| `properties.web_content` (`WebContentProperty`) | `extensions["io.openctem"].web_content` (`ctis.WebContentKey`, `ctis.OpenCTEMNamespace`) |
| `properties.import_scope`, `candidate_exposure`, `candidate_unverified`, `bounty_report` | `extensions["io.openctem"].<same key>` |
| `endpoint.parent` / `Parent` | `parent_url` / `ParentURL` |
| `EndpointParam.required` / `Required` | `is_required` / `IsRequired` |

## Findings

| Old JSON / Go | New JSON / Go |
|---|---|
| finding type `web3` (`FindingTypeWeb3`) | removed; `vulnerability` or `weakness` with the `web3` block (web3 is a profile) |
| SAST results without an advisory id typed `vulnerability` | `weakness` (`FindingTypeWeakness`) |
| `impact`, `likelihood`, `business_impact` / `BusinessImpact` | removed (receivers derive risk) |
| `vulnerability_class` / `VulnerabilityClass` | `vulnerability_classes` / `VulnerabilityClasses` |
| `subcategory` / `Subcategory` | `subcategories` / `Subcategories` |
| `attack` / `Attack` | `attack_technique_ids` / `AttackTechniqueIDs` |
| `vulnerability.capec_ids` | `finding.capec_ids` / `Finding.CAPECIDs` |
| `author`, `author_email`, `commit_date` (finding) | `location.commit {sha, author, author_email, committed_at}` / `Location.Commit *CommitInfo` (personal data) |
| `location.commit_sha` / `CommitSHA` | `location.commit.sha` |
| `evidence` (string) / `Evidence` | removed; `evidence_items[]` kind `raw_text` |
| `network.protocol` / `Protocol` | `network.transport` / `Transport ctis.Transport` |
| `network.service` / `Service` | `network.app_protocol` / `AppProtocol` |
| `remediation_context` / `RemediationContext` | merged into `remediation` (`effort`, `estimated_minutes`, `is_fix_available`) |
| `remediation.fix_available` / `FixAvailable` | `is_fix_available` / `IsFixAvailable *bool` |
| `remediation.auto_fixable` / `AutoFixable` | `is_auto_fixable` / `IsAutoFixable` |
| `remediation.references` | removed; `finding.references` |
| `remediation.effort` string | `Effort` enum (`trivial`, `low`, `medium`, `high`); old `complexity simple/moderate/complex` → `low/medium/high` |
| `remediation.solution_type` `patch`, `upgrade`, `config`, `workaround`, `mitigation`, `no_fix` (`SolutionTypePatch`, `SolutionTypeConfig`, `SolutionTypeNoFix`) | CSAF categories `vendor_fix`, `workaround`, `mitigation`, `no_fix_planned`, `none_available` + `config_change`, `upgrade` (`SolutionTypeVendorFix`, `SolutionTypeConfigChange`, `SolutionTypeNoFixPlanned`, `SolutionTypeNoneAvailable`) |
| `exposure.vector` `adjacent_net` | `adjacent` (`ExposureVector`) |
| `exposure.is_network_accessible`, `is_internet_accessible` bool | `*bool` |
| `references`, `work_item_uris`, `hosted_viewer_uri`, `info_url`, `*_url` | http or https only (schema pattern + `Validate`); receivers never fetch them |
| `native.credentialed` / `Credentialed` | `native.is_credentialed` / `IsCredentialed` |
| `source_lifecycle.first_found`, `last_found`, `last_fixed` | `first_found_at`, `last_found_at`, `last_fixed_at` |
| `ScoreSystemVPR` (`vpr`) | removed; `scores[]` system `vendor` with `source: "tenable"` |
| `AllScores(f)` (folded legacy members) | removed; read `f.Scores`. `ctis.PrimaryCVSS(f)` picks the CVSS score to show |
| `CorrelationKey` tool from the caller only | the finding's own `finding.tool` when set |

### Vulnerability, scores and threat signals

| Old JSON / Go | New JSON / Go |
|---|---|
| `cve_id`, `cve_ids` / `CVEID`, `CVEIDs` | `ids[]` / `IDs []VulnerabilityID` (`v.AddID(raw, source)`, `ctis.CVEs(v)`) |
| `cwe_id` / `CWEID` | `cwe_ids` / `CWEIDs` |
| `avd_id` (vulnerability) | `ids[]` `{type: vendor, source: aqua}` |
| `avd_id` (misconfiguration) | `rule_id` / `misconfiguration.policy_id` |
| `cvss_score`, `cvss_vector`, `cvss_version`, `cvss_source` | `scores[]` `{system: cvss, version, vector, value, source}` |
| `epss_score`, `epss_percentile` | `scores[]` `epss` / `epss_percentile` |
| `vpr_score`, `vendor_severity`, `severity_source` | `scores[]` `vendor` with `source` |
| `in_cisa_kev`, `exploit_available`, `exploit_maturity` | `vulnerability.threat_signals[]` (`kev`, `exploited_in_wild`, `public_exploit`, `ransomware_use`, `weaponized`; `source`, `as_of`, `due_on`). `ctis.HasThreatSignal(v, types...)` |
| `vulnerability.advisories` (URLs) | `remediation.advisories[]` `{id, url, source}` |
| `vulnerability.ecosystem` | removed; the ecosystem is the purl type |
| `vulnerability.package` / `Package` | `package_name` / `PackageName` |
| `affected_version` / `AffectedVersion` | `installed_version` / `InstalledVersion` |
| `fixed_version` / `FixedVersion` | `fixed_versions[]` / `FixedVersions` |
| `vuln_status` / `VulnStatus` | removed; `finding.vex.status` |
| `vulnerability.asvs` / `ASVSInfo` | removed; `finding.compliance` with framework `owasp_asvs` |

### Secret, compliance, data flow

| Old JSON / Go | New JSON / Go |
|---|---|
| `secret.secret_type` / `SecretType` | `secret.type` / `Type` |
| `secret.valid` / `Valid` | `secret.is_valid` / `IsValid *bool` |
| `secret.revoked`, `in_history_only` | `is_revoked`, `is_history_only` |
| `secret.age_in_days` / `AgeInDays` | `age_days` / `AgeDays` |
| `compliance.framework` `pci-dss` (free spelling) | registry token `pci_dss` (`ComplianceFramework`) |
| `compliance.result` / `Result` | removed; `finding.kind` (`pass`, `fail`, `review`, `not_applicable`) |
| `data_flow.vulnerability_type` | removed (CWE) |
| `data_flow.tainted`, `interprocedural`, `cross_file` | `is_tainted`, `is_interprocedural`, `is_cross_file` |
| `DataFlowLocation.class` / `Class` | `class_name` / `ClassName` |

### Dependencies

| Old JSON / Go | New JSON / Go |
|---|---|
| `dependency.ecosystem` | removed; purl type |
| `dependency.uid` / `UID` | `source_id` / `SourceID` |
| `dependency.type` free text | `DependencyType` (CycloneDX component types verbatim) |
| `dependency.relationship` free text (`direct`, `indirect`, `transit`, `root`) | `DependencyRelationship` (`root`, `direct`, `transitive`) |
| `dependency.path`, `dependency.location` | `locations[]` |

### Web3 profile

| Old | New |
|---|---|
| `verified`, `optimization_enabled`, `ownership_renounced`, `mintable`, `burnable`, `pausable`, `audited`, `paused`, `revealed`, `exploitable_on_mainnet` | `is_<name>` |
| `defi.timelock_duration` | `timelock_seconds` |
| `audit_reports[].date` | `published_at` |
| auditor, detection tool, marketplace, wallet provider, DEX, bounty platform, oracle and flash-loan provider enums | open tokens |

## Fingerprints

Producers and importers use recipe v2 (`ctis-fp/2`: `fingerprint.V2Auto`,
`V2Generate`, `V2SAST`, `V2SCA`, `V2Secret`, `V2VA`, ...; see
[fingerprints.md](fingerprints.md)). The secret recipe takes an HMAC digest
(`fingerprint.NewSecretDigest`), never the raw value. Recipe v1
(`fingerprint.Generate`, ...) stays in the `fingerprint` package, deprecated,
only so a receiver can compute old → new pairs while migrating stored data.

## Receiver checklist

1. Decode with `ctis.Decode` (2.x only; a 1.x document is an error naming the
   upgrade); run `Validate`.
2. Map the 2.0 asset types to your stored types; key assets on
   `AssetKey(type, canonical value)`.
3. Never read a database key from a document: resolve natural keys and
   `metadata.id` (idempotency, per credential) to your own ids.
4. Read `extensions["io.openctem"]` instead of reserved `properties`.
5. Migrate stored fingerprints from recipe v1 to v2 with the deprecated v1
   functions.
