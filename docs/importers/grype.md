# grype JSON output mapping

Generated from `importer/spec_grype.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `grype`
- Source versions: grype 0.7x-0.8x `-o json`
- Fields: 84 mapped, 49 ignored on purpose (63% mapped)

## Rules

- One asset for the scanned source: an image is a container asset named by the image reference, a directory or file a repository asset named by its path, an SBOM an unclassified asset; Options.DefaultAsset replaces it.
- One finding per match on that asset, with the package, version, PURL and CPE of the artifact; one dependency per artifact.
- Severity: the severity word (Critical, High, Medium, Low, Negligible); Unknown falls back to the best CVSS score, else medium with an issue.
- Every CVSS entry of the vulnerability and of its related vulnerabilities goes to finding.scores with its source (nvd@nist.gov is nvd); the legacy cvss_* members take the newest version.
- The scan configuration in descriptor.configuration (registry settings, paths, credentials) is never read.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/matches` | (container) |  |
| `/matches[]` | `findings[]` |  |
| `/matches[]/vulnerability` | (container) |  |
| `/matches[]/vulnerability/fix` | (container) |  |
| `/matches[]/vulnerability/fix/versions` | (container) |  |
| `/matches[]/vulnerability/fix/versions[]` | `findings[].vulnerability.fixed_versions, fixed_version, remediation.recommendation` |  |
| `/matches[]/vulnerability/fix/state` | `findings[].remediation.fix_available, solution_type, source_extra.fix_state` |  |
| `/matches[]/vulnerability/fix/available*` |  | per-version availability dates; the fixed versions are kept |
| `/matches[]/vulnerability/fix/available*/**` |  | per-version availability dates; the fixed versions are kept |
| `/matches[]/vulnerability/advisories` | (container) |  |
| `/matches[]/vulnerability/advisories[]` | (container) |  |
| `/matches[]/vulnerability/advisories[]/id` | `findings[].remediation.advisories[].id` |  |
| `/matches[]/vulnerability/advisories[]/link` | `findings[].remediation.advisories[].url (http(s) only)` |  |
| `/matches[]/vulnerability/risk` | `findings[].scores[] (vendor, label risk, source grype)` |  |
| `/matches[]/relatedVulnerabilities` | (container) |  |
| `/matches[]/relatedVulnerabilities[]` | (container) |  |
| `/matches[]/vulnerability/id` | `findings[].rule_id, native.vuln_id, vulnerability.ids[]` |  |
| `/matches[]/vulnerability/dataSource` | `findings[].references (http(s) only)` |  |
| `/matches[]/vulnerability/namespace` | `findings[].native.family, scores[].source (fallback), source_extra.namespace` |  |
| `/matches[]/vulnerability/severity` | `findings[].severity, native.severity` |  |
| `/matches[]/vulnerability/urls` | (container) |  |
| `/matches[]/vulnerability/urls[]` | `findings[].references (http(s) only)` |  |
| `/matches[]/vulnerability/description` | `findings[].description` |  |
| `/matches[]/vulnerability/cvss` | (container) |  |
| `/matches[]/vulnerability/cvss[]` | `findings[].scores[] (cvss, one per entry), vulnerability.cvss_* (best)` |  |
| `/matches[]/vulnerability/cvss[]/source` | `findings[].scores[].source` |  |
| `/matches[]/vulnerability/cvss[]/type` |  | Primary or Secondary; the source is kept |
| `/matches[]/vulnerability/cvss[]/version` |  | the version is read from the vector |
| `/matches[]/vulnerability/cvss[]/vector` | `findings[].scores[].vector, version` |  |
| `/matches[]/vulnerability/cvss[]/metrics` | (container) |  |
| `/matches[]/vulnerability/cvss[]/metrics/baseScore` | `findings[].scores[].value` |  |
| `/matches[]/vulnerability/cvss[]/metrics/exploitabilityScore` |  | a sub-score derived from the vector |
| `/matches[]/vulnerability/cvss[]/metrics/impactScore` |  | a sub-score derived from the vector |
| `/matches[]/vulnerability/cvss[]/vendorMetadata` |  | feed-specific metadata |
| `/matches[]/vulnerability/cvss[]/vendorMetadata/**` |  | feed-specific metadata |
| `/matches[]/vulnerability/epss` | (container) |  |
| `/matches[]/vulnerability/epss[]` | (container) |  |
| `/matches[]/vulnerability/epss[]/cve` |  | the CVE the EPSS entry is for; it is one of the finding's ids |
| `/matches[]/vulnerability/epss[]/epss` | `findings[].scores[] (epss), vulnerability.epss_score` |  |
| `/matches[]/vulnerability/epss[]/percentile` | `findings[].scores[] (epss_percentile), vulnerability.epss_percentile` |  |
| `/matches[]/vulnerability/epss[]/date` | `findings[].scores[].as_of` |  |
| `/matches[]/vulnerability/knownExploited` | (container) |  |
| `/matches[]/vulnerability/knownExploited[]` | `findings[].vulnerability.in_cisa_kev, exploit_available` |  |
| `/matches[]/vulnerability/knownExploited[]/cve` |  | the CVE of the KEV entry; it is one of the finding's ids |
| `/matches[]/vulnerability/knownExploited[]/vendorProject` | `findings[].source_extra.kev_vendor_product` |  |
| `/matches[]/vulnerability/knownExploited[]/product` | `findings[].source_extra.kev_vendor_product` |  |
| `/matches[]/vulnerability/knownExploited[]/dateAdded` | `findings[].source_extra.kev_date_added` |  |
| `/matches[]/vulnerability/knownExploited[]/requiredAction` | `findings[].source_extra.kev_required_action` |  |
| `/matches[]/vulnerability/knownExploited[]/dueDate` | `findings[].source_extra.kev_due_date` |  |
| `/matches[]/vulnerability/knownExploited[]/knownRansomwareCampaignUse` | `findings[].source_extra.kev_ransomware_use` |  |
| `/matches[]/vulnerability/knownExploited[]/notes` | `findings[].source_extra.kev_notes` |  |
| `/matches[]/vulnerability/knownExploited[]/urls` | (container) |  |
| `/matches[]/vulnerability/knownExploited[]/urls[]` | `findings[].references (http(s) only)` |  |
| `/matches[]/vulnerability/knownExploited[]/cwes` | (container) |  |
| `/matches[]/vulnerability/knownExploited[]/cwes[]` | `findings[].vulnerability.cwe_ids` |  |
| `/matches[]/relatedVulnerabilities[]/id` | `findings[].rule_id, native.vuln_id, vulnerability.ids[] (related)` |  |
| `/matches[]/relatedVulnerabilities[]/dataSource` | `findings[].references (http(s) only)` |  |
| `/matches[]/relatedVulnerabilities[]/namespace` | `findings[].native.family, scores[].source (fallback), source_extra.namespace` |  |
| `/matches[]/relatedVulnerabilities[]/severity` | `findings[].severity, native.severity` |  |
| `/matches[]/relatedVulnerabilities[]/urls` | (container) |  |
| `/matches[]/relatedVulnerabilities[]/urls[]` | `findings[].references (http(s) only)` |  |
| `/matches[]/relatedVulnerabilities[]/description` | `findings[].description` |  |
| `/matches[]/relatedVulnerabilities[]/cvss` | (container) |  |
| `/matches[]/relatedVulnerabilities[]/cvss[]` | `findings[].scores[] (cvss, one per entry), vulnerability.cvss_* (best)` |  |
| `/matches[]/relatedVulnerabilities[]/cvss[]/source` | `findings[].scores[].source` |  |
| `/matches[]/relatedVulnerabilities[]/cvss[]/type` |  | Primary or Secondary; the source is kept |
| `/matches[]/relatedVulnerabilities[]/cvss[]/version` |  | the version is read from the vector |
| `/matches[]/relatedVulnerabilities[]/cvss[]/vector` | `findings[].scores[].vector, version` |  |
| `/matches[]/relatedVulnerabilities[]/cvss[]/metrics` | (container) |  |
| `/matches[]/relatedVulnerabilities[]/cvss[]/metrics/baseScore` | `findings[].scores[].value` |  |
| `/matches[]/relatedVulnerabilities[]/cvss[]/metrics/exploitabilityScore` |  | a sub-score derived from the vector |
| `/matches[]/relatedVulnerabilities[]/cvss[]/metrics/impactScore` |  | a sub-score derived from the vector |
| `/matches[]/relatedVulnerabilities[]/cvss[]/vendorMetadata` |  | feed-specific metadata |
| `/matches[]/relatedVulnerabilities[]/cvss[]/vendorMetadata/**` |  | feed-specific metadata |
| `/matches[]/relatedVulnerabilities[]/epss` | (container) |  |
| `/matches[]/relatedVulnerabilities[]/epss[]` | (container) |  |
| `/matches[]/relatedVulnerabilities[]/epss[]/cve` |  | the CVE the EPSS entry is for; it is one of the finding's ids |
| `/matches[]/relatedVulnerabilities[]/epss[]/epss` | `findings[].scores[] (epss), vulnerability.epss_score` |  |
| `/matches[]/relatedVulnerabilities[]/epss[]/percentile` | `findings[].scores[] (epss_percentile), vulnerability.epss_percentile` |  |
| `/matches[]/relatedVulnerabilities[]/epss[]/date` | `findings[].scores[].as_of` |  |
| `/matches[]/relatedVulnerabilities[]/knownExploited` | (container) |  |
| `/matches[]/relatedVulnerabilities[]/knownExploited[]` | `findings[].vulnerability.in_cisa_kev, exploit_available` |  |
| `/matches[]/relatedVulnerabilities[]/knownExploited[]/cve` |  | the CVE of the KEV entry; it is one of the finding's ids |
| `/matches[]/relatedVulnerabilities[]/knownExploited[]/vendorProject` | `findings[].source_extra.kev_vendor_product` |  |
| `/matches[]/relatedVulnerabilities[]/knownExploited[]/product` | `findings[].source_extra.kev_vendor_product` |  |
| `/matches[]/relatedVulnerabilities[]/knownExploited[]/dateAdded` | `findings[].source_extra.kev_date_added` |  |
| `/matches[]/relatedVulnerabilities[]/knownExploited[]/requiredAction` | `findings[].source_extra.kev_required_action` |  |
| `/matches[]/relatedVulnerabilities[]/knownExploited[]/dueDate` | `findings[].source_extra.kev_due_date` |  |
| `/matches[]/relatedVulnerabilities[]/knownExploited[]/knownRansomwareCampaignUse` | `findings[].source_extra.kev_ransomware_use` |  |
| `/matches[]/relatedVulnerabilities[]/knownExploited[]/notes` | `findings[].source_extra.kev_notes` |  |
| `/matches[]/relatedVulnerabilities[]/knownExploited[]/urls` | (container) |  |
| `/matches[]/relatedVulnerabilities[]/knownExploited[]/urls[]` | `findings[].references (http(s) only)` |  |
| `/matches[]/relatedVulnerabilities[]/knownExploited[]/cwes` | (container) |  |
| `/matches[]/relatedVulnerabilities[]/knownExploited[]/cwes[]` | `findings[].vulnerability.cwe_ids` |  |
| `/matches[]/matchDetails` | (container) |  |
| `/matches[]/matchDetails[]` | (container) |  |
| `/matches[]/matchDetails[]/type` | `findings[].source_extra.match_type (first entry)` |  |
| `/matches[]/matchDetails[]/matcher` | `findings[].source_extra.matcher (first entry)` |  |
| `/matches[]/matchDetails[]/fix` | (container) |  |
| `/matches[]/matchDetails[]/fix/suggestedVersion` | `findings[].source_extra.suggested_version` |  |
| `/matches[]/matchDetails[]/searchedBy` |  | how the matcher searched (matcher internals) |
| `/matches[]/matchDetails[]/searchedBy/**` |  | how the matcher searched (matcher internals) |
| `/matches[]/matchDetails[]/found` |  | the database record the matcher found (matcher internals) |
| `/matches[]/matchDetails[]/found/**` |  | the database record the matcher found (matcher internals) |
| `/matches[]/artifact` | `dependencies[]` |  |
| `/matches[]/artifact/id` | `dependencies[].id` |  |
| `/matches[]/artifact/name` | `dependencies[].name, findings[].vulnerability.package` |  |
| `/matches[]/artifact/version` | `dependencies[].version, findings[].vulnerability.affected_version` |  |
| `/matches[]/artifact/type` | `dependencies[].type, ecosystem (fallback)` |  |
| `/matches[]/artifact/locations` | (container) |  |
| `/matches[]/artifact/locations[]` | (container) |  |
| `/matches[]/artifact/locations[]/path` | `dependencies[].path, findings[].location.path (first location)` |  |
| `/matches[]/artifact/locations[]/layerID` | `dependencies[].properties.layer_id (first location)` |  |
| `/matches[]/artifact/locations[]/accessPath` |  | the path through links; path is kept |
| `/matches[]/artifact/locations[]/annotations` |  | evidence annotations of the cataloger |
| `/matches[]/artifact/locations[]/annotations/**` |  | evidence annotations of the cataloger |
| `/matches[]/artifact/language` | `dependencies[].ecosystem (fallback), properties.language` |  |
| `/matches[]/artifact/licenses` | (container) |  |
| `/matches[]/artifact/licenses[]` | `dependencies[].licenses` |  |
| `/matches[]/artifact/cpes` | (container) |  |
| `/matches[]/artifact/cpes[]` | `findings[].vulnerability.cpe, dependencies[].properties.cpe (first)` |  |
| `/matches[]/artifact/purl` | `findings[].vulnerability.purl, dependencies[].purl, ecosystem` |  |
| `/matches[]/artifact/upstreams` | (container) |  |
| `/matches[]/artifact/upstreams[]` | (container) |  |
| `/matches[]/artifact/upstreams[]/name` | `dependencies[].properties.upstream (first)` |  |
| `/matches[]/artifact/upstreams[]/version` | `dependencies[].properties.upstream (first)` |  |
| `/matches[]/artifact/metadataType` |  | the type of the cataloger metadata below |
| `/matches[]/artifact/metadata` |  | cataloger-specific package metadata |
| `/matches[]/artifact/metadata/**` |  | cataloger-specific package metadata |
| `/ignoredMatches` |  | matches the scan's ignore rules suppressed; they are not findings of the scan |
| `/ignoredMatches[]` |  | matches the scan's ignore rules suppressed |
| `/ignoredMatches[]/**` |  | matches the scan's ignore rules suppressed |
| `/source` | (container) |  |
| `/source/type` | `assets[].type, properties.source_type` |  |
| `/source/target` | `assets[].value (a path string, or the object below)` |  |
| `/source/target/userInput` | `assets[].value (the image reference)` |  |
| `/source/target/imageID` | `assets[].properties.image_id` |  |
| `/source/target/manifestDigest` | `assets[].properties.manifest_digest` |  |
| `/source/target/tags` | (container) |  |
| `/source/target/tags[]` | `assets[].properties.image_tag (first)` |  |
| `/source/target/repoDigests` | (container) |  |
| `/source/target/repoDigests[]` | `assets[].properties.repo_digest (first)` |  |
| `/source/target/architecture` | `assets[].properties.architecture` |  |
| `/source/target/os` | `assets[].properties.os` |  |
| `/source/target/path` | `assets[].value (a directory or file source)` |  |
| `/source/target/mediaType` |  | image manifest media type |
| `/source/target/imageSize` |  | image size |
| `/source/target/layers*` |  | image layers (digests and sizes) |
| `/source/target/layers*/**` |  | image layers (digests and sizes) |
| `/source/target/manifest` |  | the raw image manifest (base64) |
| `/source/target/config` |  | the raw image configuration (base64; may hold environment values) |
| `/source/target/labels` |  | image labels chosen by the image author |
| `/source/target/labels/**` |  | image labels chosen by the image author |
| `/source/target/variant` |  | platform variant |
| `/distro` | (container) |  |
| `/distro/name` | `assets[].properties.distro` |  |
| `/distro/version` | `assets[].properties.distro` |  |
| `/distro/idLike` |  | related distribution families |
| `/distro/idLike[]` |  | related distribution families |
| `/descriptor` | (container) |  |
| `/descriptor/name` |  | always grype; the tool is named by the format |
| `/descriptor/version` | `tool.version` |  |
| `/descriptor/timestamp` | `metadata.properties.generated_at` |  |
| `/descriptor/db` | (container) |  |
| `/descriptor/db/built` | `metadata.properties.grype_db_built` |  |
| `/descriptor/db/schemaVersion` | `metadata.properties.grype_db_schema` |  |
| `/descriptor/db/location` |  | a path on the scanning machine |
| `/descriptor/db/checksum` |  | database file checksum |
| `/descriptor/db/error` |  | database load error text |
| `/descriptor/db/**` |  | database bookkeeping |
| `/descriptor/configuration` |  | the scan configuration: registry settings, paths and credentials |
| `/descriptor/configuration/**` |  | the scan configuration: registry settings, paths and credentials |
