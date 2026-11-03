# trivy JSON mapping

Generated from `importer/spec_trivy.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `trivy`
- Source versions: trivy 0.4x-0.6x --format json (SchemaVersion 2): image, file-system, repository and config scans
- Fields: 81 mapped, 25 ignored on purpose (76% mapped)

## Rules

- Asset: Options.Repository; else the image of an image scan (container_image asset, by its repo digest when the report has one, with the OS as a technology) or the repository of a repository scan; a file-system scan names a local path, so its findings go to Options.DefaultAsset or an unclassified asset (with an issue).
- One finding per vulnerability, misconfiguration and secret. Severity CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN maps to critical/high/medium/low/info; native.severity keeps the word.
- Every CVSS source (nvd, ghsa, redhat, ...) and version goes to finding.scores; each vendor severity is a vendor score with the vendor as source; the status is finding.vex.
- A secret's match line is masked again with ctis.MaskSecretMatch unless trivy already masked it; the fingerprint is left to the receiver (the secret is masked, so there is nothing to digest). An unmasked match is also masked in every other field (ctis.RedactSecretFinding).
- Packages (--list-all-pkgs) become dependencies with their PURL; a language result's dependencies carry its target (the manifest or lockfile) as path and their lockfile lines as locations.
- With the packages of a language result, each vulnerability gets vulnerability.is_direct (its package's relationship is direct), vulnerability.dependency_path (the shortest chain of package ids from the project, or the direct dependency, to the package; at most 32 entries, the first and the 31 nearest the package kept), the package's PURL when the record has none, and the target with the package's first lockfile line as location when the record has no package path.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/SchemaVersion` | `format check` |  |
| `/CreatedAt` |  | report time; the import time is the report timestamp |
| `/ReportID` |  | trivy's id of the run |
| `/ArtifactName` | `assets[].value (image or repository)` |  |
| `/ArtifactType` | `assets[].type (container, repository)` |  |
| `/Metadata` | (container) |  |
| `/Metadata/OS` | (container) |  |
| `/Metadata/OS/Family` | `assets[].technologies[] (operating-system)` |  |
| `/Metadata/OS/Name` | `assets[].technologies[] (operating-system)` |  |
| `/Metadata/ImageID` | `assets[].properties.image_id` |  |
| `/Metadata/RepoDigests` | (container) |  |
| `/Metadata/RepoDigests[]` | `assets[].properties.repo_digest (the first)` |  |
| `/Metadata/RepoTags` |  | image tags; the artifact name is kept |
| `/Metadata/RepoTags[]` |  | image tags; the artifact name is kept |
| `/Metadata/DiffIDs` |  | image layer ids; each vulnerability keeps its layer |
| `/Metadata/DiffIDs[]` |  | image layer ids; each vulnerability keeps its layer |
| `/Metadata/ImageConfig` |  | image configuration (history, environment, entrypoint): may hold build arguments |
| `/Metadata/ImageConfig/**` |  | image configuration (history, environment, entrypoint): may hold build arguments |
| `/Metadata/*` |  | other scan metadata |
| `/Results` | (container) |  |
| `/Results[]` | (container) |  |
| `/Results[]/Target` | `findings[].tags, location.path (misconfigurations, secrets), source_extra.target` |  |
| `/Results[]/Class` | `lang-pkgs: the target is the dependencies' path and the placed findings' location` |  |
| `/Results[]/Type` |  | package manager or config kind of the target |
| `/Results[]/MisconfSummary` |  | counts of passed and failed checks |
| `/Results[]/MisconfSummary/**` |  | counts of passed and failed checks |
| `/Results[]/Packages` | (container) |  |
| `/Results[]/Packages[]` | `dependencies[]` |  |
| `/Results[]/Packages[]/ID` | `dependencies[].id` |  |
| `/Results[]/Packages[]/Name` | `dependencies[].name` |  |
| `/Results[]/Packages[]/Version` | `dependencies[].version` |  |
| `/Results[]/Packages[]/Identifier` | (container) |  |
| `/Results[]/Packages[]/Identifier/PURL` | `dependencies[].purl` |  |
| `/Results[]/Packages[]/Identifier/UID` | `dependencies[].source_id` |  |
| `/Results[]/Packages[]/Licenses` | (container) |  |
| `/Results[]/Packages[]/Licenses[]` | `dependencies[].licenses` |  |
| `/Results[]/Packages[]/DependsOn` | (container) |  |
| `/Results[]/Packages[]/DependsOn[]` | `dependencies[].depends_on, findings[].vulnerability.dependency_path` |  |
| `/Results[]/Packages[]/Relationship` | `dependencies[].relationship, findings[].vulnerability.is_direct` |  |
| `/Results[]/Packages[]/Indirect` | `dependencies[].relationship (when Relationship is absent)` |  |
| `/Results[]/Packages[]/Locations` | (container) |  |
| `/Results[]/Packages[]/Locations[]` | `dependencies[].locations[], findings[].location (the first)` |  |
| `/Results[]/Packages[]/Locations[]/StartLine` | `dependencies[].locations[].start_line, findings[].location.start_line` |  |
| `/Results[]/Packages[]/Locations[]/EndLine` | `dependencies[].locations[].end_line, findings[].location.end_line` |  |
| `/Results[]/Packages[]/*` |  | other package details (layer, arch, source package, file path) |
| `/Results[]/Packages[]/*/**` |  | other package details (layer, arch, source package, file path) |
| `/Results[]/Vulnerabilities` | (container) |  |
| `/Results[]/Vulnerabilities[]` | `findings[] (vulnerability)` |  |
| `/Results[]/Vulnerabilities[]/VulnerabilityID` | `findings[].rule_id, native.vuln_id, vulnerability.ids` |  |
| `/Results[]/Vulnerabilities[]/VendorIDs` | (container) |  |
| `/Results[]/Vulnerabilities[]/VendorIDs[]` | `findings[].vulnerability.ids[] (vendor)` |  |
| `/Results[]/Vulnerabilities[]/PkgID` | `findings[].source_extra.pkg_id; the package whose graph places the finding` |  |
| `/Results[]/Vulnerabilities[]/Fingerprint` |  | trivy's own result hash; the CTIS SCA fingerprint is computed |
| `/Results[]/Vulnerabilities[]/PkgName` | `findings[].vulnerability.package_name` |  |
| `/Results[]/Vulnerabilities[]/PkgPath` | `findings[].location.path` |  |
| `/Results[]/Vulnerabilities[]/PkgIdentifier` | (container) |  |
| `/Results[]/Vulnerabilities[]/PkgIdentifier/PURL` | `findings[].vulnerability.purl` |  |
| `/Results[]/Vulnerabilities[]/PkgIdentifier/UID` |  | trivy-internal package uid |
| `/Results[]/Vulnerabilities[]/InstalledVersion` | `findings[].vulnerability.installed_version` |  |
| `/Results[]/Vulnerabilities[]/FixedVersion` | `findings[].vulnerability.fixed_versions, remediation` |  |
| `/Results[]/Vulnerabilities[]/Status` | `findings[].vex.status` |  |
| `/Results[]/Vulnerabilities[]/SeveritySource` | `findings[].scores[] (vendor source)` |  |
| `/Results[]/Vulnerabilities[]/Severity` | `findings[].severity, native.severity` |  |
| `/Results[]/Vulnerabilities[]/VendorSeverity` | `findings[].scores[] (vendor)` |  |
| `/Results[]/Vulnerabilities[]/VendorSeverity/*` | `findings[].scores[] (vendor)` |  |
| `/Results[]/Vulnerabilities[]/Title` | `findings[].title` |  |
| `/Results[]/Vulnerabilities[]/Description` | `findings[].description` |  |
| `/Results[]/Vulnerabilities[]/PrimaryURL` | `findings[].references` |  |
| `/Results[]/Vulnerabilities[]/DataSource` | (container) |  |
| `/Results[]/Vulnerabilities[]/DataSource/ID` | `findings[].vulnerability.data_source.id` |  |
| `/Results[]/Vulnerabilities[]/DataSource/Name` | `findings[].vulnerability.data_source.name` |  |
| `/Results[]/Vulnerabilities[]/DataSource/URL` | `findings[].vulnerability.data_source.url` |  |
| `/Results[]/Vulnerabilities[]/CVSS` | (container) |  |
| `/Results[]/Vulnerabilities[]/CVSS/*` | (container) |  |
| `/Results[]/Vulnerabilities[]/CVSS/*/V2Vector` | `findings[].scores[] (cvss 2.0)` |  |
| `/Results[]/Vulnerabilities[]/CVSS/*/V2Score` | `findings[].scores[] (cvss 2.0), scores[] (cvss)` |  |
| `/Results[]/Vulnerabilities[]/CVSS/*/V3Vector` | `findings[].scores[] (cvss 3.x), scores[] (cvss)` |  |
| `/Results[]/Vulnerabilities[]/CVSS/*/V3Score` | `findings[].scores[] (cvss 3.x), scores[] (cvss)` |  |
| `/Results[]/Vulnerabilities[]/CVSS/*/V40Vector` | `findings[].scores[] (cvss 4.0)` |  |
| `/Results[]/Vulnerabilities[]/CVSS/*/V40Score` | `findings[].scores[] (cvss 4.0)` |  |
| `/Results[]/Vulnerabilities[]/CweIDs` | (container) |  |
| `/Results[]/Vulnerabilities[]/CweIDs[]` | `findings[].vulnerability.cwe_ids` |  |
| `/Results[]/Vulnerabilities[]/References` | (container) |  |
| `/Results[]/Vulnerabilities[]/References[]` | `findings[].references` |  |
| `/Results[]/Vulnerabilities[]/PublishedDate` | `findings[].vulnerability.published_at` |  |
| `/Results[]/Vulnerabilities[]/LastModifiedDate` | `findings[].vulnerability.modified_at` |  |
| `/Results[]/Vulnerabilities[]/Layer` | (container) |  |
| `/Results[]/Vulnerabilities[]/Layer/Digest` | `findings[].vulnerability.layer.digest` |  |
| `/Results[]/Vulnerabilities[]/Layer/DiffID` | `findings[].vulnerability.layer.diff_id` |  |
| `/Results[]/Misconfigurations` | (container) |  |
| `/Results[]/Misconfigurations[]` | `findings[] (misconfiguration)` |  |
| `/Results[]/Misconfigurations[]/Type` | `findings[].source_extra.misconfig_type` |  |
| `/Results[]/Misconfigurations[]/ID` | `findings[].rule_id, misconfiguration.policy_id` |  |
| `/Results[]/Misconfigurations[]/AVDID` | `findings[].misconfiguration.policy_id (the AVD id when given)` |  |
| `/Results[]/Misconfigurations[]/Title` | `findings[].title, misconfiguration.policy_name` |  |
| `/Results[]/Misconfigurations[]/Description` | `findings[].description` |  |
| `/Results[]/Misconfigurations[]/Message` | `findings[].message` |  |
| `/Results[]/Misconfigurations[]/Namespace` | `findings[].misconfiguration.namespace` |  |
| `/Results[]/Misconfigurations[]/Query` | `findings[].misconfiguration.query` |  |
| `/Results[]/Misconfigurations[]/Resolution` | `findings[].remediation.recommendation` |  |
| `/Results[]/Misconfigurations[]/Severity` | `findings[].severity, native.severity` |  |
| `/Results[]/Misconfigurations[]/PrimaryURL` | `findings[].references` |  |
| `/Results[]/Misconfigurations[]/References` | (container) |  |
| `/Results[]/Misconfigurations[]/References[]` | `findings[].references` |  |
| `/Results[]/Misconfigurations[]/Status` | `findings[].native.status` |  |
| `/Results[]/Misconfigurations[]/CauseMetadata` | (container) |  |
| `/Results[]/Misconfigurations[]/CauseMetadata/Resource` | `findings[].misconfiguration.resource_name` |  |
| `/Results[]/Misconfigurations[]/CauseMetadata/Provider` | `findings[].misconfiguration.provider` |  |
| `/Results[]/Misconfigurations[]/CauseMetadata/Service` | `findings[].misconfiguration.service` |  |
| `/Results[]/Misconfigurations[]/CauseMetadata/StartLine` | `findings[].location.start_line` |  |
| `/Results[]/Misconfigurations[]/CauseMetadata/EndLine` | `findings[].location.end_line` |  |
| `/Results[]/Misconfigurations[]/CauseMetadata/Code` |  | the source lines of the cause; may hold configuration values |
| `/Results[]/Misconfigurations[]/CauseMetadata/Code/**` |  | the source lines of the cause; may hold configuration values |
| `/Results[]/Misconfigurations[]/CauseMetadata/*` |  | other cause details |
| `/Results[]/Misconfigurations[]/Layer` |  | image layer of the configuration file |
| `/Results[]/Misconfigurations[]/Layer/**` |  | image layer of the configuration file |
| `/Results[]/Secrets` | (container) |  |
| `/Results[]/Secrets[]` | `findings[] (secret)` |  |
| `/Results[]/Secrets[]/RuleID` | `findings[].rule_id, native.vuln_id` |  |
| `/Results[]/Secrets[]/Category` | `findings[].secret.type, source_extra.category` |  |
| `/Results[]/Secrets[]/Severity` | `findings[].severity, native.severity` |  |
| `/Results[]/Secrets[]/Title` | `findings[].title` |  |
| `/Results[]/Secrets[]/StartLine` | `findings[].location.start_line` |  |
| `/Results[]/Secrets[]/EndLine` | `findings[].location.end_line` |  |
| `/Results[]/Secrets[]/Match` | `findings[].location.snippet (masked), fingerprint input (masked)` |  |
| `/Results[]/Secrets[]/Code` |  | the source lines around the secret; they hold the secret |
| `/Results[]/Secrets[]/Code/**` |  | the source lines around the secret; they hold the secret |
| `/Results[]/Secrets[]/Layer` |  | image layer of the file |
| `/Results[]/Secrets[]/Layer/**` |  | image layer of the file |
