# osv-scanner JSON results (OSV records) mapping

Generated from `importer/spec_osv.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `osv`
- Source versions: osv-scanner 1.x and 2.x JSON output; OSV schema 1.0 to 1.7 records
- Fields: 43 mapped, 13 ignored on purpose (77% mapped)

## Rules

- One asset per scanned source (results[].source.path, as a label of at most 255 characters; never opened): type repository, id osv-<path>. Every package of the source is a dependency of it (path = the source label, so a receiver attributes it to that asset).
- One finding per package and vulnerability group: a group (groups[]) joins the records of one vulnerability under all its ids; records no group names stand alone. A group whose ids name no record, and a withdrawn record, are skipped with an issue.
- Ids: the group ids and aliases and every record id and alias go to vulnerability.ids (typed: CVE, GHSA, OSV databases, vendor); rule_id and native.vuln_id are the first record's id.
- Severity: max_severity (the group's highest CVSS base score) banded 9/7/4/0.1; else database_specific.severity (GitHub words, MODERATE is medium); else medium with a note in source_extra. native.severity keeps the source value.
- severity[] vectors (record and affected) go to scores as CVSS with the version the vector declares and source ghsa or osv; nothing is computed from a vector. Other severity types are vendor labels.
- The affected entry of the package (same name and ecosystem) gives affected_version_range (introduced, fixed, last_affected, limit events as >=, <, <=, <), fixed_versions and the purl (with the installed version); a fix makes the remediation an upgrade.
- database_specific and ecosystem_specific objects are kept as compact JSON in source_extra (bounded); GitHub cwe_ids become cwe_ids.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/results` | (container) |  |
| `/results[]` | (container) |  |
| `/results[]/source` | (container) |  |
| `/results[]/source/path` | `assets[].value, name, id; dependencies[].path` |  |
| `/results[]/source/type` | `assets[].properties.source_type` |  |
| `/results[]/packages` | (container) |  |
| `/results[]/packages[]` | `dependencies[]` |  |
| `/results[]/packages[]/package` | (container) |  |
| `/results[]/packages[]/package/name` | `dependencies[].name, findings[].vulnerability.package` |  |
| `/results[]/packages[]/package/version` | `dependencies[].version, findings[].vulnerability.affected_version` |  |
| `/results[]/packages[]/package/ecosystem` | `dependencies[].ecosystem, findings[].vulnerability.ecosystem` |  |
| `/results[]/packages[]/package/purl` | `dependencies[].purl, findings[].vulnerability.purl` |  |
| `/results[]/packages[]/package/commit` | `dependencies[].properties.commit` |  |
| `/results[]/packages[]/package/inventory/**` |  | where the scanner found the package on its own disk |
| `/results[]/packages[]/dependency_groups` | (container) |  |
| `/results[]/packages[]/dependency_groups[]` | `dependencies[].properties.dependency_groups` |  |
| `/results[]/packages[]/licenses` | (container) |  |
| `/results[]/packages[]/licenses[]` | `dependencies[].licenses` |  |
| `/results[]/packages[]/license_violations` |  | license policy result of the scanner run |
| `/results[]/packages[]/license_violations[]` |  | license policy result of the scanner run |
| `/results[]/packages[]/groups` | (container) |  |
| `/results[]/packages[]/groups[]` | `findings[] (one per group)` |  |
| `/results[]/packages[]/groups[]/ids` | (container) |  |
| `/results[]/packages[]/groups[]/ids[]` | `findings[].vulnerability.ids (and the records of the group)` |  |
| `/results[]/packages[]/groups[]/aliases` | (container) |  |
| `/results[]/packages[]/groups[]/aliases[]` | `findings[].vulnerability.ids` |  |
| `/results[]/packages[]/groups[]/max_severity` | `findings[].severity, native.severity, source_extra.max_severity` |  |
| `/results[]/packages[]/groups[]/experimentalAnalysis/**` |  | experimental call analysis of the scanner run |
| `/results[]/packages[]/vulnerabilities` | (container) |  |
| `/results[]/packages[]/vulnerabilities[]` | `findings[] (through its group)` |  |
| `/results[]/packages[]/vulnerabilities[]/schema_version` |  | OSV schema version of the record |
| `/results[]/packages[]/vulnerabilities[]/id` | `findings[].rule_id, native.vuln_id, vulnerability.ids` |  |
| `/results[]/packages[]/vulnerabilities[]/modified` | `findings[].vulnerability.modified_at (latest of the group)` |  |
| `/results[]/packages[]/vulnerabilities[]/published` | `findings[].vulnerability.published_at (earliest of the group)` |  |
| `/results[]/packages[]/vulnerabilities[]/withdrawn` | `skips the finding (issue)` |  |
| `/results[]/packages[]/vulnerabilities[]/aliases` | (container) |  |
| `/results[]/packages[]/vulnerabilities[]/aliases[]` | `findings[].vulnerability.ids` |  |
| `/results[]/packages[]/vulnerabilities[]/related` | (container) |  |
| `/results[]/packages[]/vulnerabilities[]/related[]` | `findings[].source_extra.related` |  |
| `/results[]/packages[]/vulnerabilities[]/upstream` | (container) |  |
| `/results[]/packages[]/vulnerabilities[]/upstream[]` | `findings[].source_extra.upstream` |  |
| `/results[]/packages[]/vulnerabilities[]/summary` | `findings[].title, message, description` |  |
| `/results[]/packages[]/vulnerabilities[]/details` | `findings[].description` |  |
| `/results[]/packages[]/vulnerabilities[]/severity` | (container) |  |
| `/results[]/packages[]/vulnerabilities[]/severity[]` | `findings[].scores[]` |  |
| `/results[]/packages[]/vulnerabilities[]/severity[]/type` | `findings[].scores[].system (CVSS_V2/V3/V4: cvss; others: vendor, source the type)` |  |
| `/results[]/packages[]/vulnerabilities[]/severity[]/score` | `findings[].scores[].vector (cvss), label (others); vulnerability.cvss_vector` |  |
| `/results[]/packages[]/vulnerabilities[]/affected` | (container) |  |
| `/results[]/packages[]/vulnerabilities[]/affected[]` | `the entry of this package (same name and ecosystem)` |  |
| `/results[]/packages[]/vulnerabilities[]/affected[]/package` | (container) |  |
| `/results[]/packages[]/vulnerabilities[]/affected[]/package/ecosystem` | `selects the entry` |  |
| `/results[]/packages[]/vulnerabilities[]/affected[]/package/name` | `selects the entry` |  |
| `/results[]/packages[]/vulnerabilities[]/affected[]/package/purl` | `findings[].vulnerability.purl (with the installed version)` |  |
| `/results[]/packages[]/vulnerabilities[]/affected[]/severity` | (container) |  |
| `/results[]/packages[]/vulnerabilities[]/affected[]/severity[]` | `findings[].scores[]` |  |
| `/results[]/packages[]/vulnerabilities[]/affected[]/severity[]/type` | `findings[].scores[].system` |  |
| `/results[]/packages[]/vulnerabilities[]/affected[]/severity[]/score` | `findings[].scores[].vector or label` |  |
| `/results[]/packages[]/vulnerabilities[]/affected[]/ranges` | (container) |  |
| `/results[]/packages[]/vulnerabilities[]/affected[]/ranges[]` | (container) |  |
| `/results[]/packages[]/vulnerabilities[]/affected[]/ranges[]/type` |  | range kind (SEMVER, ECOSYSTEM, GIT); the events are kept as written |
| `/results[]/packages[]/vulnerabilities[]/affected[]/ranges[]/repo` |  | repository of a GIT range |
| `/results[]/packages[]/vulnerabilities[]/affected[]/ranges[]/events` | (container) |  |
| `/results[]/packages[]/vulnerabilities[]/affected[]/ranges[]/events[]` | (container) |  |
| `/results[]/packages[]/vulnerabilities[]/affected[]/ranges[]/events[]/introduced` | `findings[].vulnerability.affected_version_range (>=)` |  |
| `/results[]/packages[]/vulnerabilities[]/affected[]/ranges[]/events[]/fixed` | `findings[].vulnerability.affected_version_range (<), fixed_version(s), remediation` |  |
| `/results[]/packages[]/vulnerabilities[]/affected[]/ranges[]/events[]/last_affected` | `findings[].vulnerability.affected_version_range (<=)` |  |
| `/results[]/packages[]/vulnerabilities[]/affected[]/ranges[]/events[]/limit` | `findings[].vulnerability.affected_version_range (<)` |  |
| `/results[]/packages[]/vulnerabilities[]/affected[]/ranges[]/database_specific/**` |  | database detail of a range |
| `/results[]/packages[]/vulnerabilities[]/affected[]/versions` |  | every affected version, often thousands; the ranges are kept |
| `/results[]/packages[]/vulnerabilities[]/affected[]/versions[]` |  | every affected version, often thousands; the ranges are kept |
| `/results[]/packages[]/vulnerabilities[]/affected[]/ecosystem_specific/**` | `findings[].source_extra.ecosystem_specific:<id> (compact JSON)` |  |
| `/results[]/packages[]/vulnerabilities[]/affected[]/database_specific/**` | `findings[].source_extra.affected_database_specific:<id> (compact JSON)` |  |
| `/results[]/packages[]/vulnerabilities[]/references` | (container) |  |
| `/results[]/packages[]/vulnerabilities[]/references[]` | (container) |  |
| `/results[]/packages[]/vulnerabilities[]/references[]/type` | `ADVISORY: findings[].remediation.advisories` |  |
| `/results[]/packages[]/vulnerabilities[]/references[]/url` | `findings[].references, remediation.advisories[].url` |  |
| `/results[]/packages[]/vulnerabilities[]/credits` |  | people and organizations credited; names and contacts |
| `/results[]/packages[]/vulnerabilities[]/credits[]/**` |  | people and organizations credited; names and contacts |
| `/results[]/packages[]/vulnerabilities[]/database_specific/**` | `findings[].source_extra.database_specific:<id> (compact JSON); cwe_ids; severity (fallback)` |  |
| `/experimental_config/**` |  | scanner run configuration |
