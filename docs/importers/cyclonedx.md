# CycloneDX JSON (SBOM, VDR, VEX) mapping

Generated from `importer/spec_cyclonedx.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `cyclonedx`
- Source versions: CycloneDX 1.4, 1.5 and 1.6 JSON
- Fields: 75 mapped, 77 ignored on purpose (49% mapped)

## Rules

- The subject (metadata.component) is the asset: value is its purl, else name@version; type container for a container, host for an operating system, device, firmware or platform, else repository. Without a subject, an unclassified asset named after the serial number holds the components and findings, and an issue says so. A BOM without components or findings (a pure VEX) creates no asset.
- Every other component, at any nesting depth, is a dependency of the subject: id is its bom-ref (else purl, else name@version); a second component with a used bom-ref is skipped with an issue. depends_on keeps only refs that name a component; relationship is direct when the subject depends on it, indirect when the BOM has a dependency graph.
- One finding per vulnerability and affected component of this BOM (affects[].ref naming a component, or the subject). A ref that is a package URL outside the BOM is a VEX product but no finding.
- Severity: the severity word of the newest CVSS rating (else the first rating with one; a CVSS score without a word is banded 9/7/4/0.1); without any, medium with a note in source_extra. Every rating goes to scores (CVSSv2/v3/v31/v4 as cvss with version, SSVC as ssvc, others as vendor). The legacy cvss_* members take the newest CVSS rating.
- analysis maps through ctis.NormalizeVEXStatus and NormalizeVEXJustification. It becomes finding.vex and one VEX statement per vulnerability whose products are the affected components (purl, cpe, name, version). A not_affected analysis without a known justification or a detail is refused (issue). No finding is made for not_affected, resolved, resolved_with_pedigree and false_positive; they count as skipped.
- The VEX source is the BOM serial number.
- People's names and contacts (authors, credits, supplier contacts, annotations) are not read. Proof-of-concept material is not copied.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/bomFormat` | `format detection (must be CycloneDX)` |  |
| `/$schema` |  | schema location |
| `/specVersion` | `metadata.properties.cyclonedx_spec_version` |  |
| `/serialNumber` | `metadata.properties.bom_serial_number, findings[].vex.source, vex[].vex.source` |  |
| `/version` | `metadata.properties.bom_version` |  |
| `/metadata` | (container) |  |
| `/metadata/timestamp` | `metadata.properties.bom_timestamp` |  |
| `/metadata/tools/**` |  | the tools that wrote the BOM |
| `/metadata/tools[]/**` |  | the tools that wrote the BOM |
| `/metadata/authors` |  | people's names and contacts |
| `/metadata/authors[]/**` |  | people's names and contacts |
| `/metadata/manufacture/**` |  | manufacturer contact details |
| `/metadata/manufacturer/**` |  | manufacturer contact details |
| `/metadata/supplier/**` |  | supplier contact details |
| `/metadata/licenses/**` |  | license of the BOM document itself |
| `/metadata/properties/**` |  | producer-specific properties of the BOM document |
| `/metadata/lifecycles/**` |  | product lifecycle phase the BOM was made in |
| `/components` | (container) |  |
| `/metadata/component` | `assets[] (the subject of the BOM)` |  |
| `/metadata/component/bom-ref` | `vulnerabilities[].affects[].ref resolution to the subject` |  |
| `/metadata/component/type` | `assets[].type (container; operating-system, device, firmware, platform: host; else repository), assets[].properties.component_type` |  |
| `/metadata/component/group` | `assets[].name (group/name)` |  |
| `/metadata/component/name` | `assets[].name, assets[].value (name@version when no purl)` |  |
| `/metadata/component/version` | `assets[].value, assets[].properties.version` |  |
| `/metadata/component/purl` | `assets[].value` |  |
| `/metadata/component/cpe` | `assets[].properties.cpe` |  |
| `/metadata/component/components` | (container) |  |
| `/metadata/component/description` |  | the subject keeps its identity (name, version, purl, cpe, type); its other details describe the product, not the scanned asset |
| `/metadata/component/scope` |  | the subject keeps its identity (name, version, purl, cpe, type); its other details describe the product, not the scanned asset |
| `/metadata/component/hashes` |  | the subject keeps its identity (name, version, purl, cpe, type); its other details describe the product, not the scanned asset |
| `/metadata/component/hashes[]/**` |  | the subject keeps its identity (name, version, purl, cpe, type); its other details describe the product, not the scanned asset |
| `/metadata/component/licenses` |  | the subject keeps its identity (name, version, purl, cpe, type); its other details describe the product, not the scanned asset |
| `/metadata/component/licenses[]/**` |  | the subject keeps its identity (name, version, purl, cpe, type); its other details describe the product, not the scanned asset |
| `/metadata/component/supplier/**` |  | the subject keeps its identity (name, version, purl, cpe, type); its other details describe the product, not the scanned asset |
| `/metadata/component/publisher` |  | the subject keeps its identity (name, version, purl, cpe, type); its other details describe the product, not the scanned asset |
| `/metadata/component/properties` |  | the subject keeps its identity (name, version, purl, cpe, type); its other details describe the product, not the scanned asset |
| `/metadata/component/properties[]/**` |  | the subject keeps its identity (name, version, purl, cpe, type); its other details describe the product, not the scanned asset |
| `/metadata/component/externalReferences/**` |  | the subject keeps its identity (name, version, purl, cpe, type); its other details describe the product, not the scanned asset |
| `/metadata/component/author` |  | a person's name |
| `/metadata/component/authors/**` |  | people's names and contacts |
| `/metadata/component/manufacturer/**` |  | the subject keeps its identity (name, version, purl, cpe, type); its other details describe the product, not the scanned asset |
| `/metadata/component/copyright` |  | the subject keeps its identity (name, version, purl, cpe, type); its other details describe the product, not the scanned asset |
| `/components[]` | `dependencies[]` |  |
| `/components[]/bom-ref` | `dependencies[].id, vulnerabilities[].affects[].ref resolution` |  |
| `/components[]/type` | `dependencies[].type` |  |
| `/components[]/group` | `dependencies[].properties.group, findings[].vulnerability.package (group/name)` |  |
| `/components[]/name` | `dependencies[].name, findings[].vulnerability.package` |  |
| `/components[]/version` | `dependencies[].version, findings[].vulnerability.affected_version` |  |
| `/components[]/description` | `dependencies[].properties.description` |  |
| `/components[]/scope` | `dependencies[].properties.scope` |  |
| `/components[]/purl` | `dependencies[].purl, dependencies[].ecosystem (purl type), findings[].vulnerability.purl, ecosystem` |  |
| `/components[]/cpe` | `dependencies[].properties.cpe, findings[].vulnerability.cpe` |  |
| `/components[]/hashes` | (container) |  |
| `/components[]/hashes[]` | (container) |  |
| `/components[]/hashes[]/alg` | `dependencies[].properties.hash_<alg> (key)` |  |
| `/components[]/hashes[]/content` | `dependencies[].properties.hash_<alg>` |  |
| `/components[]/licenses` | (container) |  |
| `/components[]/licenses[]` | (container) |  |
| `/components[]/licenses[]/license` | (container) |  |
| `/components[]/licenses[]/license/id` | `dependencies[].licenses` |  |
| `/components[]/licenses[]/license/name` | `dependencies[].licenses (when no id)` |  |
| `/components[]/licenses[]/license/url` |  | license text location; the id or name is kept |
| `/components[]/licenses[]/license/text/**` |  | license text; the id or name is kept |
| `/components[]/licenses[]/license/acknowledgement` |  | declared or concluded; the license is kept either way |
| `/components[]/licenses[]/expression` | `dependencies[].licenses` |  |
| `/components[]/supplier` | (container) |  |
| `/components[]/supplier/name` | `dependencies[].properties.supplier` |  |
| `/components[]/supplier/url` |  | supplier web site |
| `/components[]/supplier/url[]` |  | supplier web site |
| `/components[]/supplier/contact[]/**` |  | people's names, e-mail addresses and phone numbers |
| `/components[]/supplier/contact` |  | people's names, e-mail addresses and phone numbers |
| `/components[]/publisher` | `dependencies[].properties.publisher` |  |
| `/components[]/author` |  | a person's name |
| `/components[]/authors/**` |  | people's names and contacts |
| `/components[]/manufacturer/**` |  | manufacturer contact details |
| `/components[]/copyright` |  | copyright notice text |
| `/components[]/properties` | (container) |  |
| `/components[]/properties[]` | (container) |  |
| `/components[]/properties[]/name` | `dependencies[].properties.property:<name> (key)` |  |
| `/components[]/properties[]/value` | `dependencies[].properties.property:<name>` |  |
| `/components[]/components` | (container) |  |
| `/components[]/externalReferences` |  | links to the project (VCS, web site, issue tracker); not a property of the installed component |
| `/components[]/externalReferences[]/**` |  | links to the project (VCS, web site, issue tracker); not a property of the installed component |
| `/components[]/evidence/**` |  | how the producer found the component (occurrences, call stacks); can hold build paths |
| `/components[]/pedigree/**` |  | ancestors and patches of the component; not imported |
| `/components[]/swid/**` |  | SWID tag; purl and cpe identify the component |
| `/components[]/omniborId` |  | artifact id; purl identifies the component |
| `/components[]/omniborId[]` |  | artifact id; purl identifies the component |
| `/components[]/swhid` |  | artifact id; purl identifies the component |
| `/components[]/swhid[]` |  | artifact id; purl identifies the component |
| `/components[]/mime-type` |  | file type of a file component |
| `/components[]/modified` |  | deprecated flag (use pedigree) |
| `/components[]/tags` |  | free-form labels of the producer |
| `/components[]/tags[]` |  | free-form labels of the producer |
| `/components[]/releaseNotes/**` |  | release notes text |
| `/components[]/modelCard/**` |  | machine-learning model card |
| `/components[]/data/**` |  | data set description |
| `/components[]/cryptoProperties/**` |  | cryptographic asset inventory (CBOM); not imported |
| `/components[]/signature/**` |  | signature of the component entry |
| `/dependencies` | (container) |  |
| `/dependencies[]` | (container) |  |
| `/dependencies[]/ref` | `dependencies[] (the dependent); dependencies[].relationship (direct when the subject depends on it)` |  |
| `/dependencies[]/dependsOn` | (container) |  |
| `/dependencies[]/dependsOn[]` | `dependencies[].depends_on (refs that name a component)` |  |
| `/dependencies[]/provides` |  | specifications a component implements (CBOM) |
| `/dependencies[]/provides[]` |  | specifications a component implements (CBOM) |
| `/vulnerabilities` | (container) |  |
| `/vulnerabilities[]` | `findings[] (one per affected component of this BOM), vex[] (with an analysis)` |  |
| `/vulnerabilities[]/bom-ref` | `findings[].native.instance_id` |  |
| `/vulnerabilities[]/id` | `findings[].rule_id, native.vuln_id, vulnerability.ids, cve_id; vex[].vulnerability_ids` |  |
| `/vulnerabilities[]/source` | (container) |  |
| `/vulnerabilities[]/source/name` | `findings[].vulnerability.data_source.name` |  |
| `/vulnerabilities[]/source/url` | `findings[].vulnerability.data_source.url, references` |  |
| `/vulnerabilities[]/references` | (container) |  |
| `/vulnerabilities[]/references[]` | (container) |  |
| `/vulnerabilities[]/references[]/id` | `findings[].vulnerability.ids; vex[].vulnerability_ids` |  |
| `/vulnerabilities[]/references[]/source` | (container) |  |
| `/vulnerabilities[]/references[]/source/name` | `findings[].vulnerability.ids[].source (vendor ids)` |  |
| `/vulnerabilities[]/references[]/source/url` |  | the id is kept; the database link is derived from it |
| `/vulnerabilities[]/ratings` | (container) |  |
| `/vulnerabilities[]/ratings[]` | `findings[].scores[]` |  |
| `/vulnerabilities[]/ratings[]/source` | (container) |  |
| `/vulnerabilities[]/ratings[]/source/name` | `findings[].scores[].source` |  |
| `/vulnerabilities[]/ratings[]/source/url` |  | the source name is kept |
| `/vulnerabilities[]/ratings[]/score` | `findings[].scores[].value, vulnerability.cvss_score, severity (when no severity word)` |  |
| `/vulnerabilities[]/ratings[]/severity` | `findings[].severity (from the newest CVSS rating), native.severity, scores[].label` |  |
| `/vulnerabilities[]/ratings[]/method` | `findings[].scores[].system and version (CVSSv2, CVSSv3, CVSSv31, CVSSv4, SSVC; others vendor)` |  |
| `/vulnerabilities[]/ratings[]/vector` | `findings[].scores[].vector, vulnerability.cvss_vector` |  |
| `/vulnerabilities[]/ratings[]/justification` | `findings[].source_extra.rating_justification:<source>:<method>` |  |
| `/vulnerabilities[]/cwes` | (container) |  |
| `/vulnerabilities[]/cwes[]` | `findings[].vulnerability.cwe_ids` |  |
| `/vulnerabilities[]/description` | `findings[].description, message` |  |
| `/vulnerabilities[]/detail` | `findings[].description` |  |
| `/vulnerabilities[]/recommendation` | `findings[].remediation.recommendation` |  |
| `/vulnerabilities[]/workaround` | `findings[].remediation.steps, solution_type workaround (when no recommendation)` |  |
| `/vulnerabilities[]/proofOfConcept/**` |  | reproduction steps and exploit material; not copied into findings |
| `/vulnerabilities[]/advisories` | (container) |  |
| `/vulnerabilities[]/advisories[]` | `findings[].remediation.advisories` |  |
| `/vulnerabilities[]/advisories[]/title` | `findings[].remediation.advisories[].id` |  |
| `/vulnerabilities[]/advisories[]/url` | `findings[].remediation.advisories[].url, references` |  |
| `/vulnerabilities[]/created` | `findings[].source_extra.created` |  |
| `/vulnerabilities[]/published` | `findings[].vulnerability.published_at` |  |
| `/vulnerabilities[]/updated` | `findings[].vulnerability.modified_at` |  |
| `/vulnerabilities[]/rejected` | `findings[].source_extra.rejected` |  |
| `/vulnerabilities[]/credits/**` |  | people and organizations credited; names and contacts |
| `/vulnerabilities[]/tools/**` |  | the tools that found the vulnerability |
| `/vulnerabilities[]/tools[]/**` |  | the tools that found the vulnerability |
| `/vulnerabilities[]/analysis` | `findings[].vex, vex[]` |  |
| `/vulnerabilities[]/analysis/state` | `findings[].vex.status, vex[].vex.status; no finding for not_affected, resolved, resolved_with_pedigree, false_positive` |  |
| `/vulnerabilities[]/analysis/justification` | `findings[].vex.justification, native_justification` |  |
| `/vulnerabilities[]/analysis/response` | (container) |  |
| `/vulnerabilities[]/analysis/response[]` | `findings[].source_extra.analysis_response` |  |
| `/vulnerabilities[]/analysis/detail` | `findings[].vex.statement` |  |
| `/vulnerabilities[]/analysis/firstIssued` | `findings[].vex.as_of (when no lastUpdated)` |  |
| `/vulnerabilities[]/analysis/lastUpdated` | `findings[].vex.as_of` |  |
| `/vulnerabilities[]/affects` | (container) |  |
| `/vulnerabilities[]/affects[]` | `findings[] (one per affected component), vex[].products` |  |
| `/vulnerabilities[]/affects[]/ref` | `findings[].vulnerability.package/purl/affected_version (the component), vex[].products` |  |
| `/vulnerabilities[]/affects[]/versions` | (container) |  |
| `/vulnerabilities[]/affects[]/versions[]` | `findings[].source_extra.affects_versions` |  |
| `/vulnerabilities[]/affects[]/versions[]/version` | `findings[].source_extra.affects_versions` |  |
| `/vulnerabilities[]/affects[]/versions[]/range` | `findings[].source_extra.affects_versions` |  |
| `/vulnerabilities[]/affects[]/versions[]/status` | `findings[].source_extra.affects_versions` |  |
| `/vulnerabilities[]/properties` | (container) |  |
| `/vulnerabilities[]/properties[]` | (container) |  |
| `/vulnerabilities[]/properties[]/name` | `findings[].source_extra.property:<name> (key)` |  |
| `/vulnerabilities[]/properties[]/value` | `findings[].source_extra.property:<name>` |  |
| `/services` |  | services of the product (endpoints, data flows); not imported |
| `/services[]/**` |  | services of the product (endpoints, data flows); not imported |
| `/externalReferences` |  | links about the product |
| `/externalReferences[]/**` |  | links about the product |
| `/compositions` |  | completeness claims of the BOM |
| `/compositions[]/**` |  | completeness claims of the BOM |
| `/annotations` |  | comments by people; names and text |
| `/annotations[]/**` |  | comments by people; names and text |
| `/formulation/**` |  | how the product was built |
| `/properties` |  | producer-specific properties of the BOM document |
| `/properties[]/**` |  | producer-specific properties of the BOM document |
| `/signature/**` |  | signature of the BOM; verification is the uploader's concern |
| `/definitions/**` |  | standards definitions (CycloneDX 1.6 attestations) |
| `/declarations/**` |  | conformance declarations (CycloneDX 1.6 attestations) |
