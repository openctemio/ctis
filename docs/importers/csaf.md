# CSAF 2.0 (VEX and security advisory profiles) mapping

Generated from `importer/spec_csaf.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `csaf`
- Source versions: CSAF 2.0 JSON (csaf_vex, csaf_security_advisory, csaf_base)
- Fields: 45 mapped, 55 ignored on purpose (45% mapped)

## Rules

- A CSAF document describes products, not findings: the report has no assets or findings, and Result.VEX holds one statement per vulnerability, product_status group and statement text.
- Status groups: known_not_affected is not_affected; known_affected, first_affected and last_affected are affected; fixed, first_fixed and recommended are fixed; under_investigation is under_investigation.
- not_affected: the justification is the label of a flag that names the product (directly or through a product group); the statement is the details of an impact threat for the product. A not_affected product with neither is left out with an issue: a bare claim never suppresses a finding.
- affected and fixed: the statement is the remediation for the product (`category: details (url)`). Nothing is invented when there is none.
- Products are resolved through the product tree: branches (any depth; a product_version branch gives the version), full_product_names, and relationships (the platform, with the component in products[].subcomponents). PURL and CPE come from product_identification_helper; a product without them keeps its name.
- Product ids the tree does not define, and relationships that refer to undefined or circular products, are left out with an issue.
- Statement source: publisher.namespace#tracking.id; as_of: tracking.current_release_date.
- Links in the document (sbom_urls, x_generic_uris, references) are never fetched.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/document` | (container) |  |
| `/document/category` | `metadata.properties.category` |  |
| `/document/csaf_version` | `metadata.properties.csaf_version` |  |
| `/document/title` | `metadata.properties.title` |  |
| `/document/lang` |  | document language |
| `/document/source_lang` |  | language of a translated document's source |
| `/document/publisher` | (container) |  |
| `/document/publisher/name` | `metadata.properties.publisher` |  |
| `/document/publisher/namespace` | `vex[].vex.source, metadata.properties.publisher_namespace` |  |
| `/document/publisher/category` |  | kind of publisher (vendor, coordinator, ...) |
| `/document/publisher/contact_details` |  | publisher contact (personal data) |
| `/document/publisher/issuing_authority` |  | publisher's authority statement (prose) |
| `/document/tracking` | (container) |  |
| `/document/tracking/id` | `metadata.source_ref, vex[].vex.source` |  |
| `/document/tracking/version` | `metadata.properties.document_version` |  |
| `/document/tracking/status` | `metadata.properties.document_status` |  |
| `/document/tracking/current_release_date` | `vex[].vex.as_of, metadata.properties.current_release_date` |  |
| `/document/tracking/initial_release_date` | `metadata.properties.initial_release_date` |  |
| `/document/tracking/aliases` |  | other ids of the document |
| `/document/tracking/aliases[]` |  | other ids of the document |
| `/document/tracking/generator*/**` |  | the tool that wrote the document |
| `/document/tracking/generator` |  | the tool that wrote the document |
| `/document/tracking/revision_history*/**` |  | revision log of the document |
| `/document/tracking/revision_history` |  | revision log of the document |
| `/document/distribution` | (container) |  |
| `/document/distribution/text` |  | distribution prose; the TLP label is kept |
| `/document/distribution/tlp` | (container) |  |
| `/document/distribution/tlp/label` | `metadata.properties.tlp` |  |
| `/document/distribution/tlp/url` |  | link to the TLP definition |
| `/document/aggregate_severity` | (container) |  |
| `/document/aggregate_severity/text` | `metadata.properties.aggregate_severity` |  |
| `/document/aggregate_severity/namespace` |  | namespace of the severity text |
| `/document/notes` |  | advisory prose; statements carry the per-product text |
| `/document/notes*/**` |  | advisory prose; statements carry the per-product text |
| `/document/references` |  | links about the advisory; never fetched |
| `/document/references*/**` |  | links about the advisory; never fetched |
| `/document/acknowledgments` |  | names of people and organizations (personal data) |
| `/document/acknowledgments*/**` |  | names of people and organizations (personal data) |
| `/product_tree` | (container) |  |
| `/product_tree/**/branches` | (container) |  |
| `/product_tree/**/branches[]` | (container) |  |
| `/product_tree/**/branches[]/category` | `vex[].products[].version (a product_version branch)` |  |
| `/product_tree/**/branches[]/name` | `vex[].products[].version (a product_version branch; vendor and product names are in the product name)` |  |
| `/product_tree/**/branches[]/product` | (container) |  |
| `/product_tree/**/branches[]/product/name` | `vex[].products[].name` |  |
| `/product_tree/**/branches[]/product/product_id` | `(product id the statements refer to)` |  |
| `/product_tree/full_product_names` | (container) |  |
| `/product_tree/full_product_names[]` | (container) |  |
| `/product_tree/full_product_names[]/name` | `vex[].products[].name` |  |
| `/product_tree/full_product_names[]/product_id` | `(product id the statements refer to)` |  |
| `/product_tree/relationships` | (container) |  |
| `/product_tree/relationships[]` | (container) |  |
| `/product_tree/relationships[]/category` | `vex[].products[].subcomponents (every category: the component inside the platform)` |  |
| `/product_tree/relationships[]/product_reference` | `vex[].products[].subcomponents[]` |  |
| `/product_tree/relationships[]/relates_to_product_reference` | `vex[].products[] (the platform: its PURL or CPE when the relationship has none)` |  |
| `/product_tree/relationships[]/full_product_name` | (container) |  |
| `/product_tree/relationships[]/full_product_name/name` | `vex[].products[].name` |  |
| `/product_tree/relationships[]/full_product_name/product_id` | `(product id the statements refer to)` |  |
| `/product_tree/product_groups` | (container) |  |
| `/product_tree/product_groups[]` | (container) |  |
| `/product_tree/product_groups[]/group_id` | `(group id flags, threats and remediations refer to)` |  |
| `/product_tree/product_groups[]/product_ids` | (container) |  |
| `/product_tree/product_groups[]/product_ids[]` | `(the products of the group)` |  |
| `/product_tree/product_groups[]/summary` |  | description of the group |
| `/product_tree/**/product_identification_helper` | (container) |  |
| `/product_tree/**/product_identification_helper/purl` | `vex[].products[].purl` |  |
| `/product_tree/**/product_identification_helper/cpe` | `vex[].products[].cpe` |  |
| `/product_tree/**/product_identification_helper/hashes` |  | file hashes; findings are matched on PURL and CPE |
| `/product_tree/**/product_identification_helper/hashes*/**` |  | file hashes; findings are matched on PURL and CPE |
| `/product_tree/**/product_identification_helper/model_numbers` |  | hardware model numbers; no CTIS member |
| `/product_tree/**/product_identification_helper/model_numbers[]` |  | hardware model numbers; no CTIS member |
| `/product_tree/**/product_identification_helper/serial_numbers` |  | hardware serial numbers; no CTIS member |
| `/product_tree/**/product_identification_helper/serial_numbers[]` |  | hardware serial numbers; no CTIS member |
| `/product_tree/**/product_identification_helper/skus` |  | stock keeping units; no CTIS member |
| `/product_tree/**/product_identification_helper/skus[]` |  | stock keeping units; no CTIS member |
| `/product_tree/**/product_identification_helper/sbom_urls` |  | links to SBOMs; never fetched |
| `/product_tree/**/product_identification_helper/sbom_urls[]` |  | links to SBOMs; never fetched |
| `/product_tree/**/product_identification_helper/x_generic_uris` |  | other identifiers by URI; never fetched |
| `/product_tree/**/product_identification_helper/x_generic_uris*/**` |  | other identifiers by URI; never fetched |
| `/vulnerabilities` | (container) |  |
| `/vulnerabilities[]` | `vex[] (one statement per status group and statement text)` |  |
| `/vulnerabilities[]/cve` | `vex[].vulnerability_ids (cve)` |  |
| `/vulnerabilities[]/ids` | (container) |  |
| `/vulnerabilities[]/ids[]` | (container) |  |
| `/vulnerabilities[]/ids[]/text` | `vex[].vulnerability_ids` |  |
| `/vulnerabilities[]/ids[]/system_name` | `vex[].vulnerability_ids[].source (vendor ids)` |  |
| `/vulnerabilities[]/product_status` | (container) |  |
| `/vulnerabilities[]/product_status/*` | `vex[].vex.status (by group)` |  |
| `/vulnerabilities[]/product_status/*[]` | `vex[].products` |  |
| `/vulnerabilities[]/flags` | (container) |  |
| `/vulnerabilities[]/flags[]` | (container) |  |
| `/vulnerabilities[]/flags[]/label` | `vex[].vex.justification, native_justification` |  |
| `/vulnerabilities[]/flags[]/product_ids` | (container) |  |
| `/vulnerabilities[]/flags[]/product_ids[]` | `(products the justification is for)` |  |
| `/vulnerabilities[]/flags[]/group_ids` | (container) |  |
| `/vulnerabilities[]/flags[]/group_ids[]` | `(product groups the justification is for)` |  |
| `/vulnerabilities[]/flags[]/date` |  | date of the flag; the document date is the statement date |
| `/vulnerabilities[]/threats` | (container) |  |
| `/vulnerabilities[]/threats[]` | (container) |  |
| `/vulnerabilities[]/threats[]/category` | `(impact threats give the not_affected statement)` |  |
| `/vulnerabilities[]/threats[]/details` | `vex[].vex.statement (not_affected)` |  |
| `/vulnerabilities[]/threats[]/product_ids` | (container) |  |
| `/vulnerabilities[]/threats[]/product_ids[]` | `(products the threat is for)` |  |
| `/vulnerabilities[]/threats[]/group_ids` | (container) |  |
| `/vulnerabilities[]/threats[]/group_ids[]` | `(product groups the threat is for)` |  |
| `/vulnerabilities[]/threats[]/date` |  | date of the threat; the document date is the statement date |
| `/vulnerabilities[]/remediations` | (container) |  |
| `/vulnerabilities[]/remediations[]` | (container) |  |
| `/vulnerabilities[]/remediations[]/category` | `vex[].vex.statement (affected, fixed)` |  |
| `/vulnerabilities[]/remediations[]/details` | `vex[].vex.statement (affected, fixed)` |  |
| `/vulnerabilities[]/remediations[]/url` | `vex[].vex.statement (affected, fixed); never fetched` |  |
| `/vulnerabilities[]/remediations[]/product_ids` | (container) |  |
| `/vulnerabilities[]/remediations[]/product_ids[]` | `(products the remediation is for)` |  |
| `/vulnerabilities[]/remediations[]/group_ids` | (container) |  |
| `/vulnerabilities[]/remediations[]/group_ids[]` | `(product groups the remediation is for)` |  |
| `/vulnerabilities[]/remediations[]/date` |  | date of the remediation |
| `/vulnerabilities[]/remediations[]/entitlements` |  | who may get the fix (licensing prose) |
| `/vulnerabilities[]/remediations[]/entitlements[]` |  | who may get the fix (licensing prose) |
| `/vulnerabilities[]/remediations[]/restart_required` |  | operational detail of applying the fix |
| `/vulnerabilities[]/remediations[]/restart_required*/**` |  | operational detail of applying the fix |
| `/vulnerabilities[]/scores` |  | per-product CVSS of the advisory; a statement carries no scores, and the receiver's findings keep their own |
| `/vulnerabilities[]/scores*/**` |  | per-product CVSS of the advisory; a statement carries no scores, and the receiver's findings keep their own |
| `/vulnerabilities[]/cwe` |  | weakness of the vulnerability; a statement carries no weakness |
| `/vulnerabilities[]/cwe*/**` |  | weakness of the vulnerability; a statement carries no weakness |
| `/vulnerabilities[]/title` |  | vulnerability title (advisory prose) |
| `/vulnerabilities[]/notes` |  | vulnerability prose; statements carry the per-product text |
| `/vulnerabilities[]/notes*/**` |  | vulnerability prose; statements carry the per-product text |
| `/vulnerabilities[]/references` |  | links about the vulnerability; never fetched |
| `/vulnerabilities[]/references*/**` |  | links about the vulnerability; never fetched |
| `/vulnerabilities[]/acknowledgments` |  | names of people and organizations (personal data) |
| `/vulnerabilities[]/acknowledgments*/**` |  | names of people and organizations (personal data) |
| `/vulnerabilities[]/involvements` |  | coordination log of the parties |
| `/vulnerabilities[]/involvements*/**` |  | coordination log of the parties |
| `/vulnerabilities[]/discovery_date` |  | when the vulnerability was discovered |
| `/vulnerabilities[]/release_date` |  | when the vulnerability was published |
