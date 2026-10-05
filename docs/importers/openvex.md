# OpenVEX mapping

Generated from `importer/spec_openvex.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `openvex`
- Source versions: OpenVEX v0.2.0 (the v0.0.1 string forms of vulnerability, products and subcomponents are read too)
- Fields: 29 mapped, 11 ignored on purpose (72% mapped)

## Rules

- An OpenVEX document describes products, not findings: the report has no assets or findings, and Result.VEX holds one statement per OpenVEX statement.
- Statuses and justifications are the CTIS VEX vocabulary already. A not_affected statement needs a justification or an impact statement; without either it is skipped with an issue.
- Statement text: impact_statement (not_affected) or action_statement (affected), followed by status_notes.
- Products: identifiers.purl and identifiers.cpe23 (else cpe22) win; an @id that is a PURL or CPE fills the empty one; any other @id is the product name.
- Subcomponents narrow a product: they go to products[].subcomponents, and the statement is about those components inside that product only (a v0.0.1 statement-level subcomponents list narrows every product).
- Statement source: author (@id) of the document; as_of: the statement's last_updated or timestamp, else the document's.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/@context` | `metadata.properties.openvex_context (format check)` |  |
| `/@id` | `metadata.source_ref, vex[].vex.source` |  |
| `/author` | `vex[].vex.source, metadata.properties.author` |  |
| `/role` |  | the author's role (prose) |
| `/timestamp` | `vex[].vex.as_of (when the statement has none)` |  |
| `/last_updated` | `vex[].vex.as_of (when the statement has none)` |  |
| `/version` | `metadata.properties.document_version` |  |
| `/tooling` | `metadata.properties.tooling` |  |
| `/statements` | (container) |  |
| `/statements[]` | `vex[]` |  |
| `/statements[]/@id` |  | statement id; the document id is the source |
| `/statements[]/version` |  | statement revision |
| `/statements[]/vulnerability` | `vex[].vulnerability_ids (v0.0.1 string, or the object below)` |  |
| `/statements[]/vulnerability/name` | `vex[].vulnerability_ids` |  |
| `/statements[]/vulnerability/aliases` | (container) |  |
| `/statements[]/vulnerability/aliases[]` | `vex[].vulnerability_ids` |  |
| `/statements[]/vulnerability/@id` |  | IRI of the vulnerability record; name and aliases carry the ids |
| `/statements[]/vulnerability/description` |  | vulnerability prose; the statement text is kept |
| `/statements[]/products` | (container) |  |
| `/statements[]/products[]` | `vex[].products[] (v0.0.1 string, or the object below)` |  |
| `/statements[]/products[]/@id` | `vex[].products[].purl, cpe or name` |  |
| `/statements[]/products[]/identifiers` | (container) |  |
| `/statements[]/products[]/identifiers/purl` | `vex[].products[].purl` |  |
| `/statements[]/products[]/identifiers/cpe23` | `vex[].products[].cpe` |  |
| `/statements[]/products[]/identifiers/cpe22` | `vex[].products[].cpe (when no cpe23)` |  |
| `/statements[]/products[]/hashes` |  | artifact hashes; findings are matched on PURL and CPE |
| `/statements[]/products[]/hashes/*` |  | artifact hashes; findings are matched on PURL and CPE |
| `/statements[]/products[]/subcomponents` | (container) |  |
| `/statements[]/products[]/subcomponents[]` | `vex[].products[].subcomponents[] (v0.0.1 string, or the object below)` |  |
| `/statements[]/products[]/subcomponents[]/@id` | `vex[].products[].subcomponents[].purl, cpe or name` |  |
| `/statements[]/products[]/subcomponents[]/identifiers` | (container) |  |
| `/statements[]/products[]/subcomponents[]/identifiers/purl` | `vex[].products[].subcomponents[].purl` |  |
| `/statements[]/products[]/subcomponents[]/identifiers/cpe23` | `vex[].products[].subcomponents[].cpe` |  |
| `/statements[]/products[]/subcomponents[]/identifiers/cpe22` | `vex[].products[].subcomponents[].cpe (when no cpe23)` |  |
| `/statements[]/products[]/subcomponents[]/hashes` |  | artifact hashes; findings are matched on PURL and CPE |
| `/statements[]/products[]/subcomponents[]/hashes/*` |  | artifact hashes; findings are matched on PURL and CPE |
| `/statements[]/subcomponents` | (container) |  |
| `/statements[]/subcomponents[]` | `vex[].products[].subcomponents[] (v0.0.1: narrows every product)` |  |
| `/statements[]/status` | `vex[].vex.status` |  |
| `/statements[]/status_notes` | `vex[].vex.statement (appended)` |  |
| `/statements[]/justification` | `vex[].vex.justification, native_justification` |  |
| `/statements[]/impact_statement` | `vex[].vex.statement (not_affected)` |  |
| `/statements[]/action_statement` | `vex[].vex.statement (affected)` |  |
| `/statements[]/action_statement_timestamp` |  | when the action statement was written; the statement date is kept |
| `/statements[]/timestamp` | `vex[].vex.as_of (when no last_updated)` |  |
| `/statements[]/last_updated` | `vex[].vex.as_of` |  |
| `/statements[]/supplier` |  | who supplies the product, not who makes the statement |
