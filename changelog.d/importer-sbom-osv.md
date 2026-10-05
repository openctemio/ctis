### Added: CycloneDX, SPDX and OSV importers

- CycloneDX 1.4-1.6 JSON (SBOM, VDR, VEX): the subject component is the asset (container, host or repository), every other component at any depth a dependency with licenses, hashes, purl and the dependency graph; one finding per vulnerability and affected component with typed ids, every rating as a score (CVSS 2.0-4.0, SSVC, vendor), CWEs, advisories, recommendation and workaround; `analysis` becomes the finding's VEX and a VEX statement whose products are the affected purls. Findings the analysis declares not_affected, resolved or false_positive are not made; a bare not_affected claim (no justification, no detail) is refused and the finding kept.
- SPDX 2.2/2.3 JSON: the described package is the asset, every other package a dependency (purl, CPE, licenses, checksums, organization supplier and originator), DEPENDS_ON / CONTAINS relationships as the graph.
- osv-scanner JSON results: one asset per scanned source, its packages as dependencies, one finding per package and vulnerability group with every id and alias, CVSS vectors as scores, the affected version range and fixed versions, and database-specific data in `source_extra`.
- Mapping specs `docs/importers/cyclonedx.md`, `spdx.md`, `osv.md` with golden fixtures under the field-coverage gate.

### Security

- People's names and contacts (BOM authors, credits, supplier contacts, annotations, SPDX `Person:` suppliers and creators, e-mail addresses) are never read; CycloneDX proof-of-concept material is not copied. Package URLs with control characters or whitespace are dropped before they reach a match key.
