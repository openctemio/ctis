# SPDX JSON mapping

Generated from `importer/spec_spdx.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `spdx`
- Source versions: SPDX 2.2 and 2.3 JSON
- Fields: 28 mapped, 34 ignored on purpose (45% mapped)

## Rules

- SPDX holds packages, not vulnerabilities: the result is one asset and its dependencies, no findings.
- The asset is the described package (documentDescribes, else the DESCRIBES / DESCRIBED_BY relationship of the document): value is its purl, else name@version; type container for a CONTAINER purpose, host for OPERATING-SYSTEM, DEVICE, FIRMWARE, else repository. Without one, a repository asset named after the document holds the dependencies, and an issue says so. A document without packages creates no asset.
- Every other package is a dependency: id is its SPDXID (a second package with a used SPDXID is skipped with an issue); licenses are licenseConcluded, else licenseDeclared, never NOASSERTION or NONE.
- DEPENDS_ON and CONTAINS (and their inverses DEPENDENCY_OF, CONTAINED_BY) between packages become depends_on; from the described package they make the target a direct dependency. Other relationship types are ignored.
- Suppliers and originators are kept only as organization names: a "Person:" value, and every e-mail address, is never read. Document creators are kept only when they are tools.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/spdxVersion` | `metadata.properties.spdx_version (must be SPDX-2.x)` |  |
| `/dataLicense` |  | license of the document itself |
| `/SPDXID` | `the DESCRIBES relationship of the document` |  |
| `/name` | `metadata.properties.sbom_name, the asset when no package is described` |  |
| `/documentNamespace` | `metadata.properties.sbom_namespace` |  |
| `/comment` |  | free text about the document |
| `/creationInfo` | (container) |  |
| `/creationInfo/created` | `metadata.properties.sbom_created` |  |
| `/creationInfo/creators` | (container) |  |
| `/creationInfo/creators[]` | `metadata.properties.sbom_tools (Tool: entries only; persons and organizations are not read)` |  |
| `/creationInfo/licenseListVersion` |  | version of the SPDX license list used |
| `/creationInfo/comment` |  | free text about the document |
| `/externalDocumentRefs` |  | other SPDX documents; only this one is read |
| `/externalDocumentRefs[]/**` |  | other SPDX documents; only this one is read |
| `/documentDescribes` | (container) |  |
| `/documentDescribes[]` | `assets[] (the first described package)` |  |
| `/packages` | (container) |  |
| `/packages[]` | `dependencies[], assets[] (the described package)` |  |
| `/packages[]/SPDXID` | `dependencies[].id` |  |
| `/packages[]/name` | `dependencies[].name, assets[].name` |  |
| `/packages[]/versionInfo` | `dependencies[].version, assets[].value, assets[].properties.version` |  |
| `/packages[]/primaryPackagePurpose` | `dependencies[].type, assets[].type, assets[].properties.package_purpose` |  |
| `/packages[]/supplier` | `dependencies[].properties.supplier (organizations only)` |  |
| `/packages[]/originator` | `dependencies[].properties.originator (organizations only)` |  |
| `/packages[]/downloadLocation` | `dependencies[].properties.download_location` |  |
| `/packages[]/homepage` | `dependencies[].properties.homepage` |  |
| `/packages[]/licenseConcluded` | `dependencies[].licenses` |  |
| `/packages[]/licenseDeclared` | `dependencies[].licenses (when nothing is concluded)` |  |
| `/packages[]/licenseInfoFromFiles` |  | licenses found in the package files; the concluded or declared license is kept |
| `/packages[]/licenseInfoFromFiles[]` |  | licenses found in the package files; the concluded or declared license is kept |
| `/packages[]/licenseComments` |  | free text about the license |
| `/packages[]/copyrightText` |  | copyright notice text |
| `/packages[]/checksums` | (container) |  |
| `/packages[]/checksums[]` | (container) |  |
| `/packages[]/checksums[]/algorithm` | `dependencies[].properties.checksum_<algorithm> (key)` |  |
| `/packages[]/checksums[]/checksumValue` | `dependencies[].properties.checksum_<algorithm>` |  |
| `/packages[]/externalRefs` | (container) |  |
| `/packages[]/externalRefs[]` | (container) |  |
| `/packages[]/externalRefs[]/referenceCategory` | `selects PERSISTENT-ID refs` |  |
| `/packages[]/externalRefs[]/referenceType` | `selects purl, cpe23Type/cpe22Type, advisory/fix/url/swid, PERSISTENT-ID refs` |  |
| `/packages[]/externalRefs[]/referenceLocator` | `dependencies[].purl (purl), properties.cpe (cpe), properties.security_refs (advisory, fix, url, swid), properties.persistent_id_<type>; assets[].value (purl)` |  |
| `/packages[]/externalRefs[]/comment` |  | free text about the reference |
| `/packages[]/releaseDate` | `dependencies[].properties.release_date` |  |
| `/packages[]/builtDate` | `dependencies[].properties.built_date` |  |
| `/packages[]/validUntilDate` |  | end of support date of the package; not a property CTIS defines |
| `/packages[]/filesAnalyzed` |  | whether the producer looked at the files |
| `/packages[]/packageFileName` |  | file name of the package archive |
| `/packages[]/packageVerificationCode/**` |  | digest of the package files; checksums are kept |
| `/packages[]/hasFiles` |  | files of the package; files are not imported |
| `/packages[]/hasFiles[]` |  | files of the package; files are not imported |
| `/packages[]/sourceInfo` |  | free text about the package source |
| `/packages[]/description` |  | free text about the package |
| `/packages[]/summary` |  | free text about the package |
| `/packages[]/comment` |  | free text about the package |
| `/packages[]/attributionTexts` |  | attribution notices |
| `/packages[]/attributionTexts[]` |  | attribution notices |
| `/packages[]/annotations` |  | comments by people; names and text |
| `/packages[]/annotations[]/**` |  | comments by people; names and text |
| `/relationships` | (container) |  |
| `/relationships[]` | (container) |  |
| `/relationships[]/spdxElementId` | `dependencies[].depends_on, relationship (the dependent)` |  |
| `/relationships[]/relationshipType` | `selects DEPENDS_ON, DEPENDENCY_OF, CONTAINS, CONTAINED_BY, DESCRIBES, DESCRIBED_BY` |  |
| `/relationships[]/relatedSpdxElement` | `dependencies[].depends_on, relationship (the dependency)` |  |
| `/relationships[]/comment` |  | free text about the relationship |
| `/files` |  | files and their licenses; a package inventory is imported, not a file inventory |
| `/files[]/**` |  | files and their licenses; a package inventory is imported, not a file inventory |
| `/snippets` |  | snippets of files; not imported |
| `/snippets[]/**` |  | snippets of files; not imported |
| `/hasExtractedLicensingInfos` |  | texts of non-SPDX licenses |
| `/hasExtractedLicensingInfos[]/**` |  | texts of non-SPDX licenses |
| `/annotations` |  | comments by people; names and text |
| `/annotations[]/**` |  | comments by people; names and text |
