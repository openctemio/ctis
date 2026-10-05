# vuls JSON scan result mapping

Generated from `importer/spec_vuls.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `vuls`
- Source versions: vuls report JSON (jsonVersion 4) of one server
- Fields: 62 mapped, 58 ignored on purpose (52% mapped)

## Rules

- One asset per file: the first scanned IPv4 address (ip_address, with the server name as host name), else the server name (host). A file that names neither imports nothing, with an issue.
- One finding per scanned CVE; severity from the preferred CVSS score (v4, else v3, else v2): 9+ critical, 7+ high, 4+ medium, above 0 low, else info.
- Packages become dependencies with an OS PURL (deb, rpm, apk, ...) carrying arch and distro.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/jsonVersion` | `format check` |  |
| `/serverName` | `assets[].value or name, findings[].tags` |  |
| `/serverUUID` |  | vuls-internal server id |
| `/family` | `assets[].tags, properties.os_family, dependencies[].ecosystem, purl type` |  |
| `/release` | `assets[].tags, properties.os_release, purl distro` |  |
| `/container` |  | container of a container scan (vuls container mode) |
| `/container/**` |  | container of a container scan |
| `/runningKernel` | (container) |  |
| `/runningKernel/version` | `assets[].properties.kernel_version` |  |
| `/runningKernel/release` | `assets[].properties.kernel_release` |  |
| `/runningKernel/rebootRequired` | `assets[].properties.reboot_required` |  |
| `/scannedAt` | `assets[].properties.scanned_at` |  |
| `/scanMode` |  | scan mode (fast, deep) |
| `/scannedVersion` |  | vuls version |
| `/scannedRevision` |  | vuls revision |
| `/scannedBy` |  | the host vuls ran on |
| `/scannedVia` | `assets[].properties.scanned_via` |  |
| `/scannedIpv4Addrs` | (container) |  |
| `/scannedIpv4Addrs[]` | `assets[].value (the first)` |  |
| `/scannedIpv6Addrs` | (container) |  |
| `/scannedIpv6Addrs[]` | `assets[].properties.ipv6_addresses` |  |
| `/reportedAt` |  | report time |
| `/reportedVersion` |  | vuls version |
| `/reportedRevision` |  | vuls revision |
| `/reportedBy` |  | the host vuls reported from |
| `/errors` |  | scan errors |
| `/errors[]` |  | scan errors |
| `/warnings` |  | scan warnings |
| `/warnings[]` |  | scan warnings |
| `/platform` | (container) |  |
| `/platform/name` | `assets[].properties.platform` |  |
| `/platform/instanceID` | `assets[].identity_hints.cloud_resource_id` |  |
| `/ipv4Addrs` |  | addresses read on the host; the scanned address is kept |
| `/ipv4Addrs[]` |  | addresses read on the host |
| `/ipv6Addrs` |  | addresses read on the host |
| `/ipv6Addrs[]` |  | addresses read on the host |
| `/packages` | (container) |  |
| `/packages/*` | `dependencies[]` |  |
| `/packages/*/name` | `dependencies[].name, purl` |  |
| `/packages/*/version` | `dependencies[].version, purl` |  |
| `/packages/*/release` | `dependencies[].version, purl` |  |
| `/packages/*/arch` | `dependencies[].purl (arch)` |  |
| `/packages/*/repository` |  | package repository |
| `/packages/*/newVersion` |  | available update; fixed versions come from the CVE |
| `/packages/*/newRelease` |  | available update; fixed versions come from the CVE |
| `/packages/*/*` |  | other package details (changelog, processes using it) |
| `/packages/*/*/**` |  | other package details |
| `/srcPackages` |  | source packages; binary packages are kept |
| `/srcPackages/**` |  | source packages; binary packages are kept |
| `/scannedCves` | (container) |  |
| `/scannedCves/*` | `findings[]` |  |
| `/scannedCves/*/cveID` | `findings[].rule_id, native.vuln_id, vulnerability.ids, cve_id` |  |
| `/scannedCves/*/confidences` | (container) |  |
| `/scannedCves/*/confidences[]` | (container) |  |
| `/scannedCves/*/confidences[]/score` | `findings[].confidence (the first)` |  |
| `/scannedCves/*/confidences[]/detectionMethod` | `findings[].source_extra.detection_method` |  |
| `/scannedCves/*/affectedPackages` | (container) |  |
| `/scannedCves/*/affectedPackages[]` | (container) |  |
| `/scannedCves/*/affectedPackages[]/name` | `findings[].vulnerability.package, purl, affected_version (the first)` |  |
| `/scannedCves/*/affectedPackages[]/fixedIn` | `findings[].vulnerability.fixed_version, remediation` |  |
| `/scannedCves/*/affectedPackages[]/notFixedYet` | `findings[].remediation.solution_type no_fix` |  |
| `/scannedCves/*/affectedPackages[]/fixState` | `findings[].source_extra.fix_state` |  |
| `/scannedCves/*/cveContents` | (container) |  |
| `/scannedCves/*/cveContents/*` | (container) |  |
| `/scannedCves/*/cveContents/*[]` | `findings[] details from the preferred source (nvd, redhat, ubuntu, debian, oracle, amazon, suse, then by name)` |  |
| `/scannedCves/*/cveContents/*[]/type` |  | the content source; the key names it |
| `/scannedCves/*/cveContents/*[]/cveID` |  | duplicate of the CVE id |
| `/scannedCves/*/cveContents/*[]/title` | `findings[].title` |  |
| `/scannedCves/*/cveContents/*[]/summary` | `findings[].description` |  |
| `/scannedCves/*/cveContents/*[]/cvss3Score` | `findings[].scores[] (cvss 3.x, every source), vulnerability.cvss_score` |  |
| `/scannedCves/*/cveContents/*[]/cvss3Vector` | `findings[].scores[].vector, vulnerability.cvss_vector` |  |
| `/scannedCves/*/cveContents/*[]/cvss3Severity` |  | label of the cvss3 score |
| `/scannedCves/*/cveContents/*[]/cvss2Score` | `findings[].scores[] (cvss 2.0), vulnerability.cvss_score (when no v3/v4)` |  |
| `/scannedCves/*/cveContents/*[]/cvss2Vector` | `findings[].scores[].vector` |  |
| `/scannedCves/*/cveContents/*[]/cvss2Severity` |  | label of the cvss2 score |
| `/scannedCves/*/cveContents/*[]/cvss40Score` | `findings[].scores[] (cvss 4.0), vulnerability.cvss_score` |  |
| `/scannedCves/*/cveContents/*[]/cvss40Vector` | `findings[].scores[].vector` |  |
| `/scannedCves/*/cveContents/*[]/cweIDs` | (container) |  |
| `/scannedCves/*/cveContents/*[]/cweIDs[]` | `findings[].vulnerability.cwe_ids` |  |
| `/scannedCves/*/cveContents/*[]/references` | (container) |  |
| `/scannedCves/*/cveContents/*[]/references[]` | (container) |  |
| `/scannedCves/*/cveContents/*[]/references[]/link` | `findings[].references` |  |
| `/scannedCves/*/cveContents/*[]/references[]/source` |  | reference source; the link is kept |
| `/scannedCves/*/cveContents/*[]/references[]/refID` |  | reference id; the link is kept |
| `/scannedCves/*/cveContents/*[]/references[]/tags` |  | reference tags |
| `/scannedCves/*/cveContents/*[]/references[]/tags[]` |  | reference tags |
| `/scannedCves/*/cveContents/*[]/published` | `findings[].vulnerability.published_at` |  |
| `/scannedCves/*/cveContents/*[]/lastModified` | `findings[].vulnerability.modified_at` |  |
| `/scannedCves/*/cveContents/*[]/sourceLink` | `findings[].references` |  |
| `/scannedCves/*/cveContents/*[]/optional` |  | source-specific extras |
| `/scannedCves/*/cveContents/*[]/optional/**` |  | source-specific extras |
| `/scannedCves/*/cveContents/*[]/*` |  | other content members (cpes, severity words, mitigations) |
| `/scannedCves/*/cveContents/*[]/*/**` |  | other content members (cpes, severity words, mitigations) |
| `/scannedCves/*/alertDict` |  | security alerts (CERT, US-CERT, JPCERT) of the CVE |
| `/scannedCves/*/alertDict/**` |  | security alerts (CERT, US-CERT, JPCERT) of the CVE |
| `/scannedCves/*/*` |  | other per-CVE data (exploits, metasploit modules, KEV, CTI): vuls enrichment kept out of this mapping |
| `/scannedCves/*/*/**` |  | other per-CVE data |
| `/scannedCves[]` | `findings[]` |  |
| `/scannedCves[]/cveID` | `findings[].rule_id, native.vuln_id, vulnerability.ids, cve_id` |  |
| `/scannedCves[]/confidences` | (container) |  |
| `/scannedCves[]/confidences[]` | (container) |  |
| `/scannedCves[]/confidences[]/score` | `findings[].confidence (the first)` |  |
| `/scannedCves[]/confidences[]/detectionMethod` | `findings[].source_extra.detection_method` |  |
| `/scannedCves[]/affectedPackages` | (container) |  |
| `/scannedCves[]/affectedPackages[]` | (container) |  |
| `/scannedCves[]/affectedPackages[]/name` | `findings[].vulnerability.package, purl, affected_version (the first)` |  |
| `/scannedCves[]/affectedPackages[]/fixedIn` | `findings[].vulnerability.fixed_version, remediation` |  |
| `/scannedCves[]/affectedPackages[]/notFixedYet` | `findings[].remediation.solution_type no_fix` |  |
| `/scannedCves[]/affectedPackages[]/fixState` | `findings[].source_extra.fix_state` |  |
| `/scannedCves[]/cveContents` | (container) |  |
| `/scannedCves[]/cveContents/*` | (container) |  |
| `/scannedCves[]/cveContents/*[]` | `findings[] details from the preferred source (nvd, redhat, ubuntu, debian, oracle, amazon, suse, then by name)` |  |
| `/scannedCves[]/cveContents/*[]/type` |  | the content source; the key names it |
| `/scannedCves[]/cveContents/*[]/cveID` |  | duplicate of the CVE id |
| `/scannedCves[]/cveContents/*[]/title` | `findings[].title` |  |
| `/scannedCves[]/cveContents/*[]/summary` | `findings[].description` |  |
| `/scannedCves[]/cveContents/*[]/cvss3Score` | `findings[].scores[] (cvss 3.x, every source), vulnerability.cvss_score` |  |
| `/scannedCves[]/cveContents/*[]/cvss3Vector` | `findings[].scores[].vector, vulnerability.cvss_vector` |  |
| `/scannedCves[]/cveContents/*[]/cvss3Severity` |  | label of the cvss3 score |
| `/scannedCves[]/cveContents/*[]/cvss2Score` | `findings[].scores[] (cvss 2.0), vulnerability.cvss_score (when no v3/v4)` |  |
| `/scannedCves[]/cveContents/*[]/cvss2Vector` | `findings[].scores[].vector` |  |
| `/scannedCves[]/cveContents/*[]/cvss2Severity` |  | label of the cvss2 score |
| `/scannedCves[]/cveContents/*[]/cvss40Score` | `findings[].scores[] (cvss 4.0), vulnerability.cvss_score` |  |
| `/scannedCves[]/cveContents/*[]/cvss40Vector` | `findings[].scores[].vector` |  |
| `/scannedCves[]/cveContents/*[]/cweIDs` | (container) |  |
| `/scannedCves[]/cveContents/*[]/cweIDs[]` | `findings[].vulnerability.cwe_ids` |  |
| `/scannedCves[]/cveContents/*[]/references` | (container) |  |
| `/scannedCves[]/cveContents/*[]/references[]` | (container) |  |
| `/scannedCves[]/cveContents/*[]/references[]/link` | `findings[].references` |  |
| `/scannedCves[]/cveContents/*[]/references[]/source` |  | reference source; the link is kept |
| `/scannedCves[]/cveContents/*[]/references[]/refID` |  | reference id; the link is kept |
| `/scannedCves[]/cveContents/*[]/references[]/tags` |  | reference tags |
| `/scannedCves[]/cveContents/*[]/references[]/tags[]` |  | reference tags |
| `/scannedCves[]/cveContents/*[]/published` | `findings[].vulnerability.published_at` |  |
| `/scannedCves[]/cveContents/*[]/lastModified` | `findings[].vulnerability.modified_at` |  |
| `/scannedCves[]/cveContents/*[]/sourceLink` | `findings[].references` |  |
| `/scannedCves[]/cveContents/*[]/optional` |  | source-specific extras |
| `/scannedCves[]/cveContents/*[]/optional/**` |  | source-specific extras |
| `/scannedCves[]/cveContents/*[]/*` |  | other content members (cpes, severity words, mitigations) |
| `/scannedCves[]/cveContents/*[]/*/**` |  | other content members (cpes, severity words, mitigations) |
| `/scannedCves[]/alertDict` |  | security alerts (CERT, US-CERT, JPCERT) of the CVE |
| `/scannedCves[]/alertDict/**` |  | security alerts (CERT, US-CERT, JPCERT) of the CVE |
| `/scannedCves[]/*` |  | other per-CVE data (exploits, metasploit modules, KEV, CTI): vuls enrichment kept out of this mapping |
| `/scannedCves[]/*/**` |  | other per-CVE data |
