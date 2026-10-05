### Added: the DefectDojo Generic Findings JSON importer

- `importer.Parse` reads DefectDojo Generic Findings Import JSON. One finding per record and endpoint host (domain or IP asset); a record without endpoints goes to `Options.DefaultAsset`, else to an unclassified asset named after the tool.
- Kept: the severity label and the status flags as native values (normalized to the CTIS severity, status and source state), `vuln_id_from_tool` and `unique_id_from_tool`, CVE and typed vulnerability ids, CWE, CVSS v3 and v4 with vectors, EPSS, KEV, component and fix version, file and line, endpoint port, protocol and URL, tags, mitigation, effort, payload, and the other members in `source_extra`.
- A record that cannot be decoded is skipped with an issue at its line; values written as numbers or strings are read either way.
- New `Options.DefaultAsset` for records that name no asset.

### Security

- Endpoint user info (credentials in the URL), attached files, and the DefectDojo users who reported or mitigated a finding are never read.
