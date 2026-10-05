### Added: the importer package and the Nessus v2 importer

- `importer.Detect` names the format of an exported file from its first bytes; `importer.Parse` converts it to a CTIS 1.4 report, with counts, problems with their line numbers, and the source fields the format's mapping spec does not list.
- Nessus v2 XML (`.nessus`, from Nessus and Tenable.sc): one asset per host with its identity hints (FQDN, NetBIOS name, MACs, OS CPE, cloud instance id, agent id), one finding per plugin result or compliance check, with the native identity (plugin id, family, severity, credentialed scan), every CVSS version, VPR and EPSS in `scores`, typed vulnerability ids, CWEs, advisories, KEV and exploit flags, and the remaining plugin members in `source_extra`.
- Every importer has a mapping spec rendered to `docs/importers/`, golden fixtures, and a field-coverage test that fails when a fixture holds a field the spec does not list or the spec maps a field no fixture holds.
- `importer.OpenZip` lists the files of an uploaded ZIP archive without writing to disk.

### Security

- Imported files are hostile input: limits on size, nesting depth, elements, attributes, text and records; XML internal subsets, entity declarations and external resources are refused (an external DTD identifier is allowed and never read); only UTF-8, US-ASCII and ISO-8859-1; `OpenZip` refuses path traversal, absolute paths, links, encrypted entries, nested archives and decompression bombs.
- The Nessus scan policy (which holds scan credentials) is skipped whole; the accounts a scan logged in with are not read; plugin output and compliance values have account names, passwords, tokens and community strings replaced by `[redacted]`.
