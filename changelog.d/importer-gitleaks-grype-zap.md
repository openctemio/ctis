### Added: gitleaks, grype and ZAP importers

- `importer.Parse` reads gitleaks JSON reports (`gitleaks`), grype JSON output (`grype`) and ZAP traditional reports in JSON and XML (`zap`); `importer.Detect` recognizes them.
- gitleaks: one secret finding per leak on `Options.DefaultAsset` (the scanned repository), with rule id, location, commit, entropy and tags; the secret type is mapped to the CTIS vocabulary by keyword.
- grype: the scanned image (container), directory (repository) or SBOM becomes the asset; one finding per match with every CVSS entry and its source, EPSS, KEV, typed ids of related vulnerabilities, fix versions and state, advisories; one dependency per artifact.
- ZAP: one website asset per site origin; one finding per alert with riskcode severity, confidence, CWE, references, tags and up to 20 instances (method, URI, parameter, attack, evidence) as evidence.
- Mapping specs `docs/importers/gitleaks.md`, `grype.md` and `zap.md`.

### Security

- gitleaks: the raw secret never reaches the report. `Secret` is masked with the rule of the SARIF converter (first four characters of a value of at least 16 characters, else `REDACTED`) and every repeat in the description and fingerprint is replaced; `Match` and `Line` are not read; the commit author, e-mail and message are never read.
- grype: the scan configuration (registry settings and credentials), image manifest and config blobs and image labels are never read.
- ZAP: request and response headers and bodies (cookies, authorization headers, session tokens) are never read, and the user info of instance URIs is removed.
