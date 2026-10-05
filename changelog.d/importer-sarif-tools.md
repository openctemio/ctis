### Added: SARIF 2.1.0 and the trivy, nuclei, semgrep, betterleaks and vuls formats in the importer

- `importer.Parse` reads SARIF 2.1.0 (through `FromSARIF`, with the importer's input limits) and the native JSON of trivy, nuclei (JSON lines or an array), semgrep, betterleaks and vuls, with mapping specs, golden fixtures and the field-coverage gate like the other formats. `importer.Detect` recognizes each of them.
- New `Options.Repository`, `Branch` and `CommitSHA`: the repository a code report is filed on. It wins over the repository or image a file names (a SARIF `versionControlProvenance`, a trivy artifact), so a receiver that sets it from a verified identity decides the asset, never the file.
- `ctis.MaskSecretMatch`: the masking `FromSARIF` applies to a secret scanner's match, for other secret-scanner formats.
- Parity with the SDK's tool adapters is tested on their fixtures; the differences are listed in the test with their reasons (SARIF titles and types from `FromSARIF`, schema secret types, no default criticality, semgrep's placeholder fingerprint).

### Security

- Raw secrets never reach a report: betterleaks and trivy matches are masked in the snippet, title and commit message, and only the masked value goes into fingerprints. Credentials in SARIF repository URIs and in nuclei URLs are removed; nuclei raw requests, responses, curl commands and extracted values, and trivy image configuration and code lines are never read.
- Each nuclei line is checked on its own: a broken, oversized or wrong-typed line is skipped with an issue at its line.
- Fuzzing found and this change fixes two invalid outputs: a trivy CVSS score above 10 in the legacy members, and a SARIF result with neither message nor rule.

### Changed: one parser for gitleaks and betterleaks reports

- gitleaks and betterleaks write the same JSON shape and are now read by one parser. `importer.Detect` names the shape `gitleaks`; `betterleaks` is the same mapping under its tool name, chosen with `Options.Format`. The record is filed on `Options.Repository` (else `Options.DefaultAsset`); the secret is masked with `ctis.MaskSecretMatch` in the masked value, snippet, title and commit message; the commit author and e-mail are kept (the person who must rotate the secret), replacing the gitleaks behaviour of the previous unreleased entry that dropped them.
- `importer.Detect` also recognizes a nuclei `-json-export` array.
