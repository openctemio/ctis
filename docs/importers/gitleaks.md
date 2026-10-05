# gitleaks JSON report mapping

Generated from `importer/spec_gitleaks.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `gitleaks`
- Source versions: the JSON report of gitleaks 8.x (`--report-format json`), an array of leaks; any gitleaks-compatible scanner that writes the same shape
- Fields: 16 mapped, 5 ignored on purpose (76% mapped)

## Rules

- One secret finding per leak, severity high, on Options.DefaultAsset (the scanned repository), else on an unclassified asset named after the tool.
- Detection: a top-level array whose first element has RuleID and Secret or Match. Every gitleaks-compatible scanner writes this shape, so the format cannot tell them apart; Options.ToolName names the tool.
- The raw secret never reaches the report: Secret becomes location.snippet masked with the rule of the SARIF converter (first four characters of a value of at least 16 characters followed by asterisks, else REDACTED), and every occurrence of the secret in Description and Fingerprint is replaced by the mask. Match and Line hold the secret with its context and are not read. secret.masked_value is left unset so receiver fingerprints match those of SARIF secret findings.
- The commit author, e-mail address and commit message are personal data and are never read.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/[]` | `findings[]` |  |
| `/[]/RuleID` | `findings[].rule_id, native.vuln_id, secret.secret_type (mapped to the CTIS vocabulary by keyword, else generic_secret)` |  |
| `/[]/Description` | `findings[].title, rule_name, description (secret masked)` |  |
| `/[]/Secret` | `findings[].location.snippet (masked)` |  |
| `/[]/Match` |  | holds the raw secret with its context; the masked secret is kept |
| `/[]/Line` |  | the whole source line, which holds the raw secret |
| `/[]/File` | `findings[].location.path` |  |
| `/[]/SymlinkFile` | `findings[].source_extra.symlink_file` |  |
| `/[]/StartLine` | `findings[].location.start_line` |  |
| `/[]/EndLine` | `findings[].location.end_line` |  |
| `/[]/StartColumn` | `findings[].location.start_column` |  |
| `/[]/EndColumn` | `findings[].location.end_column` |  |
| `/[]/Commit` | `findings[].location.commit_sha (source_extra.commit without a file)` |  |
| `/[]/Date` | `findings[].commit_date` |  |
| `/[]/Entropy` | `findings[].secret.entropy` |  |
| `/[]/Tags` | (container) |  |
| `/[]/Tags[]` | `findings[].tags` |  |
| `/[]/Fingerprint` | `findings[].native.instance_id (secret masked)` |  |
| `/[]/Link` | `findings[].references (http(s) only)` |  |
| `/[]/Author` |  | the commit author (personal data) |
| `/[]/Email` |  | the commit author's e-mail address (personal data) |
| `/[]/Message` |  | the commit message (may name people; not a property of the leak) |
