# betterleaks JSON report mapping

Generated from `importer/spec_betterleaks.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `betterleaks`
- Source versions: betterleaks v1 --report-format json (the gitleaks-compatible array of leak records)
- Fields: 20 mapped, 1 ignored on purpose (95% mapped)

## Rules

- The betterleaks format is the gitleaks parser under the betterleaks tool name; Detect names the shared shape gitleaks, so choose betterleaks with Options.Format.
- One secret finding per record, filed on Options.Repository, else Options.DefaultAsset, else an unclassified asset named after the tool (with an issue).
- The raw secret never reaches the report: secret.masked_value, the snippet, the title and the commit message hold it masked with ctis.MaskSecretMatch (the masking FromSARIF uses), and the fingerprint input is the masked value (CTIS spec 5.2).
- Severity is inferred from the rule id (the report has none): cloud credentials, private keys and personal access tokens are critical, anything else high.
- The commit author and e-mail are kept: they say who committed the secret, which is who must rotate it.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/[]` | `findings[]` |  |
| `/[]/RuleID` | `findings[].rule_id, native.vuln_id, severity, secret.secret_type, secret.service` |  |
| `/[]/Description` | `findings[].title, message` |  |
| `/[]/File` | `findings[].location.path` |  |
| `/[]/SymlinkFile` | `findings[].source_extra.symlink_file` |  |
| `/[]/StartLine` | `findings[].location.start_line` |  |
| `/[]/EndLine` | `findings[].location.end_line` |  |
| `/[]/StartColumn` | `findings[].location.start_column` |  |
| `/[]/EndColumn` | `findings[].location.end_column` |  |
| `/[]/Match` | `findings[].location.snippet (masked)` |  |
| `/[]/Secret` | `findings[].secret.masked_value, secret.length, fingerprint input (masked)` |  |
| `/[]/Line` |  | the whole source line holding the secret; the masked match is kept |
| `/[]/Entropy` | `findings[].secret.entropy` |  |
| `/[]/Commit` | `findings[].location.commit_sha` |  |
| `/[]/Link` | `findings[].source_extra.commit_link` |  |
| `/[]/Author` | `findings[].author` |  |
| `/[]/Email` | `findings[].author_email` |  |
| `/[]/Date` | `findings[].commit_date` |  |
| `/[]/Message` | `findings[].source_extra.commit_message (secret masked)` |  |
| `/[]/Tags` | (container) |  |
| `/[]/Tags[]` | `findings[].tags` |  |
| `/[]/Fingerprint` | `findings[].fingerprint (when it does not hold the secret)` |  |
