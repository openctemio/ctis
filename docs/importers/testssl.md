# testssl.sh JSON mapping

Generated from `importer/spec_testssl.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `testssl`
- Source versions: testssl.sh 3.x --jsonfile (flat array) and --jsonfile-pretty
- Fields: 22 mapped, 7 ignored on purpose (76% mapped)

## Rules

- Each endpoint is a service asset name:port/tcp (the address when there is no name), with TLS set; its name is a domain_name that resolves_to its address. The endpoint is an asset even when every check passed.
- Severity: LOW, MEDIUM, HIGH and CRITICAL become low, medium, high and critical findings. OK, INFO and DEBUG checks passed or only inform: they are counted in one issue, never findings. WARN and FATAL are problems of the scan: one issue each.
- Scores, grades and scan statistics (overall_grade, final_score, grade_cap_*, the *_score ids, scanTime, scanProblem) sum up other checks and are not findings.
- The same check on the same name and port seen on several addresses is one finding with occurrence_count.
- The title is "TLS check <id>: <finding>" cut to 120 characters of the finding; the identity of a finding is its check id on its service.
- Every host-bearing asset carries extensions[io.openctem].import_scope relative to Options.ScopeDomains; the receiver judges scope.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/[]/ip` | `assets[]: name/address of the endpoint` |  |
| `/[]/port` | `service port, findings[].network.port` |  |
| `/Invocation` |  | the command line |
| `/at` |  | where testssl.sh ran |
| `/version` | `tool.version` |  |
| `/openssl` |  | the OpenSSL testssl.sh used |
| `/startTime` |  | run start |
| `/scanTime` |  | run duration |
| `/scanResult` | (container) |  |
| `/scanResult[]` | `one endpoint` |  |
| `/scanResult[]/targetHost` | `assets[] (domain_name)` |  |
| `/scanResult[]/ip` | `assets[] (ip_address)` |  |
| `/scanResult[]/port` | `service port, findings[].network.port` |  |
| `/scanResult[]/rDNS` |  | the reverse name, the address owner's choice |
| `/scanResult[]/service` |  | the protocol testssl.sh spoke (HTTP, SMTP, ...) |
| `/scanResult[]/*` | `a section of checks (pretest, protocols, ciphers, vulnerabilities, rating, ...)` |  |
| `/[]` | `findings[] (severity LOW and above)` |  |
| `/[]/id` | `findings[].rule_id, native.vuln_id, title` |  |
| `/[]/severity` | `findings[].severity, native.severity` |  |
| `/[]/finding` | `findings[].message, title` |  |
| `/[]/cve` | `findings[].vulnerability.ids (space-separated); a check with a CVE is a vulnerability, else a misconfiguration` |  |
| `/[]/cwe` | `findings[].vulnerability.cwe_ids` |  |
| `/[]/hint` | `findings[].remediation.recommendation` |  |
| `/scanResult[]/*[]` | `findings[] (severity LOW and above)` |  |
| `/scanResult[]/*[]/id` | `findings[].rule_id, native.vuln_id, title` |  |
| `/scanResult[]/*[]/severity` | `findings[].severity, native.severity` |  |
| `/scanResult[]/*[]/finding` | `findings[].message, title` |  |
| `/scanResult[]/*[]/cve` | `findings[].vulnerability.ids (space-separated); a check with a CVE is a vulnerability, else a misconfiguration` |  |
| `/scanResult[]/*[]/cwe` | `findings[].vulnerability.cwe_ids` |  |
| `/scanResult[]/*[]/hint` | `findings[].remediation.recommendation` |  |
