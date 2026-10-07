# SARIF 2.1.0 mapping

Generated from `importer/spec_sarif.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `sarif`
- Source versions: SARIF 2.1.0 (OASIS) as written by CodeQL, semgrep, trivy, gitleaks, betterleaks and other static analysis tools
- Fields: 69 mapped, 33 ignored on purpose (68% mapped)

## Rules

- The conversion is the module's FromSARIF (sarif.go); the importer adds the input limits and chooses the asset.
- Asset: Options.Repository (a receiver sets it from a verified identity); else the first repository a run names in versionControlProvenance (repositoryUri without user info, branch, revisionId); else Options.DefaultAsset or an unclassified asset named after the tool, with an issue.
- Severity: the security-severity score (result, then rule), else the result level, else the rule's default level, else medium. Type: the rule's tags, a CVE/GHSA rule id, else the tool name. Options.ToolType (sast, sca, secret, iac, web3), when set, decides the type and the tool capabilities instead.
- A secret scanner's region snippet is masked (ctis.MaskSecretMatch), and the raw value and each secret-looking word of it are masked in every other field: title, description, message, properties, tags and fingerprints.
- Fingerprint: the result's fingerprints entry with the lowest key (hashed above 64 characters); partialFingerprints pass through.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/$schema` | (container) |  |
| `/version` | `format check (only 2.1.0 is read)` |  |
| `/runs` | (container) |  |
| `/runs[]` | (container) |  |
| `/runs[]/tool` | (container) |  |
| `/runs[]/tool/driver` | (container) |  |
| `/runs[]/tool/driver/name` | `tool.name, findings[].properties.sarif_tool (several runs)` |  |
| `/runs[]/tool/driver/version` | `tool.version` |  |
| `/runs[]/tool/driver/semanticVersion` | `tool.version (when no version)` |  |
| `/runs[]/tool/driver/informationUri` | `tool.info_url` |  |
| `/runs[]/tool/driver/fullName` |  | display name; name is kept |
| `/runs[]/tool/driver/organization` |  | the tool vendor's name; not a finding property |
| `/runs[]/tool/driver/rules` | (container) |  |
| `/runs[]/tool/driver/rules[]` | `the rule of each result` |  |
| `/runs[]/tool/driver/rules[]/id` | `findings[].rule_id (rule lookup)` |  |
| `/runs[]/tool/driver/rules[]/name` | `findings[].rule_name` |  |
| `/runs[]/tool/driver/rules[]/shortDescription` | (container) |  |
| `/runs[]/tool/driver/rules[]/shortDescription/text` | `findings[].description, title (when the result has no message)` |  |
| `/runs[]/tool/driver/rules[]/fullDescription` |  | long rule text; the short description is kept |
| `/runs[]/tool/driver/rules[]/fullDescription/text` |  | long rule text; the short description is kept |
| `/runs[]/tool/driver/rules[]/help` |  | rule help text (documentation of the check, same for every finding) |
| `/runs[]/tool/driver/rules[]/help/**` |  | rule help text (documentation of the check, same for every finding) |
| `/runs[]/tool/driver/rules[]/helpUri` | `findings[].references` |  |
| `/runs[]/tool/driver/rules[]/defaultConfiguration` | (container) |  |
| `/runs[]/tool/driver/rules[]/defaultConfiguration/level` | `findings[].severity (when the result has no level)` |  |
| `/runs[]/tool/driver/rules[]/defaultConfiguration/enabled` |  | tool configuration |
| `/runs[]/tool/driver/rules[]/properties` | (container) |  |
| `/runs[]/tool/driver/rules[]/properties/tags` | `findings[].tags, type, vulnerability.cwe_ids, owasp_ids` |  |
| `/runs[]/tool/driver/rules[]/properties/tags[]` | `findings[].tags, type, vulnerability.cwe_ids, owasp_ids` |  |
| `/runs[]/tool/driver/rules[]/properties/precision` | `findings[].confidence` |  |
| `/runs[]/tool/driver/rules[]/properties/security-severity` | `findings[].severity` |  |
| `/runs[]/tool/driver/rules[]/properties/cwe` | `findings[].vulnerability.cwe_ids` |  |
| `/runs[]/tool/driver/rules[]/properties/cwe[]` | `findings[].vulnerability.cwe_ids` |  |
| `/runs[]/tool/driver/rules[]/properties/owasp` | `findings[].vulnerability.owasp_ids` |  |
| `/runs[]/tool/driver/rules[]/properties/owasp[]` | `findings[].vulnerability.owasp_ids` |  |
| `/runs[]/tool/driver/rules[]/properties/*` |  | other rule properties (CodeQL id, kind, name, description, problem.severity): duplicates of rule members or tool internals |
| `/runs[]/results` | (container) |  |
| `/runs[]/results[]` | `findings[]` |  |
| `/runs[]/results[]/ruleId` | `findings[].rule_id` |  |
| `/runs[]/results[]/ruleIndex` | `rule lookup` |  |
| `/runs[]/results[]/rule` | (container) |  |
| `/runs[]/results[]/rule/id` | `findings[].rule_id (when no ruleId)` |  |
| `/runs[]/results[]/rule/index` | `rule lookup` |  |
| `/runs[]/results[]/level` | `findings[].severity` |  |
| `/runs[]/results[]/kind` | `findings[].kind` |  |
| `/runs[]/results[]/baselineState` | `findings[].baseline_state` |  |
| `/runs[]/results[]/message` | (container) |  |
| `/runs[]/results[]/message/text` | `findings[].title (secrets masked)` |  |
| `/runs[]/results[]/locations` | (container) |  |
| `/runs[]/results[]/locations[]` | `findings[].location (the first location)` |  |
| `/runs[]/results[]/locations[]/physicalLocation` | (container) |  |
| `/runs[]/results[]/locations[]/physicalLocation/artifactLocation` | (container) |  |
| `/runs[]/results[]/locations[]/physicalLocation/artifactLocation/uri` | `findings[].location.path` |  |
| `/runs[]/results[]/locations[]/physicalLocation/artifactLocation/uriBaseId` |  | base of a relative uri on the scanning machine; the relative path is kept |
| `/runs[]/results[]/locations[]/physicalLocation/artifactLocation/index` |  | index into run.artifacts; the uri is kept |
| `/runs[]/results[]/locations[]/physicalLocation/region` | (container) |  |
| `/runs[]/results[]/locations[]/physicalLocation/region/startLine` | `findings[].location.start_line` |  |
| `/runs[]/results[]/locations[]/physicalLocation/region/endLine` | `findings[].location.end_line` |  |
| `/runs[]/results[]/locations[]/physicalLocation/region/startColumn` | `findings[].location.start_column` |  |
| `/runs[]/results[]/locations[]/physicalLocation/region/endColumn` | `findings[].location.end_column` |  |
| `/runs[]/results[]/locations[]/physicalLocation/region/snippet` | (container) |  |
| `/runs[]/results[]/locations[]/physicalLocation/region/snippet/text` | `findings[].location.snippet (masked for secret scanners)` |  |
| `/runs[]/results[]/locations[]/logicalLocations` | (container) |  |
| `/runs[]/results[]/locations[]/logicalLocations[]` | (container) |  |
| `/runs[]/results[]/locations[]/logicalLocations[]/name` | `findings[].location.logical_location.name` |  |
| `/runs[]/results[]/locations[]/logicalLocations[]/fullyQualifiedName` | `findings[].location.logical_location.fully_qualified_name` |  |
| `/runs[]/results[]/locations[]/logicalLocations[]/kind` | `findings[].location.logical_location.kind` |  |
| `/runs[]/results[]/fingerprints` | (container) |  |
| `/runs[]/results[]/fingerprints/*` | `findings[].fingerprint (the lowest key)` |  |
| `/runs[]/results[]/partialFingerprints` | (container) |  |
| `/runs[]/results[]/partialFingerprints/*` | `findings[].partial_fingerprints` |  |
| `/runs[]/results[]/correlationGuid` | `findings[].correlation_id` |  |
| `/runs[]/results[]/suppressions` | (container) |  |
| `/runs[]/results[]/suppressions[]` | `findings[].suppression, status` |  |
| `/runs[]/results[]/suppressions[]/kind` | `findings[].suppression.kind` |  |
| `/runs[]/results[]/suppressions[]/status` | `findings[].suppression.status, status` |  |
| `/runs[]/results[]/suppressions[]/justification` | `findings[].suppression.justification` |  |
| `/runs[]/results[]/webRequest` | `findings[].evidence_items[http_exchange].http.request (capped, sensitive values marked)` |  |
| `/runs[]/results[]/webRequest/protocol` | `findings[].evidence_items[].http.request.http_version` |  |
| `/runs[]/results[]/webRequest/version` | `findings[].evidence_items[].http.request.http_version` |  |
| `/runs[]/results[]/webRequest/target` | `findings[].evidence_items[].http.request.url` |  |
| `/runs[]/results[]/webRequest/method` | `findings[].evidence_items[].http.request.method` |  |
| `/runs[]/results[]/webRequest/headers` | (container) |  |
| `/runs[]/results[]/webRequest/headers/*` | `findings[].evidence_items[].http.request.headers[] (Authorization, Cookie and API-key values marked sensitive)` |  |
| `/runs[]/results[]/webRequest/body` | (container) |  |
| `/runs[]/results[]/webRequest/body/text` | `findings[].evidence_items[].http.request.body` |  |
| `/runs[]/results[]/webRequest/body/binary` | `findings[].evidence_items[].http.request.body (base64)` |  |
| `/runs[]/results[]/webRequest/index` |  | index into run.webRequests; the inline object is kept |
| `/runs[]/results[]/webRequest/parameters` |  | the request's parameters; the target URL and body hold them |
| `/runs[]/results[]/webRequest/parameters/*` |  | the request's parameters; the target URL and body hold them |
| `/runs[]/results[]/webResponse` | `findings[].evidence_items[http_exchange].http.response (capped, sensitive values marked)` |  |
| `/runs[]/results[]/webResponse/protocol` | `findings[].evidence_items[].http.response.http_version` |  |
| `/runs[]/results[]/webResponse/version` | `findings[].evidence_items[].http.response.http_version` |  |
| `/runs[]/results[]/webResponse/statusCode` | `findings[].evidence_items[].http.response.status` |  |
| `/runs[]/results[]/webResponse/reasonPhrase` | `findings[].evidence_items[].http.response.reason` |  |
| `/runs[]/results[]/webResponse/headers` | (container) |  |
| `/runs[]/results[]/webResponse/headers/*` | `findings[].evidence_items[].http.response.headers[] (Set-Cookie values marked sensitive)` |  |
| `/runs[]/results[]/webResponse/body` | (container) |  |
| `/runs[]/results[]/webResponse/body/text` | `findings[].evidence_items[].http.response.body` |  |
| `/runs[]/results[]/webResponse/body/binary` | `findings[].evidence_items[].http.response.body (base64)` |  |
| `/runs[]/results[]/webResponse/noResponseReceived` | `findings[].evidence_items[].http.response (left out when true)` |  |
| `/runs[]/results[]/webResponse/index` |  | index into run.webResponses; the inline object is kept |
| `/runs[]/results[]/properties` | (container) |  |
| `/runs[]/results[]/properties/tags` | `findings[].tags` |  |
| `/runs[]/results[]/properties/tags[]` | `findings[].tags` |  |
| `/runs[]/results[]/properties/tags[]/**` |  | a tag that is not a string |
| `/runs[]/results[]/properties/security-severity` | `findings[].severity` |  |
| `/runs[]/results[]/properties/*` |  | other result properties (tool specific) |
| `/runs[]/results[]/codeFlows` |  | taint paths; the result's location is kept |
| `/runs[]/results[]/codeFlows[]/**` |  | taint paths; the result's location is kept |
| `/runs[]/results[]/relatedLocations` |  | secondary locations; the primary location is kept |
| `/runs[]/results[]/relatedLocations[]/**` |  | secondary locations; the primary location is kept |
| `/runs[]/versionControlProvenance` | (container) |  |
| `/runs[]/versionControlProvenance[]` | `assets[] (when no repository is given)` |  |
| `/runs[]/versionControlProvenance[]/repositoryUri` | `assets[].value (user info removed)` |  |
| `/runs[]/versionControlProvenance[]/revisionId` | `assets[].properties.commit_sha` |  |
| `/runs[]/versionControlProvenance[]/branch` | `assets[].properties.branch` |  |
| `/runs[]/invocations` |  | how the tool ran (command line, environment, exit code): scan operation details, may hold paths and arguments of the build machine |
| `/runs[]/invocations[]/**` |  | how the tool ran: scan operation details |
| `/runs[]/artifacts` |  | the files the tool read; findings name their own file |
| `/runs[]/artifacts[]/**` |  | the files the tool read; findings name their own file |
| `/runs[]/originalUriBaseIds` |  | root paths of the scanning machine |
| `/runs[]/originalUriBaseIds/**` |  | root paths of the scanning machine |
| `/runs[]/columnKind` |  | column unit (UTF-16 or Unicode code points) |
| `/runs[]/automationDetails` |  | run category of a code-scanning upload |
| `/runs[]/automationDetails/**` |  | run category of a code-scanning upload |
| `/runs[]/properties` |  | run properties (tool specific) |
| `/runs[]/properties/**` |  | run properties (tool specific) |
| `/runs[]/tool/extensions` |  | tool plug-ins and query packs |
| `/runs[]/tool/extensions/**` |  | tool plug-ins and query packs |
