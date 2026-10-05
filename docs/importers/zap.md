# ZAP traditional report (JSON and XML) mapping

Generated from `importer/spec_zap.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `zap`
- Source versions: the traditional JSON and XML reports of ZAP 2.12-2.16
- Fields: 64 mapped, 29 ignored on purpose (69% mapped)

## Rules

- The JSON and XML forms are one format; the first character of the file decides which parser reads it. The paths below list both forms.
- One website asset per site, named by its origin (scheme, host and port; no path, query or user info). One finding per alert per site, on the site's host and port.
- Severity: riskcode 0 info, 1 low, 2 medium, 3 high; native.severity keeps it. Confidence 1, 2, 3, 4 become 30, 60, 90, 100; 0 (marked a false positive in ZAP) sets status false_positive.
- Each instance (method, URI, parameter, attack, evidence) becomes a line of evidence, at most 20 per alert; the attack string is kept as text, never as markup.
- Request and response headers and bodies, which hold cookies, authorization headers and session tokens, are never read.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/@programName` |  | always ZAP; the tool is named by the format |
| `/@version` | `tool.version` |  |
| `/@generated` | `metadata.properties.generated (when no created)` |  |
| `/created` | `metadata.properties.generated` |  |
| `/insights` |  | scan statistics (counts and timings) |
| `/insights[]` |  | scan statistics (counts and timings) |
| `/insights[]/**` |  | scan statistics (counts and timings) |
| `/site` | (container) |  |
| `/site[]` | `assets[]` |  |
| `/site[]/@name` | `assets[].value (the origin)` |  |
| `/site[]/@host` | `assets[].properties.host, findings[].network.host` |  |
| `/site[]/@port` | `assets[].properties.port, findings[].network.port` |  |
| `/site[]/@ssl` | `assets[].properties.scheme` |  |
| `/site[]/alerts` | (container) |  |
| `/site[]/alerts[]` | `findings[]` |  |
| `/site[]/alerts[]/pluginid` | `findings[].rule_id, native.vuln_id` |  |
| `/site[]/alerts[]/alertRef` | `findings[].native.instance_id` |  |
| `/site[]/alerts[]/alert` | `findings[].title, rule_name` |  |
| `/site[]/alerts[]/name` | `findings[].title (when no alert)` |  |
| `/site[]/alerts[]/riskcode` | `findings[].severity, native.severity` |  |
| `/site[]/alerts[]/confidence` | `findings[].confidence, status (0 is a false positive), native.detection_type (4 confirmed), source_extra.confidence` |  |
| `/site[]/alerts[]/riskdesc` |  | riskcode and confidence as words |
| `/site[]/alerts[]/confidencedesc` |  | confidence as a word |
| `/site[]/alerts[]/desc` | `findings[].description (HTML reduced to text)` |  |
| `/site[]/alerts[]/count` | `findings[].occurrence_count` |  |
| `/site[]/alerts[]/systemic` | `findings[].source_extra.systemic` |  |
| `/site[]/alerts[]/solution` | `findings[].remediation.recommendation (HTML reduced to text)` |  |
| `/site[]/alerts[]/otherinfo` | `findings[].source_extra.otherinfo (HTML reduced to text)` |  |
| `/site[]/alerts[]/reference` | `findings[].references (the http(s) URLs)` |  |
| `/site[]/alerts[]/cweid` | `findings[].vulnerability.cwe_id, cwe_ids` |  |
| `/site[]/alerts[]/wascid` | `findings[].source_extra.wascid` |  |
| `/site[]/alerts[]/sourceid` | `findings[].source_extra.sourceid` |  |
| `/site[]/alerts[]/instances` | (container) |  |
| `/site[]/alerts[]/instances[]` | `findings[].evidence (one line per instance, at most 20, the rest counted)` |  |
| `/site[]/alerts[]/instances[]/uri` | `findings[].evidence (user info removed)` |  |
| `/site[]/alerts[]/instances[]/method` | `findings[].evidence` |  |
| `/site[]/alerts[]/instances[]/param` | `findings[].evidence` |  |
| `/site[]/alerts[]/instances[]/attack` | `findings[].evidence (text)` |  |
| `/site[]/alerts[]/instances[]/evidence` | `findings[].evidence (text)` |  |
| `/site[]/alerts[]/instances[]/otherinfo` | `findings[].evidence` |  |
| `/site[]/alerts[]/instances[]/id` |  | ZAP-internal instance number |
| `/site[]/alerts[]/instances[]/nodeName` |  | the site tree node; the URI is kept |
| `/site[]/alerts[]/instances[]/request-header` |  | request headers hold cookies and authorization headers |
| `/site[]/alerts[]/instances[]/request-body` |  | request bodies hold credentials and personal data |
| `/site[]/alerts[]/instances[]/response-header` |  | response headers hold session cookies |
| `/site[]/alerts[]/instances[]/response-body` |  | response bodies hold personal data |
| `/site[]/alerts[]/instances[]/requestheader` |  | request headers hold cookies and authorization headers |
| `/site[]/alerts[]/instances[]/requestbody` |  | request bodies hold credentials and personal data |
| `/site[]/alerts[]/instances[]/responseheader` |  | response headers hold session cookies |
| `/site[]/alerts[]/instances[]/responsebody` |  | response bodies hold personal data |
| `/site[]/alerts[]/tags` | (container) |  |
| `/site[]/alerts[]/tags/*` | `findings[].tags (the name), references (the link)` |  |
| `/OWASPZAPReport` | (container) |  |
| `/OWASPZAPReport/@programName` |  | always ZAP; the tool is named by the format |
| `/OWASPZAPReport/@version` | `tool.version` |  |
| `/OWASPZAPReport/@generated` | `metadata.properties.generated` |  |
| `/OWASPZAPReport/site` | `assets[]` |  |
| `/OWASPZAPReport/site/@name` | `assets[].value (the origin)` |  |
| `/OWASPZAPReport/site/@host` | `assets[].properties.host, findings[].network.host` |  |
| `/OWASPZAPReport/site/@port` | `assets[].properties.port, findings[].network.port` |  |
| `/OWASPZAPReport/site/@ssl` | `assets[].properties.scheme` |  |
| `/OWASPZAPReport/site/alerts` | (container) |  |
| `/OWASPZAPReport/site/alerts/alertitem` | `findings[]` |  |
| `/OWASPZAPReport/site/alerts/alertitem/pluginid` | `findings[].rule_id, native.vuln_id` |  |
| `/OWASPZAPReport/site/alerts/alertitem/alertRef` | `findings[].native.instance_id` |  |
| `/OWASPZAPReport/site/alerts/alertitem/alert` | `findings[].title, rule_name` |  |
| `/OWASPZAPReport/site/alerts/alertitem/name` | `findings[].title (when no alert)` |  |
| `/OWASPZAPReport/site/alerts/alertitem/riskcode` | `findings[].severity, native.severity` |  |
| `/OWASPZAPReport/site/alerts/alertitem/confidence` | `findings[].confidence, status (0 is a false positive), native.detection_type (4 confirmed), source_extra.confidence` |  |
| `/OWASPZAPReport/site/alerts/alertitem/riskdesc` |  | riskcode and confidence as words |
| `/OWASPZAPReport/site/alerts/alertitem/confidencedesc` |  | confidence as a word |
| `/OWASPZAPReport/site/alerts/alertitem/desc` | `findings[].description (HTML reduced to text)` |  |
| `/OWASPZAPReport/site/alerts/alertitem/count` | `findings[].occurrence_count` |  |
| `/OWASPZAPReport/site/alerts/alertitem/systemic` | `findings[].source_extra.systemic` |  |
| `/OWASPZAPReport/site/alerts/alertitem/solution` | `findings[].remediation.recommendation (HTML reduced to text)` |  |
| `/OWASPZAPReport/site/alerts/alertitem/otherinfo` | `findings[].source_extra.otherinfo (HTML reduced to text)` |  |
| `/OWASPZAPReport/site/alerts/alertitem/reference` | `findings[].references (the http(s) URLs)` |  |
| `/OWASPZAPReport/site/alerts/alertitem/cweid` | `findings[].vulnerability.cwe_id, cwe_ids` |  |
| `/OWASPZAPReport/site/alerts/alertitem/wascid` | `findings[].source_extra.wascid` |  |
| `/OWASPZAPReport/site/alerts/alertitem/sourceid` | `findings[].source_extra.sourceid` |  |
| `/OWASPZAPReport/site/alerts/alertitem/instances` | (container) |  |
| `/OWASPZAPReport/site/alerts/alertitem/instances/instance` | `findings[].evidence (one line per instance, at most 20, the rest counted)` |  |
| `/OWASPZAPReport/site/alerts/alertitem/instances/instance/uri` | `findings[].evidence (user info removed)` |  |
| `/OWASPZAPReport/site/alerts/alertitem/instances/instance/method` | `findings[].evidence` |  |
| `/OWASPZAPReport/site/alerts/alertitem/instances/instance/param` | `findings[].evidence` |  |
| `/OWASPZAPReport/site/alerts/alertitem/instances/instance/attack` | `findings[].evidence (text)` |  |
| `/OWASPZAPReport/site/alerts/alertitem/instances/instance/evidence` | `findings[].evidence (text)` |  |
| `/OWASPZAPReport/site/alerts/alertitem/instances/instance/otherinfo` | `findings[].evidence` |  |
| `/OWASPZAPReport/site/alerts/alertitem/instances/instance/id` |  | ZAP-internal instance number |
| `/OWASPZAPReport/site/alerts/alertitem/instances/instance/nodeName` |  | the site tree node; the URI is kept |
| `/OWASPZAPReport/site/alerts/alertitem/instances/instance/request-header` |  | request headers hold cookies and authorization headers |
| `/OWASPZAPReport/site/alerts/alertitem/instances/instance/request-body` |  | request bodies hold credentials and personal data |
| `/OWASPZAPReport/site/alerts/alertitem/instances/instance/response-header` |  | response headers hold session cookies |
| `/OWASPZAPReport/site/alerts/alertitem/instances/instance/response-body` |  | response bodies hold personal data |
| `/OWASPZAPReport/site/alerts/alertitem/instances/instance/requestheader` |  | request headers hold cookies and authorization headers |
| `/OWASPZAPReport/site/alerts/alertitem/instances/instance/requestbody` |  | request bodies hold credentials and personal data |
| `/OWASPZAPReport/site/alerts/alertitem/instances/instance/responseheader` |  | response headers hold session cookies |
| `/OWASPZAPReport/site/alerts/alertitem/instances/instance/responsebody` |  | response bodies hold personal data |
| `/OWASPZAPReport/site/alerts/alertitem/tags` | (container) |  |
| `/OWASPZAPReport/site/alerts/alertitem/tags/tag` | (container) |  |
| `/OWASPZAPReport/site/alerts/alertitem/tags/tag/tag` | `findings[].tags` |  |
| `/OWASPZAPReport/site/alerts/alertitem/tags/tag/link` | `findings[].references` |  |
