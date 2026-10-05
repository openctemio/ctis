# DefectDojo Generic Findings Import JSON mapping

Generated from `importer/spec_defectdojo.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `defectdojo`
- Source versions: the Generic Findings Import JSON of DefectDojo 2.x (scan type "Generic Findings Import")
- Fields: 65 mapped, 8 ignored on purpose (89% mapped)

## Rules

- One finding per record and endpoint host; a record without endpoints is one finding on Options.DefaultAsset, else on an unclassified asset named after the tool (`<tool-name-slug>-import`).
- Endpoint hosts become domain or ip_address assets (id `host-<host>`); the endpoint port, protocol and URL go to the finding's network location and source_extra.endpoint.
- Severity: the label (Critical, High, Medium, Low, Info) through ctis.NormalizeNativeSeverity; native.severity keeps it.
- Status: the flags, in the order false_p, risk_accepted, out_of_scope, duplicate, is_mitigated, active=false (inactive), verified, active, give native.status; ctis.NormalizeNativeStatus maps it to the finding status and source state.
- vuln_id_from_tool is rule_id and native.vuln_id; unique_id_from_tool is native.instance_id. No fingerprint is set: the receiver keys findings.
- Values that are numbers or booleans in some exports and strings in others are read either way. A record that cannot be decoded is skipped with an issue at its line.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/name` | `tool.name` |  |
| `/type` | `metadata.properties.scan_type` |  |
| `/version` | `tool.version` |  |
| `/description` | `metadata.properties.description` |  |
| `/findings` | (container) |  |
| `/findings[]` | `findings[]` |  |
| `/findings[]/title` | `findings[].title, rule_name` |  |
| `/findings[]/description` | `findings[].description` |  |
| `/findings[]/severity` | `findings[].severity, native.severity` |  |
| `/findings[]/numerical_severity` |  | derived from severity (S0-S4) |
| `/findings[]/severity_justification` | `findings[].source_extra.severity_justification` |  |
| `/findings[]/mitigation` | `findings[].remediation.recommendation` |  |
| `/findings[]/impact` | `findings[].source_extra.impact` |  |
| `/findings[]/references` | `findings[].references (the URLs), source_extra.references (the text)` |  |
| `/findings[]/steps_to_reproduce` | `findings[].source_extra.steps_to_reproduce` |  |
| `/findings[]/date` | `findings[].first_seen_at, source_lifecycle.first_found` |  |
| `/findings[]/publish_date` | `findings[].vulnerability.published_at` |  |
| `/findings[]/cve` | `findings[].vulnerability.cve_id, cve_ids, ids[]` |  |
| `/findings[]/cwe` | `findings[].vulnerability.cwe_id, cwe_ids` |  |
| `/findings[]/vulnerability_ids` | (container) |  |
| `/findings[]/vulnerability_ids[]` | (container) |  |
| `/findings[]/vulnerability_ids[]/vulnerability_id` | `findings[].vulnerability.ids[] (cve, ghsa, osv or vendor)` |  |
| `/findings[]/cvssv3` | `findings[].scores[] (cvss 3.x vector), vulnerability.cvss_vector` |  |
| `/findings[]/cvssv3_score` | `findings[].scores[].value, vulnerability.cvss_score` |  |
| `/findings[]/cvssv4` | `findings[].scores[] (cvss 4.0 vector)` |  |
| `/findings[]/cvssv4_score` | `findings[].scores[].value (cvss 4.0)` |  |
| `/findings[]/epss_score` | `findings[].scores[] (epss), vulnerability.epss_score` |  |
| `/findings[]/epss_percentile` | `findings[].scores[] (epss_percentile), vulnerability.epss_percentile` |  |
| `/findings[]/known_exploited` | `findings[].vulnerability.in_cisa_kev, exploit_available` |  |
| `/findings[]/ransomware_used` | `findings[].source_extra.ransomware_used` |  |
| `/findings[]/kev_date` | `findings[].source_extra.kev_date` |  |
| `/findings[]/active` | `findings[].native.status, status, source_lifecycle.state` |  |
| `/findings[]/verified` | `findings[].native.status, native.detection_type confirmed` |  |
| `/findings[]/false_p` | `findings[].native.status, status false_positive` |  |
| `/findings[]/duplicate` | `findings[].native.status, status suppressed` |  |
| `/findings[]/out_of_scope` | `findings[].native.status, status suppressed` |  |
| `/findings[]/risk_accepted` | `findings[].native.status, status accepted_risk` |  |
| `/findings[]/is_mitigated` | `findings[].native.status, status resolved, source_lifecycle.state fixed` |  |
| `/findings[]/mitigated` | `findings[].source_lifecycle.last_fixed, source_extra.mitigated` |  |
| `/findings[]/under_review` | `findings[].source_extra.under_review` |  |
| `/findings[]/file_path` | `findings[].location.path` |  |
| `/findings[]/line` | `findings[].location.start_line` |  |
| `/findings[]/sast_source_object` | `findings[].source_extra.sast_source_object` |  |
| `/findings[]/sast_sink_object` | `findings[].source_extra.sast_sink_object` |  |
| `/findings[]/sast_source_line` | `findings[].source_extra.sast_source_line` |  |
| `/findings[]/sast_source_file_path` | `findings[].source_extra.sast_source_file_path` |  |
| `/findings[]/component_name` | `findings[].vulnerability.package` |  |
| `/findings[]/component_version` | `findings[].vulnerability.affected_version` |  |
| `/findings[]/fix_available` | `findings[].remediation.fix_available` |  |
| `/findings[]/fix_version` | `findings[].vulnerability.fixed_version, remediation.fix_available` |  |
| `/findings[]/vuln_id_from_tool` | `findings[].rule_id, native.vuln_id` |  |
| `/findings[]/unique_id_from_tool` | `findings[].native.instance_id` |  |
| `/findings[]/endpoints` | (container) |  |
| `/findings[]/endpoints[]` | `assets[] (the host), findings[].network, source_extra.endpoint (a URL string is read too)` |  |
| `/findings[]/endpoints[]/protocol` | `findings[].network.service, source_extra.endpoint` |  |
| `/findings[]/endpoints[]/host` | `assets[].value, findings[].network.host` |  |
| `/findings[]/endpoints[]/port` | `findings[].network.port` |  |
| `/findings[]/endpoints[]/path` | `findings[].source_extra.endpoint` |  |
| `/findings[]/endpoints[]/query` | `findings[].source_extra.endpoint` |  |
| `/findings[]/endpoints[]/fragment` | `findings[].source_extra.endpoint` |  |
| `/findings[]/endpoints[]/userinfo` |  | credentials of the endpoint URL |
| `/findings[]/tags` | (container) |  |
| `/findings[]/tags[]` | `findings[].tags` |  |
| `/findings[]/service` | `findings[].source_extra.service` |  |
| `/findings[]/planned_remediation_date` | `findings[].source_extra.planned_remediation_date` |  |
| `/findings[]/planned_remediation_version` | `findings[].source_extra.planned_remediation_version` |  |
| `/findings[]/effort_for_fixing` | `findings[].remediation.effort` |  |
| `/findings[]/static_finding` | `findings[].source_extra.static_finding` |  |
| `/findings[]/dynamic_finding` | `findings[].source_extra.dynamic_finding` |  |
| `/findings[]/payload` | `findings[].evidence` |  |
| `/findings[]/param` | `findings[].source_extra.param` |  |
| `/findings[]/nb_occurences` | `findings[].occurrence_count` |  |
| `/findings[]/hash_code` |  | DefectDojo's own deduplication hash; the receiver keys findings itself |
| `/findings[]/files` |  | attached files (base64 data); not imported |
| `/findings[]/files[]` |  | attached files (base64 data); not imported |
| `/findings[]/files[]/**` |  | attached files (base64 data); not imported |
| `/findings[]/reporter` |  | the DefectDojo user who reported it (personal data) |
| `/findings[]/mitigated_by` |  | the DefectDojo user who mitigated it (personal data) |
