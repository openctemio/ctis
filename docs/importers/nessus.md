# Nessus v2 XML (.nessus) mapping

Generated from `importer/spec_nessus.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `nessus`
- Source versions: NessusClientData_v2 as written by Nessus 10.x and Tenable.sc 6.x
- Fields: 128 mapped, 40 ignored on purpose (76% mapped)

## Rules

- One asset per ReportHost: value is host-fqdn, else host-ip, else the ReportHost name; type ip_address when the value is an IP address, else host. Asset id `host-<value>`.
- One finding per ReportItem: type vulnerability, or compliance when the item carries compliance-check-name.
- Severity: the severity attribute (0-4) through ctis.NormalizeNativeSeverity (0 info, 1 low, 2 medium, 3 high, 4 critical); risk_factor when the attribute is unusable. native.severity keeps the attribute; severity 0 sets native.detection_type info.
- Every CVSS version goes to finding.scores with source tenable. The legacy vulnerability.cvss_* members take the first of v3, v4, v2, with cvss_source vendor.
- plugin_output and compliance-actual-value go to evidence after credential redaction: account lines (User:, Login:, Account:), `as '<account>'`, and password, secret, token, API key and community values become [redacted].
- The Policy element (server and plugin preferences, which hold scan credentials and account names) is skipped whole, and smb-login-used, ssh-login-used and compliance-uname are never read.
- Values are cleaned of control characters and cut to the CTIS receiver caps (title 500, description 32 KiB, evidence 64 KiB, remediation 16 KiB).

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/NessusClientData_v2` | (container) |  |
| `/NessusClientData_v2/Policy` |  | scan policy: preferences hold credentials and account names |
| `/NessusClientData_v2/Policy/**` |  | scan policy: preferences hold credentials and account names |
| `/NessusClientData_v2/Report` | (container) |  |
| `/NessusClientData_v2/Report/@name` | `metadata.properties.scan_name` |  |
| `/NessusClientData_v2/Report/ReportHost` | `assets[]` |  |
| `/NessusClientData_v2/Report/ReportHost/@name` | `assets[].value (when no host-fqdn or host-ip)` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties` | (container) |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[*]/@name` | (container) |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[host-ip]` | `assets[].value, assets[].properties.ip_address` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[host-fqdn]` | `assets[].value, assets[].identity_hints.fqdn, assets[].properties.fqdn` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[host-rdns]` | `assets[].properties.host_rdns` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[netbios-name]` | `assets[].identity_hints.netbios_name` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[mac-address]` | `assets[].identity_hints.mac_addresses, assets[].properties.mac_address` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[operating-system]` | `assets[].properties.os (first guess)` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[operating-system-conf]` | `assets[].properties.os_confidence` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[operating-system-method]` | `assets[].properties.os_method` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[os]` |  | OS family word (linux, windows); operating-system is kept |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[system-type]` | `assets[].properties.system_type` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[cpe]` | `assets[].identity_hints.os_cpe (an OS CPE)` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[cpe-*]` | `assets[].identity_hints.os_cpe (the first OS CPE)` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[bios-uuid]` | `assets[].properties.bios_uuid` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[aws-instance-instanceId]` | `assets[].identity_hints.cloud_resource_id` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[azure-instance-id]` | `assets[].identity_hints.cloud_resource_id` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[gcp-instance-id]` | `assets[].identity_hints.cloud_resource_id` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[aws-*]` |  | cloud inventory detail beyond the instance id |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[azure-*]` |  | cloud inventory detail beyond the instance id |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[gcp-*]` |  | cloud inventory detail beyond the instance id |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[nessus-agent-uuid]` | `assets[].identity_hints.agent_id` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[tenable-agent-uuid]` | `assets[].identity_hints.agent_id` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[agent-uuid]` | `assets[].identity_hints.agent_id` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[Credentialed_Scan]` | `findings[].native.credentialed` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[HOST_START]` | `assets[].properties.scan_started_at (when no timestamp)` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[HOST_START_TIMESTAMP]` | `assets[].properties.scan_started_at` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[HOST_END]` | `assets[].properties.scan_ended_at (when no timestamp)` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[HOST_END_TIMESTAMP]` | `assets[].properties.scan_ended_at` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[local-checks-proto]` | `assets[].properties.local_checks_protocol` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[smb-login-used]` |  | the account the scan logged in with |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[ssh-login-used]` |  | the account the scan logged in with |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[ssh-auth-meth]` |  | how the scan authenticated (scan operation detail) |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[ssh-fingerprint]` |  | SSH host key fingerprint seen by the scanner; not an asset identity CTIS defines |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[LastAuthenticatedResults]` |  | scan bookkeeping time |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[LastUnauthenticatedResults]` |  | scan bookkeeping time |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[policy-used]` |  | scan policy name (scan operation detail) |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[patch-summary-*]` |  | summary derived from the plugin results, which are imported |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[traceroute-hop-*]` |  | network path from the scanner, not a property of the host |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[sinfp-*]` |  | raw OS fingerprint signature; operating-system is kept |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[hostname]` |  | duplicate of host-fqdn / netbios-name |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[host_end_timestamp]` |  | duplicate of HOST_END_TIMESTAMP |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[host_start_timestamp]` |  | duplicate of HOST_START_TIMESTAMP |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[id]` |  | scanner-internal host number |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[host-uuid]` |  | scanner-internal host id, unique per scanner database |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[wmi-domain]` |  | Windows domain of the host (directory detail) |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[smb-domain]` |  | Windows domain of the host (directory detail) |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[*]` |  | other host properties (installed software and hardware inventory, scanner bookkeeping); listed by name in Result.Unmapped only when not matched here |
| `/NessusClientData_v2/Report/ReportHost/ReportItem` | `findings[]` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/@port` | `findings[].network.port` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/@svc_name` | `findings[].network.service` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/@protocol` | `findings[].network.protocol` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/@severity` | `findings[].severity, findings[].native.severity` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/@pluginID` | `findings[].rule_id, findings[].native.vuln_id` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/@pluginName` | `findings[].title, findings[].rule_name` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/@pluginFamily` | `findings[].category, findings[].native.family` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/plugin_name` | `findings[].title (when no pluginName)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/synopsis` | `findings[].message, findings[].description` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/description` | `findings[].description` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/solution` | `findings[].remediation.recommendation` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/plugin_output` | `findings[].evidence (credentials redacted)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/see_also` | `findings[].references` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/risk_factor` | `findings[].severity (fallback), findings[].source_extra.risk_factor` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cve` | `findings[].vulnerability.cve_id, cve_ids, ids[] (cve)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/bid` | `findings[].vulnerability.ids[] (vendor, source bid)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/xref` | `findings[].vulnerability.cwe_ids (CWE), ids[] (vendor), remediation.advisories (MSFT, MSKB, IAVA, IAVB, CERT, ...), source_extra.xref` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/msft` | `findings[].remediation.advisories (source msft)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/mskb` | `findings[].remediation.advisories (source mskb)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/iava` | `findings[].remediation.advisories (source iava)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/iavb` | `findings[].remediation.advisories (source iavb)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/iavt` | `findings[].remediation.advisories (source iavt)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cert` | `findings[].remediation.advisories (source cert)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cea-id` | `findings[].remediation.advisories (source cea-id)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cvss_base_score` | `findings[].scores[] (cvss 2.0), vulnerability.cvss_score` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cvss_vector` | `findings[].scores[].vector (cvss 2.0), properties.cvss_v2_vector` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cvss3_base_score` | `findings[].scores[] (cvss 3.x), vulnerability.cvss_score` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cvss3_vector` | `findings[].scores[].vector (cvss 3.x), properties.cvss_v3_vector` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cvss4_base_score` | `findings[].scores[] (cvss 4.0)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cvss4_vector` | `findings[].scores[].vector (cvss 4.0)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cvss4_base_vector` | `findings[].scores[].vector (cvss 4.0)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cvss_temporal_score` | `findings[].source_extra.cvss_temporal_score` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cvss_temporal_vector` | `findings[].source_extra.cvss_temporal_vector` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cvss3_temporal_score` | `findings[].source_extra.cvss3_temporal_score` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cvss3_temporal_vector` | `findings[].source_extra.cvss3_temporal_vector` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cvss3_impact_score` | `findings[].source_extra.cvss3_impact_score` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cvssV3_impact_score` | `findings[].source_extra.cvssV3_impact_score` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cvss4_threat_score` | `findings[].source_extra.cvss4_threat_score` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cvss4_threat_vector` | `findings[].source_extra.cvss4_threat_vector` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cvss_score_source` | `findings[].source_extra.cvss_score_source` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cvss3_score_source` | `findings[].source_extra.cvss3_score_source` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/vpr_score` | `findings[].scores[] (vpr), vulnerability.vpr_score` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/epss_score` | `findings[].scores[] (epss), vulnerability.epss_score` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/exploit_available` | `findings[].vulnerability.exploit_available` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/exploit_code_maturity` | `findings[].vulnerability.exploit_maturity, source_extra.exploit_code_maturity` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/exploitability_ease` | `findings[].source_extra.exploitability_ease` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/exploit_framework_metasploit` | `findings[].source_extra.exploit_framework_metasploit` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/exploit_framework_canvas` | `findings[].source_extra.exploit_framework_canvas` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/exploit_framework_core` | `findings[].source_extra.exploit_framework_core` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/exploit_framework_d2_elliot` | `findings[].source_extra.exploit_framework_d2_elliot` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/exploit_framework_exploithub` | `findings[].source_extra.exploit_framework_exploithub` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/metasploit_name` | `findings[].source_extra.metasploit_name` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/canvas_package` | `findings[].source_extra.canvas_package` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/d2_elliot_name` | `findings[].source_extra.d2_elliot_name` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/exploited_by_malware` | `findings[].source_extra.exploited_by_malware` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/exploited_by_nessus` | `findings[].source_extra.exploited_by_nessus` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/in_the_news` | `findings[].source_extra.in_the_news` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/unsupported_by_vendor` | `findings[].remediation.solution_type (upgrade), source_extra.unsupported_by_vendor` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/default_account` | `findings[].source_extra.default_account` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cisa-known-exploited` | `findings[].vulnerability.in_cisa_kev, source_extra (the KEV due date)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cisa_known_exploited` | `findings[].vulnerability.in_cisa_kev, source_extra` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cpe` | `findings[].vulnerability.cpe` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/vuln_publication_date` | `findings[].vulnerability.published_at, source_extra` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/patch_publication_date` | `findings[].remediation.patch_published_at, fix_available, properties.patch_publication_date` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/plugin_publication_date` | `findings[].source_extra.plugin_publication_date` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/plugin_modification_date` | `findings[].source_extra.plugin_modification_date` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/plugin_type` | `findings[].source_extra.plugin_type` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/stig_severity` | `findings[].source_extra.stig_severity` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/age_of_vuln` | `findings[].source_extra.age_of_vuln` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/threat_intensity_last_28` | `findings[].source_extra.threat_intensity_last_28` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/threat_recency` | `findings[].source_extra.threat_recency` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/threat_sources_last_28` | `findings[].source_extra.threat_sources_last_28` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/product_coverage` | `findings[].source_extra.product_coverage` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/vendor_severity` | `findings[].source_extra.vendor_severity` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/vendor_unpatched` | `findings[].source_extra.vendor_unpatched` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/rhsa` | `findings[].source_extra.rhsa` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/usn` | `findings[].source_extra.usn` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/dsa` | `findings[].source_extra.dsa` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/glsa` | `findings[].source_extra.glsa` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/fedora` | `findings[].source_extra.fedora` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/suse` | `findings[].source_extra.suse` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/osvdb` | `findings[].source_extra.osvdb` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/edb-id` | `findings[].source_extra.edb-id` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-check-name` | `findings[].type compliance, title, compliance.control_name` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-check-id` | `findings[].compliance.control_id (when no control id), source_extra` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-control-id` | `findings[].compliance.control_id` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-result` | `findings[].compliance.result, source_extra.compliance-result` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-info` | `findings[].compliance.control_description` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-actual-value` | `findings[].evidence (credentials redacted)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-policy-value` | `findings[].source_extra.compliance-policy-value` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-solution` | `findings[].remediation.recommendation` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-see-also` | `findings[].references` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-reference` | `findings[].source_extra.compliance-reference` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-audit-file` | `findings[].source_extra.compliance-audit-file` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-benchmark-name` | `findings[].compliance.framework (cis, nist, pci-dss, ... from the name), source_extra.compliance-benchmark-name` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-benchmark-version` | `findings[].compliance.framework_version` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-benchmark-profile` | `findings[].source_extra.compliance-benchmark-profile` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-full-id` | `findings[].source_extra.compliance-full-id` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-functional-id` | `findings[].source_extra.compliance-functional-id` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-source` | `findings[].source_extra.compliance-source` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-uname` |  | the account the compliance check ran as |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance` |  | flag duplicating compliance-check-name |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/fname` |  | plugin script file name (scanner internals) |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/script_version` |  | plugin script revision (scanner internals) |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/agent` |  | which scanner kinds run the plugin (scanner internals) |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/thorough_tests` |  | scan setting the plugin needs (scanner internals) |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/always_run` |  | scan setting (scanner internals) |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/required_key` |  | plugin dependency (scanner internals) |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/required_port` |  | plugin dependency (scanner internals) |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/dependency` |  | plugin dependency (scanner internals) |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/asset_inventory` |  | flag for inventory plugins (scanner internals) |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/hardware_inventory` |  | flag for inventory plugins (scanner internals) |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/os_identification` |  | flag for OS identification plugins (scanner internals) |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/asset_inventory_category` |  | inventory plugin category (scanner internals) |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/attachment` |  | binary attachment of the plugin result (screenshots, files); not imported |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/attachment/@*` |  | binary attachment of the plugin result; not imported |
