# Nessus v2 XML (.nessus) mapping

Generated from `importer/spec_nessus.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `nessus`
- Source versions: NessusClientData_v2 as written by Nessus 10.x and Tenable.sc 6.x
- Fields: 132 mapped, 40 ignored on purpose (77% mapped)

## Rules

- One asset per ReportHost: value is host-fqdn, else host-ip, else the ReportHost name; type ip_address when the value is an IP address, else host. Asset id `host-<value>`.
- One finding per ReportItem: type vulnerability, or compliance when the item carries compliance-check-name.
- Every finding has network.host (the asset value), network.port and network.protocol; port 0 is a host-level result, and its pseudo-service general is not kept as network.service.
- Severity: the severity attribute (0-4) through ctis.NormalizeNativeSeverity (0 info, 1 low, 2 medium, 3 high, 4 critical); risk_factor when the attribute is unusable. native.severity keeps the attribute; severity 0 sets native.detection_type info.
- Every CVSS version goes to finding.scores with source tenable. VPR is a vendor score with source tenable; exploit and KEV data become vulnerability.threat_signals (source tenable or cisa).
- plugin_output and compliance-actual-value go to raw_text evidence items after credential redaction: account lines (User:, Login:, Account:) and account labels inside a line, `as '<account>'`, and password, secret, token, API key and community values become [redacted]. The passwords, tokens and community strings found there are also masked (ctis.MaskSecretMatch) wherever any other field of the finding repeats them.
- The Policy element (server and plugin preferences, which hold scan credentials and account names) is skipped whole, and smb-login-used, ssh-login-used and compliance-uname are never read.
- Application and hardware CPEs of the cpe-N host properties ("cpe:/a:vendor:product:version -> Name") become assets[].technologies[] on the host, CPE 2.3 canonical (ctis.CanonicalCPE), distinct by CPE, category application or hardware, at most 100 per asset (ctis.MaxTechnologies) with an issue beyond; the display name after -> is the name. The first operating-system CPE becomes the cpe (and version) of the operating-system technology. x-cpe values (the scanner's own names outside the CPE dictionary) keep name and version without a CPE.
- Installed packages: the plugin output of Software Enumeration (SSH) (plugin 22869: dpkg, rpm and apk lists) and Microsoft Windows Installed Software Enumeration (plugin 20811) becomes dependencies[] with asset_ref the host: deb, rpm or apk purls with the distribution of operating-system as namespace and arch, epoch and distro qualifiers; pkg:generic when the distribution is unknown and for Windows software (with the publisher as namespace when given). Distinct per host by purl, at most 10,000 per host, lines over 1 KiB and names or versions that are not package tokens skipped; the plugin output stays the finding's raw_text evidence.
- Listening sockets of the netstat-listen-{tcp,udp}{4,6}-N host properties become service assets exposed by the host with technical.service.details observed_from host (seen only from inside the host) or network (the scanner also reached the port), bind_address (any or the address) and process when given. Sockets bound to a loopback address only are not kept (nothing off the host reaches them): an issue counts them. At most 1,024 per host.
- ssh-fingerprint: each "<key type> <fingerprint>" line (MD5 colon-hex, SHA256:<base64>, or the base64 public key, whose SHA-256 fingerprint is computed) goes to assets[].properties.ssh_host_key_fingerprints, at most 8; CTIS identity_hints has no SSH host key member.
- Compliance results: compliance-error becomes findings[].message and source_extra.compliance-error (CTIS has no error member); compliance-reference is also parsed into source_extra.compliance-mappings, one "<framework>|<version>|<control>" per line (framework in the CTIS registry where one fits: 800-53 nist_800_53, CSCv7/CSCv8 cis, PCI-DSS pci_dss, ISO 27001 iso27001, CSF nist_csf; any other name lowercase), at most 64, because a compliance object holds one framework. A multi-check compliance-actual-value (blocks of a dashed line, then "PASSED|FAILED|WARNING|ERROR - title", then file, regex and matched lines) becomes source_extra.compliance-subchecks (a JSON array of {result, title, detail}, at most 32, 4 KiB) and compliance-subcheck-counts. The description loses its trailing Reference, Policy Value, Actual Value, Solution and See Also sections, which have their own members; the original text is source_extra.compliance-description-original.
- A file whose plugin results carry none of the members of a full export (description, synopsis, solution, risk_factor, plugin dates, CVEs, CVSS) gets the issue "export lacks plugin details; re-export with full plugin attributes" (NessusNoDetailsMessage); it replaces the last issue when Issues is full.
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
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[host-ip]` | `assets[].value` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[host-fqdn]` | `assets[].value, assets[].identity_hints.fqdn` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[host-rdns]` | `assets[].properties.host_rdns` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[netbios-name]` | `assets[].identity_hints.netbios_name` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[mac-address]` | `assets[].identity_hints.mac_addresses, assets[].properties.mac_address` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[operating-system]` | `assets[].technologies[] (operating-system)` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[operating-system-conf]` | `assets[].technologies[] (operating-system)_confidence` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[operating-system-method]` | `assets[].technologies[] (operating-system)_method` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[os]` |  | OS family word (linux, windows); operating-system is kept |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[system-type]` | `assets[].properties.system_type` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[cpe]` | `assets[].identity_hints.os_cpe (an OS CPE)` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[cpe-*]` | `assets[].identity_hints.os_cpe (the first OS CPE), assets[].technologies[] (application and hardware CPEs; the OS CPE on the operating-system technology)` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[bios-uuid]` | `assets[].identifiers.bios_uuid` |  |
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
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[HOST_START]` | `assets[].first_seen_at` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[HOST_START_TIMESTAMP]` | `assets[].first_seen_at` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[HOST_END]` | `assets[].last_seen_at` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[HOST_END_TIMESTAMP]` | `assets[].last_seen_at` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[local-checks-proto]` | `assets[].properties.local_checks_protocol` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[smb-login-used]` |  | the account the scan logged in with |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[ssh-login-used]` |  | the account the scan logged in with |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[ssh-auth-meth]` |  | how the scan authenticated (scan operation detail) |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[ssh-fingerprint]` | `assets[].properties.ssh_host_key_fingerprints` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[netstat-listen-*]` | `service assets (technical.service.details observed_from, bind_address, process) exposed by the host` |  |
| `/NessusClientData_v2/Report/ReportHost/HostProperties/tag[netstat-established-*]` |  | established connections name peer addresses, not services of the host |
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
| `/NessusClientData_v2/Report/ReportHost/ReportItem/@svc_name` | `findings[].network.app_protocol` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/@protocol` | `findings[].network.transport` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/@severity` | `findings[].severity, findings[].native.severity` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/@pluginID` | `findings[].rule_id, findings[].native.vuln_id` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/@pluginName` | `findings[].title, findings[].rule_name` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/@pluginFamily` | `findings[].category, findings[].native.family` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/plugin_name` | `findings[].title (when no pluginName)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/synopsis` | `findings[].message, findings[].description` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/description` | `findings[].description (a compliance result without its repeated sections; the original in source_extra.compliance-description-original)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/solution` | `findings[].remediation.recommendation` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/plugin_output` | `findings[].evidence_items[raw_text] (credentials redacted); dependencies[] for plugins 22869 and 20811` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/see_also` | `findings[].references` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/risk_factor` | `findings[].severity (fallback), findings[].source_extra.risk_factor` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cve` | `findings[].vulnerability.ids[] (cve)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/bid` | `findings[].vulnerability.ids[] (vendor, source bid)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/xref` | `findings[].vulnerability.cwe_ids (CWE), ids[] (vendor), remediation.advisories (MSFT, MSKB, IAVA, IAVB, CERT, ...), source_extra.xref` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/msft` | `findings[].remediation.advisories (source msft)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/mskb` | `findings[].remediation.advisories (source mskb)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/iava` | `findings[].remediation.advisories (source iava)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/iavb` | `findings[].remediation.advisories (source iavb)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/iavt` | `findings[].remediation.advisories (source iavt)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cert` | `findings[].remediation.advisories (source cert)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cea-id` | `findings[].remediation.advisories (source cea-id)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cvss_base_score` | `findings[].scores[] (cvss 2.0), scores[] (cvss)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cvss_vector` | `findings[].scores[].vector (cvss 2.0)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cvss3_base_score` | `findings[].scores[] (cvss 3.x), scores[] (cvss)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cvss3_vector` | `findings[].scores[].vector (cvss 3.x)` |  |
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
| `/NessusClientData_v2/Report/ReportHost/ReportItem/vpr_score` | `findings[].scores[] (vpr), scores[] (vendor, tenable)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/epss_score` | `findings[].scores[] (epss), scores[] (epss)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/exploit_available` | `findings[].vulnerability.threat_signals[]` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/exploit_code_maturity` | `findings[].vulnerability.threat_signals[], source_extra.exploit_code_maturity` |  |
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
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cisa-known-exploited` | `findings[].vulnerability.threat_signals[], source_extra (the KEV due date)` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cisa_known_exploited` | `findings[].vulnerability.threat_signals[], source_extra` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/cpe` | `findings[].vulnerability.cpe` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/vuln_publication_date` | `findings[].vulnerability.published_at, source_extra` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/patch_publication_date` | `findings[].remediation.patch_published_at, is_fix_available` |  |
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
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-actual-value` | `findings[].evidence_items[raw_text] (credentials redacted), source_extra.compliance-subchecks, source_extra.compliance-subcheck-counts` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-error` | `findings[].message, source_extra.compliance-error` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-informational-id` | `findings[].source_extra.compliance-informational-id` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-policy-value` | `findings[].source_extra.compliance-policy-value` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-solution` | `findings[].remediation.recommendation` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-see-also` | `findings[].references` |  |
| `/NessusClientData_v2/Report/ReportHost/ReportItem/compliance-reference` | `findings[].source_extra.compliance-reference, source_extra.compliance-mappings` |  |
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
