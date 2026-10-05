# Qualys VM host list detection XML mapping

Generated from `importer/spec_qualys.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `qualys`
- Source versions: HOST_LIST_VM_DETECTION_OUTPUT of the VM detection API v2 (/api/2.0/fo/asset/host/vm/detection/), joined with the KnowledgeBase (qualys_kb)
- Fields: 60 mapped, 15 ignored on purpose (80% mapped)

## Rules

- One asset per HOST: value is DNS_DATA/FQDN, else DNS, else IP, else IPV6, else NETBIOS; type ip_address when the value is an IP address, else host. Asset id `host-<value>`.
- One finding per DETECTION, keyed by QID: rule_id and native.vuln_id are the QID, native.instance_id the UNIQUE_VULN_ID. Title, description, CVEs, CVSS and the solution come from the KnowledgeBase entry of the QID (qualys_kb.md); without one the title is `Qualys QID <n>` and an issue says so.
- Severity: SEVERITY 1-5 through ctis.NormalizeNativeSeverity (1 info, 2 low, 3 medium, 4 high, 5 critical); native.severity keeps it.
- TYPE Confirmed / Potential / Info goes to native.detection_type; a Potential detection gets confidence 50.
- STATUS New / Active / Re-Opened / Fixed goes to native.status, the normalized finding status and source_lifecycle.state. FIRST_FOUND, LAST_FOUND, LAST_FIXED and TIMES_FOUND go to source_lifecycle (and first_seen_at / last_seen_at).
- RESULTS go to evidence after credential redaction (account lines, passwords, tokens, community strings become [redacted]).
- Host owner, comments and user-defined fields are never read; asset criticality and risk scores are kept as properties and do not set the CTIS criticality.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/HOST_LIST_VM_DETECTION_OUTPUT` | (container) |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE` | (container) |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/DATETIME` | `metadata.properties.generated_at` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/WARNING` |  | pagination notice; an issue says the export is one page |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/WARNING/**` |  | pagination notice (code, text, next-page URL) |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST` | (container) |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST` | `assets[]` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/ID` | `assets[].properties.qualys_host_id` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/ASSET_ID` | `assets[].properties.qualys_asset_id` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/IP` | `assets[].value (when no DNS name), properties.ip_address` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/IPV6` | `assets[].value (when no DNS name or IPv4), properties.ipv6_address` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/TRACKING_METHOD` | `assets[].properties.tracking_method` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/NETWORK_ID` | `assets[].properties.network_id` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/OS` | `assets[].properties.os` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/OS_CPE` | `assets[].identity_hints.os_cpe` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DNS` | `assets[].value, identity_hints.fqdn (when no DNS_DATA/FQDN)` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DNS_DATA` | (container) |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DNS_DATA/HOSTNAME` | `assets[].properties.dns_hostname` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DNS_DATA/DOMAIN` | `assets[].properties.dns_domain` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DNS_DATA/FQDN` | `assets[].value, identity_hints.fqdn, properties.fqdn` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/NETBIOS` | `assets[].identity_hints.netbios_name` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/CLOUD_PROVIDER` | `assets[].properties.cloud_provider` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/CLOUD_SERVICE` | `assets[].properties.cloud_service` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/CLOUD_RESOURCE_ID` | `assets[].identity_hints.cloud_resource_id` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/EC2_INSTANCE_ID` | `assets[].identity_hints.cloud_resource_id (when no CLOUD_RESOURCE_ID)` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/QG_HOSTID` | `assets[].identity_hints.agent_id` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/LAST_SCAN_DATETIME` | `assets[].properties.last_scan_at` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/LAST_VM_SCANNED_DATE` | `assets[].properties.last_vm_scanned_at` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/LAST_VM_SCANNED_DURATION` | `assets[].properties.last_vm_scan_duration_s` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/LAST_VM_AUTH_SCANNED_DATE` | `assets[].properties.last_vm_auth_scanned_at` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/LAST_VM_AUTH_SCANNED_DURATION` |  | scan bookkeeping |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/LAST_PC_SCANNED_DATE` | `assets[].properties.last_pc_scanned_at` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/ASSET_RISK_SCORE` | `assets[].properties.qualys_asset_risk_score` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/TRURISK_SCORE` | `assets[].properties.qualys_trurisk_score` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/ASSET_CRITICALITY_SCORE` | `assets[].properties.qualys_asset_criticality_score` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/TAGS` | (container) |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/TAGS/TAG` | (container) |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/TAGS/TAG/NAME` | `assets[].tags` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/TAGS/TAG/TAG_ID` |  | Qualys-internal tag number; the name is kept |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/TAGS/TAG/**` |  | tag colors and rules (presentation) |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/METADATA` |  | cloud instance metadata attributes; the cloud resource id is kept |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/METADATA/**` |  | cloud instance metadata attributes; the cloud resource id is kept |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/CLOUD_PROVIDER_TAGS` |  | cloud provider tags (key/value pairs chosen by the cloud account; may hold names of people) |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/CLOUD_PROVIDER_TAGS/**` |  | cloud provider tags |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/OWNER` |  | the person who owns the host in Qualys (personal data) |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/COMMENTS` |  | free-text comments typed by users |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/USER_DEF` |  | user-defined fields |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/USER_DEF/**` |  | user-defined fields |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/ASSET_GROUP_IDS` |  | Qualys-internal asset group numbers |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/LAST_COMPLIANCE_SCAN_DATETIME` |  | policy compliance bookkeeping |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST` | (container) |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION` | `findings[]` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/UNIQUE_VULN_ID` | `findings[].native.instance_id` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/QID` | `findings[].rule_id, native.vuln_id (the KnowledgeBase join key)` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/TYPE` | `findings[].native.detection_type, confidence, source_extra.type` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/SEVERITY` | `findings[].severity, native.severity` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/PORT` | `findings[].network.port` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/PROTOCOL` | `findings[].network.protocol` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/FQDN` | `findings[].network.host` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/SSL` | `findings[].source_extra.ssl` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/INSTANCE` | `findings[].source_extra.instance` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/RESULTS` | `findings[].evidence (credentials redacted)` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/STATUS` | `findings[].status, native.status, source_lifecycle.state` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/FIRST_FOUND_DATETIME` | `findings[].source_lifecycle.first_found, first_seen_at` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/LAST_FOUND_DATETIME` | `findings[].source_lifecycle.last_found, last_seen_at` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/TIMES_FOUND` | `findings[].source_lifecycle.times_found` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/LAST_FIXED_DATETIME` | `findings[].source_lifecycle.last_fixed` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/LAST_TEST_DATETIME` | `findings[].source_extra.last_test_datetime` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/LAST_UPDATE_DATETIME` | `findings[].source_extra.last_update_datetime` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/FIRST_REOPENED_DATETIME` | `findings[].source_extra.first_reopened_datetime` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/LAST_REOPENED_DATETIME` | `findings[].source_extra.last_reopened_datetime` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/TIMES_REOPENED` | `findings[].source_extra.times_reopened` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/SERVICE` | `findings[].network.service` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/IS_IGNORED` | `findings[].source_extra.is_ignored` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/IS_DISABLED` | `findings[].source_extra.is_disabled` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/AFFECT_RUNNING_KERNEL` | `findings[].source_extra.affect_running_kernel` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/AFFECT_RUNNING_SERVICE` | `findings[].source_extra.affect_running_service` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/AFFECT_EXPLOITABLE_CONFIG` | `findings[].source_extra.affect_exploitable_config` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/LAST_PROCESSED_DATETIME` | `findings[].source_extra.last_processed_datetime` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/QDS` | `findings[].scores[] (vendor, source qualys, label = the severity attribute)` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/QDS/@severity` | `findings[].scores[].label` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/QDS_FACTORS` | (container) |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/QDS_FACTORS/QDS_FACTOR[*]` | `findings[].source_extra.qds_factors` |  |
| `/HOST_LIST_VM_DETECTION_OUTPUT/RESPONSE/HOST_LIST/HOST/DETECTION_LIST/DETECTION/QDS_FACTORS/QDS_FACTOR[*]/@name` | (container) |  |
