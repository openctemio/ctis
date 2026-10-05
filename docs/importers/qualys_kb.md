# Qualys KnowledgeBase XML mapping

Generated from `importer/spec_qualys_kb.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `qualys_kb`
- Source versions: KNOWLEDGE_BASE_VULN_LIST_OUTPUT of the KnowledgeBase API v2 (/api/2.0/fo/knowledge_base/vuln/, details=All)
- Fields: 53 mapped, 30 ignored on purpose (64% mapped)

## Rules

- Read only as the companion of a detection file. Each VULN enriches every finding of its QID; entries of other QIDs are skipped without being kept.
- DIAGNOSIS, CONSEQUENCE and SOLUTION are light HTML: line-break and paragraph tags become newlines and every other tag is dropped, so the text is plain text.
- CVSS v3 and v2 go to finding.scores with their source attribute (service, nvd, ...); the legacy vulnerability.cvss_* members take v3, else v2.
- THREAT_INTELLIGENCE labels become tags; exploit-related ones (Exploit_Public, Easy_Exploit, Active_Attacks, Malware, Exploit_Kit, Wormable, Ransomware, Cisa_Known_Exploited_Vulns) set exploit_available, and Cisa_Known_Exploited_Vulns sets in_cisa_kev.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/DATETIME` |  | generation time of the KnowledgeBase export; the detection file's time is kept |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN` | `findings[] of the QID (enrichment)` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/QID` | `join key` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/VULN_TYPE` | `findings[].native.detection_type (when the detection has no TYPE), source_extra.vuln_type` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/SEVERITY_LEVEL` |  | the detection's SEVERITY is the severity of the finding |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/TITLE` | `findings[].title, rule_name` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CATEGORY` | `findings[].category, native.family` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/TECHNOLOGY` | `findings[].source_extra.technology` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/DETECTION_INFO` | `findings[].source_extra.detection_info` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/LAST_CUSTOMIZATION` |  | KnowledgeBase edit bookkeeping |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/LAST_CUSTOMIZATION/**` |  | KnowledgeBase edit bookkeeping (who and when) |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/LAST_SERVICE_MODIFICATION_DATETIME` | `findings[].vulnerability.modified_at` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/PUBLISHED_DATETIME` | `findings[].vulnerability.published_at` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CODE_MODIFIED_DATETIME` | `findings[].source_extra.code_modified_datetime` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/BUGTRAQ_LIST` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/BUGTRAQ_LIST/BUGTRAQ` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/BUGTRAQ_LIST/BUGTRAQ/ID` | `findings[].vulnerability.ids[] (vendor, source bid)` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/BUGTRAQ_LIST/BUGTRAQ/URL` | `findings[].references` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/PATCHABLE` | `findings[].remediation.fix_available, solution_type patch, source_extra.patchable` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/PATCH_PUBLISHED_DATE` | `findings[].remediation.patch_published_at` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/SOFTWARE_LIST` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/SOFTWARE_LIST/SOFTWARE` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/SOFTWARE_LIST/SOFTWARE/PRODUCT` | `findings[].source_extra.affected_software` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/SOFTWARE_LIST/SOFTWARE/VENDOR` | `findings[].source_extra.affected_software` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/VENDOR_REFERENCE_LIST` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/VENDOR_REFERENCE_LIST/VENDOR_REFERENCE` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/VENDOR_REFERENCE_LIST/VENDOR_REFERENCE/ID` | `findings[].remediation.advisories[].id` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/VENDOR_REFERENCE_LIST/VENDOR_REFERENCE/URL` | `findings[].remediation.advisories[].url` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVE_LIST` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVE_LIST/CVE` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVE_LIST/CVE/ID` | `findings[].vulnerability.cve_id, cve_ids, ids[]` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVE_LIST/CVE/URL` | `findings[].references` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/DIAGNOSIS` | `findings[].description` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/DIAGNOSIS_COMMENT` | `findings[].source_extra.diagnosis_comment` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CONSEQUENCE` | `findings[].source_extra.consequence` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CONSEQUENCE_COMMENT` | `findings[].source_extra.consequence_comment` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/SOLUTION` | `findings[].remediation.recommendation` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/SOLUTION_COMMENT` | `findings[].source_extra.solution_comment` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/COMPLIANCE_LIST` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/COMPLIANCE_LIST/COMPLIANCE` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/COMPLIANCE_LIST/COMPLIANCE/TYPE` | `findings[].source_extra.compliance` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/COMPLIANCE_LIST/COMPLIANCE/SECTION` | `findings[].source_extra.compliance` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/COMPLIANCE_LIST/COMPLIANCE/DESCRIPTION` | `findings[].source_extra.compliance` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CORRELATION` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CORRELATION/EXPLOITS` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CORRELATION/EXPLOITS/EXPLT_SRC` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CORRELATION/EXPLOITS/EXPLT_SRC/SRC_NAME` | `findings[].source_extra.exploits` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CORRELATION/EXPLOITS/EXPLT_SRC/EXPLT_LIST` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CORRELATION/EXPLOITS/EXPLT_SRC/EXPLT_LIST/EXPLT` | `findings[].vulnerability.exploit_available` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CORRELATION/EXPLOITS/EXPLT_SRC/EXPLT_LIST/EXPLT/REF` | `findings[].source_extra.exploits` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CORRELATION/EXPLOITS/EXPLT_SRC/EXPLT_LIST/EXPLT/DESC` | `findings[].source_extra.exploits (when no REF)` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CORRELATION/EXPLOITS/EXPLT_SRC/EXPLT_LIST/EXPLT/LINK` | `findings[].references` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CORRELATION/MALWARE` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CORRELATION/MALWARE/MW_SRC` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CORRELATION/MALWARE/MW_SRC/SRC_NAME` | `findings[].source_extra.malware` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CORRELATION/MALWARE/MW_SRC/MW_LIST` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CORRELATION/MALWARE/MW_SRC/MW_LIST/MW_INFO` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CORRELATION/MALWARE/MW_SRC/MW_LIST/MW_INFO/MW_ID` | `findings[].source_extra.malware` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CORRELATION/MALWARE/MW_SRC/MW_LIST/MW_INFO/MW_TYPE` | `findings[].source_extra.malware` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CORRELATION/MALWARE/MW_SRC/MW_LIST/MW_INFO/MW_RATING` | `findings[].source_extra.malware` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CORRELATION/MALWARE/MW_SRC/MW_LIST/MW_INFO/MW_PLATFORM` |  | malware platform list; the id, type and rating are kept |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CORRELATION/MALWARE/MW_SRC/MW_LIST/MW_INFO/MW_ALIAS` |  | malware aliases; the id is kept |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CORRELATION/MALWARE/MW_SRC/MW_LIST/MW_INFO/MW_LINK` |  | link to a malware encyclopedia page |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS/BASE` | `findings[].scores[] (cvss 2.0), vulnerability.cvss_score (when no v3)` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS/BASE/@source` | `findings[].scores[].source` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS/TEMPORAL` | `findings[].source_extra.cvss2_temporal` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS/VECTOR_STRING` | `findings[].scores[].vector (cvss 2.0)` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS/ACCESS` |  | vector component, kept in the vector string |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS/ACCESS/**` |  | vector component, kept in the vector string |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS/IMPACT` |  | vector component, kept in the vector string |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS/IMPACT/**` |  | vector component, kept in the vector string |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS/AUTHENTICATION` |  | vector component, kept in the vector string |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS/EXPLOITABILITY` |  | temporal component, kept in the temporal score |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS/REMEDIATION_LEVEL` |  | temporal component, kept in the temporal score |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS/REPORT_CONFIDENCE` |  | temporal component, kept in the temporal score |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS_V3` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS_V3/BASE` | `findings[].scores[] (cvss 3.x), vulnerability.cvss_score` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS_V3/BASE/@source` | `findings[].scores[].source` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS_V3/TEMPORAL` | `findings[].source_extra.cvss3_temporal` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS_V3/VECTOR_STRING` | `findings[].scores[].vector (cvss 3.x), the version` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS_V3/CVSS3_VERSION` | `findings[].scores[].version (when the vector has none)` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS_V3/ATTACK_VECTOR` |  | vector component, kept in the vector string |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS_V3/ATTACK_COMPLEXITY` |  | vector component, kept in the vector string |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS_V3/PRIVILEGES_REQUIRED` |  | vector component, kept in the vector string |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS_V3/USER_INTERACTION` |  | vector component, kept in the vector string |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS_V3/SCOPE` |  | vector component, kept in the vector string |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS_V3/IMPACT` |  | vector component, kept in the vector string |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS_V3/IMPACT/**` |  | vector component, kept in the vector string |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS_V3/EXPLOIT_CODE_MATURITY` |  | temporal component, kept in the temporal score |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS_V3/REMEDIATION_LEVEL` |  | temporal component, kept in the temporal score |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CVSS_V3/REPORT_CONFIDENCE` |  | temporal component, kept in the temporal score |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/PCI_FLAG` | `findings[].tags (pci), source_extra.pci_flag` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/PCI_REASONS` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/PCI_REASONS/PCI_REASON` | `findings[].source_extra.pci_reasons` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/THREAT_INTELLIGENCE` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/THREAT_INTELLIGENCE/THREAT_INTEL[*]` | `findings[].tags, vulnerability.exploit_available, in_cisa_kev` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/THREAT_INTELLIGENCE/THREAT_INTEL[*]/@id` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/DISCOVERY` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/DISCOVERY/REMOTE` | `findings[].source_extra.discovery_remote` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/DISCOVERY/AUTH_TYPE_LIST` | (container) |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/DISCOVERY/AUTH_TYPE_LIST/AUTH_TYPE` | `findings[].source_extra.discovery_auth_types` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/DISCOVERY/ADDITIONAL_INFO` | `findings[].source_extra.discovery_additional_info` |  |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/SUPPORTED_MODULES` |  | Qualys product modules that detect the QID |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/IS_DISABLED` |  | KnowledgeBase entry state; the detection's IS_DISABLED is kept |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CHANGE_LOG_LIST` |  | KnowledgeBase revision history |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/CHANGE_LOG_LIST/**` |  | KnowledgeBase revision history |
| `/KNOWLEDGE_BASE_VULN_LIST_OUTPUT/RESPONSE/VULN_LIST/VULN/AUTOMATIC_PCI_FAIL` |  | PCI scan setting |
