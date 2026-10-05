### Added: the Qualys detection importer, joined with the KnowledgeBase

- `importer.Parse` reads Qualys VM host list detection XML (`HOST_LIST_VM_DETECTION_OUTPUT`). Pass the KnowledgeBase export (`KNOWLEDGE_BASE_VULN_LIST_OUTPUT`) as `Options.QualysKnowledgeBase` to join it on QID; it is streamed and only the QIDs the detections name are decoded.
- One asset per host with its identity hints (FQDN, NetBIOS, OS CPE, cloud resource id, Qualys agent host id) and tags; one finding per detection with the QID, unique detection id, native severity, status and detection type (Confirmed / Potential / Info), the detection score, the source lifecycle (first and last found, last fixed, times found, state), and from the KnowledgeBase the title, category, diagnosis, solution, CVEs, Bugtraq ids, vendor advisories, CVSS v2 and v3 with their source, threat intelligence, exploits and patch data.
- Mapping specs `docs/importers/qualys.md` and `docs/importers/qualys_kb.md`.

### Security

- Detection results are redacted of account names, passwords, tokens and community strings; host owner, comments and user-defined fields are never read; KnowledgeBase HTML is reduced to plain text and advisory links other than http(s) are dropped. The KnowledgeBase gets the same XML limits as the detection file.
