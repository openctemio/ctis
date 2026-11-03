# OpenCTEM receiver profile

Status: informative. This document describes how OpenCTEM, one receiver of CTIS, applies the [specification](../spec.md). It does not change the meaning of any member. Other receivers publish their own profile.

## 1. Where the specification names OpenCTEM behaviour

These parts of the specification describe OpenCTEM today. They move here in full when the specification is made receiver-neutral ([proposals-2.0.md](../proposals-2.0.md), item P1):

- section 4.7: how OpenCTEM derives a report's detection technique from `tool.capabilities`;
- section 4.9: how OpenCTEM binds a report to the command that produced it (the v2 URL path or the `X-OpenCTEM-Command-ID` header), and why `metadata.id` must equal the report ID it assigned;
- section 4.11: `metadata.capability` refers to the OpenCTEM capability taxonomy;
- section 5.1: OpenCTEM uses a producer fingerprint only when it is hexadecimal and at least 16 characters long;
- section 7: the request, report and text limits OpenCTEM enforces.

## 2. What OpenCTEM stores

CTIS carries more than OpenCTEM persists today. As of October 2026, these members are accepted and validated but not stored or not used. Producers MAY send them; they are informational until the platform reads them:

- `finding.evidence`, `vulnerability.vpr_score`
- `finding.first_seen_at`, `finding.last_seen_at` (imported findings start their age at import time)
- `finding.status`, `finding.suppression`
- `vulnerability.cve_ids` beyond the first CVE (used for network deduplication only)
- `asset.related_assets`, `asset.services`
- `finding.category`, `author`, `author_email`, `commit_date`
- `vulnerability.cvss_version`, `cvss_source`, `severity_source`, `vendor_severity`, `dependency_path`, `layer`, `avd_id`, `vuln_status`
- `vulnerability.in_cisa_kev`, `epss_score`, `epss_percentile` (deliberately: OpenCTEM takes KEV and EPSS from its own threat-intelligence feeds)
- `remediation.fix_available`, `remediation.auto_fixable`
- `data_flow.tainted`, `taint_type`, `vulnerability_type`, `call_path`
- `metadata.source_ref`, `scope.includes`, `scope.excludes`, `branch.pull_request_*`
- `tool.vendor`, `tool.info_url`, `dependency.uid`
- `finding.partial_fingerprints`

