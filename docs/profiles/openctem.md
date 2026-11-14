# OpenCTEM receiver profile

Status: informative. This document describes how OpenCTEM, one receiver of CTIS, applies the [specification](../spec.md) to CTIS 2.0 documents. It does not change the meaning of any member. Other receivers publish their own profile.

## 1. Versions

OpenCTEM accepts CTIS 2.x only. A 1.x document is rejected with an error that names the upgrade: sensors, connectors and CI integrations are upgraded together with the platform. Newer 2.x minors are decoded with version-gated must-ignore (`ctis.Decode`).

## 2. Binding a document to a job

A CTIS document carries no receiver key. OpenCTEM binds a document to the job or command that produced it through the transport, never through the document:

- the sensor protocol v2 delivers results at `/commands/{command_id}/results/{delivery_id}`; the command id and the delivery id are OpenCTEM's own identifiers and stay in the URL path and OpenCTEM's records;
- the v1 path carries the command in the `X-OpenCTEM-Command-ID` header;
- the request media type is `application/vnd.ctis+json; version=2.0`.

`metadata.id` is the producer's UUIDv7. OpenCTEM uses it only as the idempotency key of a delivery, scoped to the credential that sent it: a retry with the same `metadata.id` from the same credential is recognised as a retry. OpenCTEM never uses it as one of its own record ids, and never reads an asset, finding, scan or tenant id from a document. It resolves natural keys (asset keys from canonical values, recomputed fingerprints) to its own UUIDs at ingest.

## 3. Capability, technique and channel

- The capability a document answers is the capability of the command OpenCTEM bound it to. A producer MAY state it in `metadata.extensions["io.openctem"].capability` (`id@major`, for example `scan.ports@1`); OpenCTEM treats it as a hint and never widens what the document may create because of it. The capability taxonomy is in the `github.com/openctemio/contract` module.
- The detection technique comes from `finding.technique`, else the first of `tool.techniques`.
- The channel comes from the authenticated credential (a sensor key, an integration token, a user upload); `metadata.channel` is a hint.

## 4. The io.openctem namespace

[`schemas/extensions/io.openctem/2.json`](../../schemas/extensions/io.openctem/2.json) defines the keys OpenCTEM reads under `extensions["io.openctem"]`: `capability` and `ignore_file_paths` (metadata; the patterns of a repository's scanner ignore file, which become pending suppression requests, never suppressions), `import_scope`, `candidate_exposure` and `candidate_unverified` (assets from importers), `bounty_report` (findings from disclosure reports; `researcher` is personal data), `compliance_outcome` (compliance findings of kind `not_applicable`: `error` when the check could not run, `skipped`; the receiver keeps an error as its own state), `verification_hold` (findings whose matched response the producer screened as possibly the target's throttling or block answer: `reasons` from `edge_block_page`, `throttled_response`, `soft_404`, `target_throttled`, `timing_based`, `oob_weak`, and the screen's inputs `status`, `edge`, `edge_vendor`, `similarity`, never the response body; the receiver keeps the finding and holds it out of scores, SLA, notifications and tickets until it is checked), `web_content` (web origins) and `rule_source` (rules: `tenant` for a rule the tenant authored, `platform` for a platform rule). OpenCTEM gives no meaning to `properties`.

## 5. Asset types

OpenCTEM keeps its stored asset model and maps the 2.0 wire types to it: `domain_name` to domain or subdomain (by the public-suffix apex), `web_origin` to an http service, `service` to service, `host` to host, `identity` with its kind to identity, `ip_range` to network, `kubernetes_cluster` to kubernetes. Asset natural keys are (tenant, stored type, canonical value).

## 6. Fingerprints

OpenCTEM computes its own fingerprints (recipe `ctis-fp/2`) and a composite with its asset id; a producer's `fingerprint` is a hint used only when it is a `ctis-fp/2:` value. Stored findings were migrated from recipe v1 with the deprecated v1 functions of the `fingerprint` package; the old values stay as aliases so triage carries over.

## 7. Limits

| Limit | Value |
|---|---|
| Findings or assets per document | 100,000 |
| Findings or assets per segment | 10,000 |
| Request body (v2, compressed / decompressed) | 16 MiB / 64 MiB |
| JSON nesting depth | 64 |
| Tags per asset | 50 |
| Request body of a CI run upload | 50 MB |

OpenCTEM cuts long text members (title 500, description 32 KiB, message 8 KiB, snippets 16 KiB characters) and appends `…[truncated]` rather than refusing a document.

## 8. What OpenCTEM stores

OpenCTEM validates every member. These are accepted but not stored, or used only as hints, as of the 2.0 cut:

- `finding.status`, `finding.suppression` (hints; OpenCTEM keeps its own lifecycle)
- `first_seen_at`, `last_seen_at` of imported findings (imported findings start their age at import time)
- `vulnerability.threat_signals`, EPSS scores (OpenCTEM takes KEV and EPSS from its own threat-intelligence feeds)
- `data_flow.taint_type`, `call_path`
- `branch.pull_request_*`, `tool.vendor`, `tool.info_url`, `dependency.source_id`
- `finding.partial_fingerprints`
