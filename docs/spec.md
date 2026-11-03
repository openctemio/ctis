# CTIS 2.0 specification

CTIS (CTEM Interchange Schema) is the JSON document format in which security tools and platforms exchange what they observe for continuous threat exposure management: assets, findings, software components, the relationships between assets and the web endpoints an origin serves. This document is normative. The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as described in RFC 2119 and RFC 8174.

The format has three descriptions, kept identical by tests:

- the JSON Schema (2020-12) in [`schemas/v2`](../schemas/v2);
- the Go types of the root package of `github.com/openctemio/ctis/v2`;
- the field reference at the end of this document, generated from the schema.

Worked examples are in [`examples/`](../examples); the conformance vectors every implementation runs are in [`conformance/v2`](../conformance/v2).

This specification describes no receiver. How one receiver applies it (its limits, what it stores, how it binds a document to a job) is an informative receiver profile, for example [profiles/openctem.md](profiles/openctem.md). A profile may narrow what a receiver accepts; it never changes the meaning of a member.

## 1. Design principles

1. **A document is a set of observations.** It states what one producer saw at `metadata.generated_at`. It is never a patch: a member left out says nothing about a stored value.
2. **Natural keys, never receiver keys.** A document carries natural keys (the canonical forms of section 5) and the producer's own references, never a receiver's database keys. Document-local references (`id`, `*_ref`) link items inside one document and mean nothing outside it; they MUST NOT be UUID-shaped. A producer's identifiers in its own systems go in `source_refs[]` (`{system, id}`). The only UUID a document is expected to carry is `metadata.id`, the producer's idempotency key.
3. **Receivers recompute every key.** Asset keys, fingerprints, correlation keys and URL templates are computed by the receiver from the document; a producer's value is a hint at most. A producer cannot choose the key another producer's data merges under.
4. **Native next to normalized.** The normalized value goes in the CTIS member (`severity`, `status`, `vulnerability.ids`); the source's own value is kept beside it (`native`, `source_extra`, `source_lifecycle`). A receiver never has to choose between them.
5. **One concept, one member, one name** (section 10). There are no aliases and no legacy duplicates.
6. **CTEM concepts only.** The core models assets, exposures and their context. External formats live in the interoperability layer (section 9), never in the core shape.
7. **Untrusted input.** Every member is bounded, URL members admit only `http` and `https`, text is plain text, and personal data is marked (section 12).
8. **No member carries a tenant.** The tenant, the channel and the capability come from the credential that delivered the document.

## 2. Versioning and compatibility

### 2.1 Version, media type, file name

- `version` is the specification version, `MAJOR.MINOR` without leading zeros. This specification is `2.0`. `ctis.NewReport()` stamps `ctis.SchemaVersion` and `ctis.SchemaURL`.
- The media type is `application/vnd.ctis+json` with a `version` parameter: `application/vnd.ctis+json; version=2.0` (`ctis.MediaTypeVersioned`). The file name suffix is `.ctis.json`.
- The schemas have immutable versioned identifiers on the project's domain: `https://schemas.openctem.io/ctis/2.0/report.json` and its siblings. They are identifiers, not locations: receivers MUST NOT fetch them, and a published `$id` never changes meaning.

### 2.2 Compatibility rule

- A **minor** release only adds optional members or enum values, or loosens a constraint. It never removes or renames a member, and never makes an optional member required.
- A **major** release may change anything. It gets a new schema directory and a new Go module path. There is no conversion between majors.

A receiver applies the rule by the minor the document declares, compared with its own (**version-gated must-ignore**):

- **Same or older minor:** the receiver MUST reject an unknown member and an unknown enum value. Decoding is strict, so a typo such as `"sevrity"` is an error, not something to drop.
- **Newer minor of the same major:** the receiver MUST ignore members it does not know, and MUST map an enum value it does not know to the member's documented fallback. An enum without a fallback loses the value: the member is removed when it is optional; otherwise the nearest enclosing optional member, or the array item that holds it, is removed (a finding of an unknown `type` is dropped; a target with an unknown `state` or `class` is dropped, so it never counts as done). The receiver SHOULD record what it ignored, mapped or removed.
- **Another major:** the receiver MUST reject the document, with an error that names the version it reads, so the operator knows to upgrade the producer. A 2.x receiver rejects every 1.x document.

| Enum | Fallback |
|---|---|
| `severity` | `unknown` |
| asset `type`, `metadata.targets[].kind` | `unclassified` |
| `environment` | `unknown` |
| `endpoints[].kind` | `other` |
| `endpoints[].auth` | `unknown` |
| every other enum | none: the value is removed as described above |

Open vocabularies (`native.scheme`, `technical.cloud.provider`, `technical.repository.platform`, compliance frameworks, `technical.http.cdn` and `waf`, the web3 vendor members, `source_refs[].system`) take any token of the form `^[a-z0-9][a-z0-9_.-]{0,63}$`; their known values are listed next to the member, and a receiver keeps an unknown value as a string.

`ctis.Decode(r io.Reader) (Report, Unknown, error)` implements the rule and lists each ignored member, mapped or lost enum value, removed member and dropped array item as a JSON Pointer (at most 1,000 entries). Decode checks shape only; receivers still run `Report.Validate`.

**Rollout:** a producer SHOULD stay within the members of the oldest receiver it talks to when it needs every member read; anything newer is ignored, not refused. Upgrade receivers first, then producers. A major moves producers and receivers together.

The Go module version follows the specification: module `v2.MINOR.x` implements CTIS `2.MINOR`; patch releases never change the format.

## 3. Document model

A CTIS document is one UTF-8 JSON object (RFC 8259), the **report**. Duplicate member names MUST NOT be used.

| Member | Required | Meaning |
|---|---|---|
| `version` | yes | Specification version (section 2) |
| `$schema` | no | The report schema `$id` |
| `metadata` | yes | `id` (UUIDv7) and `generated_at` are required |
| `tool` | no | The producing tool |
| `assets` | no | Things that exist, each in the canonical form of its type (section 5) |
| `findings` | no | Security findings, each on one asset of the document (section 6) |
| `dependencies` | no | Software components (SBOM) |
| `relationships` | no | Typed edges between two assets of the document (section 7) |
| `endpoints` | no | Methods and paths web origins serve |
| `properties` | no | An opaque bag |
| `extensions` | no | Namespaced producer data (section 8) |

### 3.1 Metadata

- `id` is a producer-generated **UUIDv7** (RFC 9562, lowercase). It identifies the document for idempotency: a retry re-sends the same id, and a receiver deduplicates on (credential, `id`). Every segment of a split result shares it. It is never a receiver's key; a receiver that binds a document to its own job or delivery record keeps that binding outside the document.
- `generated_at` is when the producer generated the document. `started_at` and `ended_at` bound the work.
- `channel` says how the data reached the document: `scanner`, `collector`, `integration`, `manual`. It is the producer's claim; a receiver that knows the channel from the credential uses that.
- `source_refs[]` are the producer's own references for the work (a scheduler job id, a scan id in the source product).
- `coverage_type` is `full`, `incremental` or `partial` (section 7.2). An absent value is not `full`.
- `branch` describes a code scan's branch; `is_default_branch` decides whether the scan describes the default branch.
- `profiles[]` lists the conformance profiles the producer claims: `core`, `discovery`, `vulnerability`, `code`, `sbom`, `validation`, `web3`.
- `targets[]` and `segment`: section 7.2.

### 3.2 Tool and techniques

`tool` names the producer (`name` required, `version`, `vendor`, `info_url`) and the detection **techniques** it applies, a closed set: `sast`, `sca`, `secret`, `iac`, `container`, `dast`, `va`, `easm`, `cspm`, `bas`, `pentest`, `manual`. The technique (how a finding was found) is a separate axis from the channel (how the data reached the document). A finding MAY override them with its own `tool` (in merged or imported reports) and its own `technique`.

### 3.3 properties

`properties` exists on the report, metadata, assets, findings and dependencies. It is an opaque bag: **receivers MUST NOT give meaning to its keys**. Data a receiver interprets belongs in a typed member or under a namespace in `extensions`.

## 4. Validation

- The schemas are JSON Schema 2020-12. `report.json` references the other files by relative `$ref`, so a validator loads all eight (`scripts/validate_schemas.py` shows how).
- Every object sets `additionalProperties: false` except the bags (`properties`, `extensions`) and the typed maps (`partial_fingerprints`, `source_extra`, `whois`, `languages`, `technical.cloud.tags`, `technical.service.details`). A typo fails at the schema exactly as it fails at a strict receiver.
- Every string, array and map carries a bound in the schema.
- `Report.Validate()` (Go) checks what the schema cannot: `metadata.id` is a UUIDv7; ids are unique; every reference resolves within the document; asset values are canonical for their type (section 5); score ranges per system; VEX consistency; target state and class fit; tri-state and cross-member rules. Producers SHOULD run it before sending; receivers MUST run it (or an equivalent) at their ingest boundary.

## 5. Assets

An asset is something that exists. `id` (a document reference), `type` and `value` are required.

### 5.1 Asset types

| Group | Types |
|---|---|
| External surface | `domain_name`, `ip_address`, `ip_range`, `certificate`, `autonomous_system` |
| Applications and services | `web_origin`, `web_application`, `api`, `mobile_app`, `saas_application`, `service` |
| Code and artifacts | `repository`, `package`, `container_image`, `ai_model` |
| Cloud | `cloud_account`, `cloud_resource`, `storage`, `database`, `serverless`, `container_registry` |
| Infrastructure and devices | `host`, `container`, `kubernetes_cluster`, `kubernetes_namespace`, `kubernetes_workload`, `endpoint_device`, `iot_device`, `ot_device`, `network_device` |
| Network | `vpc`, `subnet`, `load_balancer`, `firewall` |
| Identity | `identity` (with `technical.identity.kind`: `user`, `service_account`, `role`, `group`, `workload`) |
| Web3 profile | `smart_contract`, `wallet`, `nft_collection`, `defi_protocol`, `token`, `blockchain` |
| Fallback | `unclassified` |

Each type has one meaning, so two producers that see the same thing produce the same `(type, value)`:

- a DNS name is a `domain_name`, whatever its depth; the apex is derived, not typed;
- `scheme://host[:port]` is a `web_origin`; paths are `endpoints`, not assets;
- a port is a `service` asset (`host:port/transport`) linked from its host or address by `exposes`; it is not a member of the host;
- a machine is a `host`, whether physical, virtual or a cloud instance;
- a certificate is a `certificate` named by its SHA-256 fingerprint and linked by `serves_certificate`.

### 5.2 Canonical forms

`value` MUST be the canonical form of its type. `ctis.CanonicalAssetValue(type, value)` implements this table; [`conformance/v2/canonical`](../conformance/v2/canonical) holds the vectors.

| Type | Canonical value | Go |
|---|---|---|
| `domain_name` | trimmed, lowercase, no trailing dot, each non-ASCII label an IDNA A-label (Punycode, RFC 3492); no wildcard label (a wildcard is a certificate attribute); an all-numeric top label is refused | `CanonicalDomain` |
| `ip_address` | dotted quad without leading zeros; IPv6 per RFC 5952; an IPv4-mapped IPv6 address becomes IPv4; no zone | `CanonicalIP` |
| `ip_range` | CIDR with the network address (`10.0.0.0/8`) | `CanonicalCIDR` |
| `host` | a canonical IP address, else a canonical domain name | |
| `service` | `<canonical host>:<port>/<transport>`, an IPv6 host bracketed, transport `tcp`, `udp` or `sctp` | `CanonicalService` |
| `web_origin` | `scheme://host[:port]`, http or https, lowercase, canonical host, default port dropped | `CanonicalOrigin` |
| `repository` | `<host>/<owner path>/<name>`: no scheme, user info, port, `.git` or trailing slash; lowercase host; owner and name lowercase on case-insensitive hosts (github.com, gitlab.com, bitbucket.org, codeberg.org) | `CanonicalRepository` |
| `package` | the versionless package URL (purl spec canonical form) | `CanonicalPurl` |
| `container_image` | `<registry>/<repository>@sha256:<digest>`, Docker Hub expanded to `docker.io/library/...`; the tag is an attribute | `CanonicalImage` |
| `certificate` | SHA-256 of the DER, 64 lowercase hex digits | `CanonicalCertificateFingerprint` |
| `autonomous_system` | `AS<number>` | |
| cloud types | an ARN as issued (partition, service and region lowercase), an Azure resource id lowercase, a GCP full resource name `//<service>.googleapis.com/<path>`; another provider id as given | `CanonicalARN`, `CanonicalAzureResourceID`, `CanonicalGCPResourceName` |
| every other type | trimmed, no control characters | |

URLs inside members (not asset values) use `CanonicalURL`: origin + path with its case kept, percent-encoding normalised, dot segments removed, query parameter names only. CPE names use `CanonicalCPE`.

Domain names follow IDNA-lite: Unicode lowercase and the ideographic full stops are applied before encoding; there is no UTS 46 mapping beyond that. Producers that hold a name in Unicode SHOULD send it NFC-normalised.

### 5.3 Asset key

The **asset key** is `uuidv5(9678743b-b91d-59fa-b168-ed192fe9eed3, type + 0x1F + canonical value)` (`ctis.AssetKey`; the namespace is the uuidv5 of the URL `urn:ctis:asset-key`). Receivers compute it and never take one from a document. Two documents describe the same asset exactly when they produce the same key.

### 5.4 Other asset members

- `identifiers` are values read from the asset itself that survive renames (machine id, cloud resource id, BIOS UUID, serial number, MAC addresses, SCM repository id). Producers MUST NOT guess them. `identity_hints` are remote observations (FQDN, NetBIOS name, MACs, OS CPE, cloud id, the scanner's own agent id), weaker than identifiers.
- `technical` holds the details of the type: `domain`, `ip_address`, `repository`, `certificate`, `cloud`, `service`, `http` (a web origin's status, title, server, TLS version, redirect, CDN, WAF, JARM, favicon hash and `security_headers`), `identity`, `web3`.
- `technologies[]` are what a fingerprinting tool identified.
- `criticality` (`critical`, `high`, `medium`, `low`) is business context; scanners SHOULD NOT set it.
- `environment` (`production`, `staging`, `development`, `test`, `unknown`), `owners[]` (`kind`, `ref`, `role`; `ref` is personal data) and `compliance` (framework registry tokens, `data_classification`, `has_pii`, `has_phi`) are context.
- `first_seen_at` and `last_seen_at` are when the producer first and last observed the asset.
- `state` (`active`, `gone`) and `state_reason`: section 7.2.
- `is_internet_accessible` is tri-state (section 10).

## 6. Findings

A finding is a security finding on one asset. `type`, `title`, `severity` and `asset_ref` are required; `asset_ref` MUST name an asset of the document.

### 6.1 Types and severity

| Type | Meaning |
|---|---|
| `vulnerability` | a known vulnerability with an advisory id |
| `weakness` | a code or design weakness without an advisory id (most SAST results) |
| `secret` | an exposed credential |
| `misconfiguration` | a setting that weakens security |
| `compliance` | a control evaluation; the result is `kind` (`pass`, `fail`, `review`, `not_applicable`) |
| `exposure` | something reachable that should not be |
| `malware` | malicious code or a malicious package |
| `license` | a license policy violation |

Web3 is a profile, not a type: a smart-contract issue is a `vulnerability` or `weakness` with a `web3` block.

`severity` is the producer's assessment: `critical`, `high`, `medium`, `low`, `info` or `unknown` (the source gave none that maps). `status` is the producer's view and a hint only. `suppression` follows SARIF. `first_seen_at` and `last_seen_at` are the producer's observations.

### 6.2 Location

- `location` is for code and files; `location.commit` (`sha`, `author`, `author_email`, `committed_at`) is the commit that introduced the finding; the author members are personal data.
- `network` is for a host and port: `port` (`0` for host-level), `transport` (`tcp`, `udp`, `sctp`), `app_protocol` (an IANA service name). Producers SHOULD send `transport` with `port`.
- `web` is the location on a web origin: the redacted `url`, `method`, `endpoint_ref`, the `parameter` (location and name, never its value), `request_ref` and `status_code`. Web findings use it rather than a URL in `location.path`.
- `ctis.LocationKey` derives the normalized location on the asset: `pkg:` (versionless purl), `url:` (`web.url`, then a URL-shaped `location.path`), `file:`, `net:<port>/<transport>`, `resource:`.

### 6.3 Vulnerability, scores and threat signals

- `vulnerability.ids[]` lists every id with its namespace (`cve`, `ghsa`, `osv`, `vendor` with `source`). `ctis.PreferredVulnerabilityID` picks the id receivers key on: the numerically smallest CVE, else GHSA, else OSV, else vendor.
- `cwe_ids`, `owasp_ids`, `package_name`, `purl`, `installed_version`, `affected_version_range`, `fixed_versions`, `cpe`, `is_direct`, `dependency_path`, `data_source` and `layer` describe the affected software. The ecosystem is the purl type.
- `finding.scores[]` holds every score with its `system`, `version`, `vector`, `value`, `label`, `source` and `as_of`. Ranges: `cvss` 0-10 (a `version` of `2.0`, `3.0`, `3.1` or `4.0`, and a value or a vector that matches it), `epss` and `epss_percentile` 0-1 (FIRST's fraction: `0.97` is the 97th percentile), `ssvc` no value, `vendor` any finite number with `source` naming the vendor. There are no bare score members.
- `vulnerability.threat_signals[]` are assertions with a source and a date: `type` (`kev`, `exploited_in_wild`, `public_exploit`, `ransomware_use`, `weaponized`), `source`, `as_of`, `ref` (never fetched) and `due_on`. Receivers SHOULD prefer their own intelligence and MUST NOT embed copied catalog text.
- `attack_technique_ids` (MITRE ATT&CK) and `capec_ids` are producer hints for reporting and coverage.
- `vex` is an exploitability statement in the CSAF / OpenVEX vocabulary; `not_affected` needs a justification or a statement.

### 6.4 Remediation

`remediation` is the one remediation object: `recommendation`, `steps`, `solution_type` (the CSAF remediation categories `vendor_fix`, `workaround`, `mitigation`, `no_fix_planned`, `none_available`, plus `config_change` and `upgrade`), `effort` (`trivial`, `low`, `medium`, `high`), `estimated_minutes`, `is_fix_available` (tri-state), `is_auto_fixable`, `fix_code`, `fix_regex`, `patch_published_at` and `advisories[]` (`id`, `url`, `source`). References live in `finding.references`.

### 6.5 Evidence, validation and provenance

- `evidence_items[]` (at most 20) is the one evidence model: typed items (`http_exchange`, `raw_text`, `curl`, `command_output`, `file_excerpt`, `screenshot`; other kinds keep their fields in `data`) with an envelope (`kind`, `version`, `label`, `captured_at`, `content_sha256` taken before masking, and `sensitive[]` spans). Sensitive values MAY appear only inside marked spans; receivers mask them before display or forwarding (section 12).
- `validation` says whether and how the finding was shown to be exploitable: `status` (`exploited`, `not_exploited`, `blocked`, `detected`, `not_reproducible`, `not_tested`), `method` (`pentest`, `bas`, `automated_exploit`, `retest`, `manual_review`), `validated_at`, `validator` (personal data), `evidence_refs[]` and `notes`. A pentest or bug-bounty result is a finding with `metadata.channel: manual` and `validation`.
- `native`, `source_lifecycle` and `source_extra` keep the source's own view (principle 4). `source_lifecycle` is the source's history; receivers MUST NOT replace their own lifecycle with it.
- `dependency_ref` names the dependency the finding affects. `source_refs[]` are the producer's identifiers of the finding (a plugin instance, an issue key).

### 6.6 Secrets

- No member of a document may hold a usable secret value: not the snippet, the message, the title, the evidence outside marked spans, the remediation, the tags, the properties or a fingerprint.
- `secret.masked_value` MUST NOT reveal more than 4 characters at either end, nor more than half of the secret. Receivers SHOULD mask it again rather than trust the producer; the Go module does this with `RedactSecretFinding`.
- A secret's fingerprint input is `HMAC-SHA256(producer key, secret)` only ([fingerprints.md](fingerprints.md)).

## 7. Relationships, coverage and absence

### 7.1 Relationships

`relationships[]` are typed edges between two different assets of the document, named by their `id`. Each type has one direction, read "from <type> to", and no inverse duplicate:

| Type | From → to |
|---|---|
| `subdomain_of` | a name below → a name |
| `resolves_to` | a name → an address |
| `cname_of` | a name → the name it aliases |
| `exposes` | a host or address → a service |
| `serves_certificate` | a service or web origin → a certificate |
| `hosted_by` | a service or address → a provider or host |
| `contains` | a cluster, account, network or image → a member |
| `runs_on` | a workload, container or service → a host, cluster or cloud resource |
| `depends_on` | an application or package → a package or service |
| `deployed_from` | a workload or image → a repository or image |
| `member_of` | an identity or host → a group, network or account |
| `routes_to` | a load balancer, gateway or origin → a target |
| `has_access_to` | an identity → a resource |

An edge MAY carry `first_seen_at`, `last_seen_at` and `confidence` (0-100).

### 7.2 Coverage and absence

- `metadata.targets[]` says how each target of the work ended: `target`, `kind` (an asset type), `state` (`done`, `failed`, `skipped`, `unfinished`), `class` and `cause` (`target`, `sensor`, `platform`). `done` and `unfinished` take no class or cause; `failed` takes `unreachable`, `timeout`, `tool_error`, `egress_refused`, `name_gone`, `resolver_failed`, `sensor_network_fault`, `rate_limited`, `edge_challenged` or `edge_blocked`; `skipped` takes `refused`, `excluded`, `edge_challenged` or `edge_blocked`.
- `metadata.segment` (`index` from 0, `count` up to 10,000) places a document in a result split over several documents that share one `metadata.id`.

The absence rule is normative:

- An asset or finding seen earlier on target T is **gone** only when a document with `coverage_type: full` lists T in `metadata.targets` with `state: done` and does not contain the item, and the receiver holds every segment of that result.
- Every other absence means **not seen**: a partial or incremental document, a target that failed, was skipped or is unfinished, a target the document does not list, or a missing segment.
- An asset MAY carry `state: gone` only on an authoritative signal, named by `state_reason`: `name_gone` (an authoritative NXDOMAIN or NODATA answer), `resource_deleted` (the provider's API reports it deleted) or `inventory_removed` (the authoritative inventory no longer lists it).

## 8. Extensions

`extensions` is allowed on the report, `metadata`, assets, findings, dependencies, endpoints and relationships. It is an object keyed by a reverse-DNS namespace (`io.openctem`, `com.example.scanner`: at least two lowercase labels, at most 128 characters), each value an object whose members the namespace defines.

- A namespace MAY publish a JSON Schema. A receiver validates a namespace it knows and ignores one it does not.
- At most 32 namespaces and 64 KiB serialized per object.
- A namespace never chooses a tenant, a key, a channel or a capability.
- Experimental members MAY ship under `org.ctis.experimental` and move to the core when two independent implementations exist.
- [`schemas/extensions/io.openctem/2.json`](../schemas/extensions/io.openctem/2.json) is the OpenCTEM namespace (informative).

## 9. Interoperability

CTIS converts to and from the formats tools already speak (SARIF, CycloneDX, SPDX, OSV, CSAF, OpenVEX, OCSF) without letting their shapes into the core:

1. **The core models CTEM concepts only.** No core member exists to mirror an external format.
2. **Adapters are versioned and declarative.** Each format is an adapter: a small package plus mapping data per upstream version, with named transforms from a fixed registry. Several upstream versions load side by side and are chosen by the version the input declares; a new upstream version is normally new mapping data plus vectors.
3. **Lossless passthrough.** What an adapter cannot map is kept under `extensions["<format>"]` (`{"version": "<upstream version>", "unmapped": {<JSON pointer>: value}}`, bounded), and the reverse adapter writes it back.
4. **Independent adapter versions.** An upstream update releases its adapter only; the core version changes only when the CTEM model changes.
5. **Round trips are tested.** Every adapter and version has vectors (import, export, compare) with its accepted losses listed per fixture.

The exporters of this module and their accepted losses are listed in [exporters.md](exporters.md); the importers in [importers/](importers).

## 10. Naming rules

1. Members are lower snake_case ASCII.
2. Enum values are lower snake_case. Values from an external vocabulary keep its spelling: DNS record types, HTTP methods, CVSS vectors, ATT&CK, CWE and CAPEC ids, SPDX license ids, IANA service names, CycloneDX component types.
3. A timestamp ends in `_at` and is an RFC 3339 date-time with an offset (UTC recommended); a date ends in `_on`. External names (X.509 `not_before`, `not_after`; `as_of`) are kept.
4. A duration names its unit: `_ms`, `_seconds`, `_days`.
5. A boolean starts with `is_` or `has_`. An absent boolean means unknown. The members where "verified false" matters are tri-state in the Go types (`is_internet_accessible`, `exposure.is_*`, `remediation.is_fix_available`, `secret.is_valid`, `native.is_credentialed`).
6. An array has a plural name; an object a singular one.
7. A reference to another item of the document ends in `_ref` or `_refs`. An identifier from outside the document ends in `_id` or `_ids`. A URL ends in `_url`, except the names kept from SARIF (`hosted_viewer_uri`, `work_item_uris`).
8. A score states its system and version (`scores[]`).
9. One concept has one name in every object (`transport`, `app_protocol`).
10. Product and vendor names never appear in member names or closed enums; open vocabularies list known values instead.

## 11. Fingerprints

`finding.fingerprint` is the producer's identity for a finding (recipe `ctis-fp/2`). The recipes, their canonical encoding, the secret digest and the cross-tool **correlation key** (`ctis-ck/1`: asset key, preferred vulnerability id or `rule:<tool>/<rule_id>`, `LocationKey`) are specified in [fingerprints.md](fingerprints.md), with vectors in `conformance/v2/fingerprint` and `conformance/v2/correlation`. Receivers recompute fingerprints; a producer's value is a hint. `partial_fingerprints` carries SARIF partial fingerprints unchanged.

## 12. Security considerations

A CTIS document is untrusted input from the credential that sent it.

- **Nothing in a document chooses the tenant, the deduplication key, the channel or the capability.** Receivers take the tenant and channel from the authenticated credential and recompute every key. No member carries a tenant identifier.
- **No receiver keys.** Document-local references are never UUID-shaped (schema `not` + `Validate`), so a receiver's database key cannot be planted in a document and mistaken for one of its own. A receiver MUST NOT read a key of its own from a document.
- **URLs are data, never fetched.** Every URL member admits only `http` and `https` (schema pattern + `Validate`). A receiver MUST NOT dereference a URL of a document (`$schema`, `references`, `info_url`, `work_item_uris`, `hosted_viewer_uri`, `native.raw_ref`, advisory, evidence and threat-signal references) during ingest.
- **Text is plain text.** No member is HTML or Markdown. Receivers escape text for the output medium, SHOULD strip bidirectional control characters from text they display, and SHOULD show a non-ASCII host name with its A-label.
- **Personal data** is marked `"x-ctis-pii": true` in the schema: `location.commit.author` and `author_email`, `suppression.suppressed_by`, `owners[].ref`, `validation.validator`, `secret.scopes`, `technical.domain.whois`. Producers SHOULD omit them unless the receiver uses them (in particular `author_email`); receivers SHOULD be able to erase them.
- **Secrets**: section 6.6; secret fingerprints are keyed hashes only.
- **Extensions** are validated against their namespace schema when known and bounded always.
- **Resource limits.** Receivers enforce the limits of section 13 and bound decompression, nesting depth and string sizes before parsing further.
- **Integrity.** The channel (TLS, mutual TLS for sensors) authenticates a document in transit. A stored or relayed document MAY be signed whole, for example in a DSSE envelope over its exact bytes; a receiver MAY require a signature for a channel.

## 13. Limits

Every member carries its bound in the schema; `Validate` refuses a document that exceeds one. The main ones:

| Member | Limit |
|---|---|
| `assets`, `findings`, `dependencies` | 1,000,000 entries each (receivers SHOULD set lower limits and split into segments) |
| `relationships` | 10,000; `endpoints` 200,000 |
| asset `value` | 2,048 characters |
| document references (`id`, `*_ref`) | 255 characters, `^[A-Za-z0-9][A-Za-z0-9._:/@+=~%-]{0,254}$`, not UUID-shaped |
| `source_refs` | 16 entries; `system` an open token, `id` 256 characters |
| URL members | 2,048 characters, http or https |
| `title` / `description` / `message` | 1,024 / 32 KiB / 32 KiB characters |
| `scores` | 32 entries; `vector` 512, `source` 64, `label` and `version` 32 characters |
| `vulnerability.ids` | 64 entries; `cwe_ids` 32 |
| `remediation.advisories` | 50 entries |
| `evidence_items` | 20 items of at most 256 KiB serialized; each body and `text` 64 KiB |
| `source_extra` | 64 entries; keys 128, values 4,096 characters; 32 KiB in all |
| `technologies` | 100 entries |
| `extensions` | 32 namespaces; 64 KiB serialized per object |
| `owners` | 20; `threat_signals` 16; `capec_ids` 32 |
| `metadata.targets` | 100,000 entries, `target` 2,048 bytes, unique |
| `metadata.segment.count` | 1 to 10,000 |

Producers SHOULD split larger results into segments. A receiver profile states the limits its ingest enforces.

## 14. Field reference

Generated from `schemas/v2`. "Required" marks members the schema requires; every other member is optional.

<!-- BEGIN GENERATED FIELD REFERENCE: go test -run TestSpecFieldReference -update -->

### CTIS Report (`report.json`)

CTEM Interchange Schema (CTIS) 2.0: one producer's observations of assets, findings, dependencies, relationships and endpoints. A document carries natural keys (canonical forms) and the producer's own references, never a receiver's database keys. Normative semantics: docs/spec.md. Media type application/vnd.ctis+json; version=2.0, file suffix .ctis.json.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `$schema` | string |  | pattern `^[Hh][Tt][Tt][Pp][Ss]?://[^\s/?#]+[^\s]*$`; maxLength 2048 | Schema URL, normally https://schemas.openctem.io/ctis/2.0/report.json. An identifier: receivers never fetch it. |
| `assets` | array of `asset.json` |  |  | Discovered assets |
| `dependencies` | array of `dependency.json` |  |  | Software dependencies (SBOM) |
| `endpoints` | array of `endpoint.json` |  |  | Methods and paths web origins serve, as a tool saw them; parameters are named, never valued |
| `extensions` | `Extensions` |  |  |  |
| `findings` | array of `finding.json` |  |  | Security findings |
| `metadata` | `ReportMetadata` | yes |  |  |
| `properties` | `Properties` |  |  |  |
| `relationships` | array of `Relationship` |  |  | Typed relationships between two assets of this report, named by their ids |
| `tool` | `Tool` |  |  |  |
| `version` | string | yes | pattern `^2\.(0\|[1-9][0-9]{0,3})$`; maxLength 1024 | CTIS specification version as MAJOR.MINOR. Receivers decode a document of their own or an older minor strictly, ignore unknown members and map unknown enum values to their fallback in a document of a newer minor, and reject another major (spec section Versioning). 1.x documents are rejected. |

#### BranchInfo

Git branch context for CI/CD scans. Used for branch-aware finding lifecycle management.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `base_branch` | string |  | maxLength 1024 | Base branch for PR/MR scans (e.g., 'main' when scanning a PR targeting main) |
| `commit_sha` | string |  | maxLength 1024 | Commit SHA being scanned |
| `is_default_branch` | boolean |  |  | Whether this is the default branch (main/master). Auto-resolve only applies to default branch scans. |
| `name` | string |  | maxLength 512 | Branch name (e.g., 'main', 'feature/xyz') |
| `pull_request_number` | integer |  |  | PR/MR number if this is a pull request scan |
| `pull_request_url` | string |  | pattern `^[Hh][Tt][Tt][Pp][Ss]?://[^\s/?#]+[^\s]*$`; maxLength 2048 | Pull request URL (http or https) |
| `repository_url` | string |  | pattern `^[Hh][Tt][Tt][Pp][Ss]?://[^\s/?#]+[^\s]*$`; maxLength 2048 | Repository URL (http or https) |

#### DocumentRef

A document-local reference (id and *_ref members): links items inside one document and means nothing outside it. At most 255 visible ASCII characters, and never UUID-shaped, so a receiver's database key cannot be passed off as one.

Type: string. pattern `^[A-Za-z0-9][A-Za-z0-9._:/@+=~%-]{0,254}$`; maxLength 255

#### Extensions

Namespaced producer data: keys are reverse-DNS namespaces (io.openctem, com.example.scanner), values objects that namespace defines. A receiver validates a namespace it knows and ignores one it does not. At most 32 namespaces and 64 KiB serialized (the size is checked by Validate).

Type: map of object (free-form). 

#### Properties

An opaque bag. Receivers MUST NOT give meaning to its keys; namespaced data goes in extensions.

Type: object (free-form). 

#### Relationship

A typed edge between two different assets of the report

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `confidence` | integer |  | minimum 0; maximum 100 | How sure the producer is of the edge, 0-100 |
| `extensions` | `Extensions` |  |  |  |
| `first_seen_at` | string (date-time) |  | maxLength 64 | When the producer first observed the edge |
| `from_ref` | `DocumentRef` | yes |  | The asset the relationship starts from |
| `last_seen_at` | string (date-time) |  | maxLength 64 | When the producer last observed the edge |
| `to_ref` | `DocumentRef` | yes |  | The asset the relationship points to |
| `type` | `RelationshipType` | yes |  |  |

#### RelationshipType

One direction per type, read as from <type> to; no inverse duplicates

Type: string. one of: subdomain_of, resolves_to, cname_of, exposes, serves_certificate, hosted_by, contains, runs_on, depends_on, deployed_from, member_of, routes_to, has_access_to

#### ReportMetadata

Report metadata. No member carries a tenant identifier: the tenant comes from the credential.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `branch` | `BranchInfo` |  |  |  |
| `channel` | string |  | one of: scanner, collector, integration, manual | How the data reached the document: scanner, collector, integration, manual. A separate axis from the detection technique. |
| `coverage_type` | string |  | one of: full, incremental, partial | Coverage type: full (complete scan), incremental (diff scan), partial (specific directories) |
| `duration_ms` | integer |  | minimum 0 | Scan duration in milliseconds |
| `ended_at` | string (date-time) |  | maxLength 64 | When the work that produced the report ended |
| `extensions` | `Extensions` |  |  |  |
| `generated_at` | string (date-time) | yes | maxLength 64 | When the producer generated the document (RFC 3339 with offset) |
| `id` | string | yes | pattern `^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$` | Producer-generated UUIDv7 that identifies this document: the idempotency key. A retry re-sends the same id; receivers deduplicate on (credential, id). Every segment of a split result shares it. Never a receiver's key. |
| `profiles` | array of string |  | items: one of: core, discovery, vulnerability, code, sbom, validation, web3 | Conformance profiles the producer claims for this document |
| `properties` | `Properties` |  |  |  |
| `segment` | `Segment` |  |  |  |
| `source_refs` | array of `SourceRef` |  |  | The producer's own references for the work (a job id in its scheduler, a scan id in the source product) |
| `started_at` | string (date-time) |  | maxLength 64 | When the work that produced the report started |
| `targets` | array of `TargetOutcome` |  |  | How each target of the work ended. An item seen earlier on target T is gone only when a coverage_type full report lists T with state done and omits it |

#### Segment

This document's place in a result split over count documents that share one metadata.id. index is zero-based.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `count` | integer | yes | minimum 1; maximum 10000 |  |
| `index` | integer | yes | minimum 0; maximum 9999 |  |

#### SourceRef

A producer's own identifier of an item in its own system ({system, id}): a plugin id, a scan id, an issue key. Never a receiver's key; receivers never use it as one.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string | yes | minLength 1; maxLength 256 | The id in that system (opaque) |
| `system` | string | yes | pattern `^[a-z0-9][a-z0-9_.-]{0,63}$` | The system that issued the id, an open token |

#### TargetOutcome

How one target of the work ended, in the vocabulary of the outcome package: done and unfinished take no class or cause; failed and skipped need a class of their own

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `cause` | string |  | one of: target, sensor, platform |  |
| `class` | string |  | one of: unreachable, timeout, tool_error, egress_refused, name_gone, resolver_failed, sensor_network_fault, rate_limited, edge_challenged, edge_blocked, refused, excluded |  |
| `kind` | `AssetType` |  |  |  |
| `state` | string | yes | one of: done, failed, skipped, unfinished |  |
| `target` | string | yes | minLength 1; maxLength 2048 | The target as the work was given it (a name, an address, a range, a URL) |

#### Technique

Detection technique: how a finding was found

Type: string. one of: sast, sca, secret, iac, container, dast, va, easm, cspm, bas, pentest, manual

#### Tool

Tool that generated this report

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `info_url` | string |  | pattern `^[Hh][Tt][Tt][Pp][Ss]?://[^\s/?#]+[^\s]*$`; maxLength 2048 | Tool information URL (http or https) |
| `name` | string | yes | maxLength 512 | Tool name |
| `techniques` | array of `Technique` |  |  | Detection techniques the tool applies (closed set). A finding may override with its own technique. |
| `vendor` | string |  | maxLength 1024 | Tool vendor/organization |
| `version` | string |  | maxLength 1024 | Tool version |

### CTIS Asset (`asset.json`)

An observed asset. Its identity is AssetKey(type, canonical value); receivers compute the key and never trust a producer's.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `compliance` | `AssetCompliance` |  |  |  |
| `confidence` | integer |  | minimum 0; maximum 100 | Confidence score (0-100) |
| `criticality` | `Criticality` |  |  |  |
| `description` | string |  | maxLength 32768 | Asset description |
| `environment` | `Environment` |  |  |  |
| `extensions` | `Extensions` |  |  |  |
| `first_seen_at` | string (date-time) |  | maxLength 64 | When the producer first observed the asset |
| `id` | `DocumentRef` | yes |  | Document-local reference (required): findings, relationships, dependencies and endpoints name the asset by it |
| `identifiers` | `AssetIdentifiers` |  |  |  |
| `identity_hints` | `IdentityHints` |  |  |  |
| `is_internet_accessible` | boolean |  |  | Whether the asset is reachable from the internet. Absent means unknown; false means verified not reachable. |
| `last_seen_at` | string (date-time) |  | maxLength 64 | When the producer last observed the asset |
| `name` | string |  | maxLength 512 | Human-readable name |
| `owners` | array of `AssetOwner` |  |  | Who owns the asset |
| `properties` | `Properties` |  |  |  |
| `source_refs` | array of `SourceRef` |  |  | The producer's own identifiers of the asset in its own systems |
| `state` | string |  | one of: active, gone | State of the asset. gone only on an authoritative signal named by state_reason; every other absence is not seen |
| `state_reason` | string |  | one of: name_gone, resource_deleted, inventory_removed | The authoritative signal behind state gone |
| `tags` | array of string |  | items: maxLength 1024 | Categorization tags |
| `technical` | `AssetTechnical` |  |  |  |
| `technologies` | array of `Technology` |  |  | Technologies the asset runs, as a fingerprinting tool identified them |
| `type` | `AssetType` | yes |  |  |
| `value` | string | yes | minLength 1; maxLength 2048 | The asset's value in the canonical form of its type (spec section Canonical forms) |

#### AssetCompliance

CTEM compliance context for an asset

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `data_classification` | string |  | one of: public, internal, confidential, restricted | Data classification level |
| `frameworks` | array of `ComplianceFramework` |  |  | Compliance frameworks the asset is in scope for (framework registry tokens) |
| `has_phi` | boolean |  |  | The asset holds protected health information |
| `has_pii` | boolean |  |  | The asset holds personally identifiable information |

#### AssetIdentifiers

Identifiers that stay the same when the asset is renamed or readdressed. In order of trust: machine_id, cloud_resource_id, bios_uuid, serial_number, mac_addresses. scm_repo_id identifies a repository.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `bios_uuid` | string |  | maxLength 1024 | SMBIOS system UUID |
| `cloud_resource_id` | string |  | maxLength 1024 | Cloud instance ID, VM ID or resource ARN |
| `mac_addresses` | array of string |  | items: maxLength 1024 | MAC addresses of the host's network interfaces. Receivers ignore locally administered, multicast and known shared addresses. |
| `machine_id` | string |  | maxLength 1024 | Host ID read by a sensor on the host: /etc/machine-id (Linux), MachineGuid (Windows), IOPlatformUUID (macOS) |
| `scm_repo_id` | string |  | maxLength 1024 | Repository ID assigned by the source-code host (GitHub repository ID, GitLab project ID) |
| `serial_number` | string |  | maxLength 1024 | Hardware serial number |

#### AssetOwner

One owner of the asset

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `kind` | string | yes | one of: team, person, group |  |
| `ref` | string | yes | minLength 1; maxLength 256 | Name, handle or e-mail of the owner; personal data when kind is person |
| `role` | string |  | one of: technical, business, security |  |

#### AssetTechnical

Type-specific technical details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `certificate` | `CertificateTechnical` |  |  |  |
| `cloud` | `CloudTechnical` |  |  |  |
| `domain` | `DomainTechnical` |  |  |  |
| `http` | `HTTPTechnical` |  |  |  |
| `identity` | `IdentityTechnical` |  |  |  |
| `ip_address` | `IPAddressTechnical` |  |  |  |
| `repository` | `RepositoryTechnical` |  |  |  |
| `service` | `ServiceTechnical` |  |  |  |
| `web3` | `web3-asset.json` |  |  |  |

#### AssetType

Asset type. Each type has one canonical value form (spec section Canonical forms).

Type: string. one of: domain_name, ip_address, ip_range, certificate, autonomous_system, web_origin, web_application, api, mobile_app, saas_application, service, repository, package, container_image, ai_model, cloud_account, cloud_resource, storage, database, serverless, container_registry, host, container, kubernetes_cluster, kubernetes_namespace, kubernetes_workload, endpoint_device, iot_device, ot_device, network_device, vpc, subnet, load_balancer, firewall, identity, smart_contract, wallet, nft_collection, defi_protocol, token, blockchain, unclassified

#### CertificateTechnical

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `is_self_signed` | boolean |  |  |  |
| `is_wildcard` | boolean |  |  |  |
| `issuer_cn` | string |  | maxLength 1024 |  |
| `issuer_org` | string |  | maxLength 1024 |  |
| `key_algorithm` | string |  | maxLength 1024 |  |
| `key_size` | integer |  |  |  |
| `not_after` | string (date-time) |  | maxLength 64 |  |
| `not_before` | string (date-time) |  | maxLength 64 |  |
| `serial_number` | string |  | maxLength 1024 |  |
| `sha256_fingerprint` | string |  | pattern `^[0-9a-f]{64}$` | SHA-256 of the DER, 64 lowercase hex digits; equals the asset value |
| `signature_algorithm` | string |  | maxLength 1024 |  |
| `subject_alt_names` | array of string |  | items: maxLength 1024 | Subject alternative names |
| `subject_cn` | string |  | maxLength 1024 |  |

#### CloudTechnical

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `account_id` | string |  | maxLength 1024 |  |
| `arn` | string |  | maxLength 1024 |  |
| `provider` | string |  | pattern `^[a-z0-9][a-z0-9_.-]{0,63}$` | Cloud provider, an open token (aws, azure, gcp, oci, alibaba) |
| `region` | string |  | maxLength 1024 |  |
| `resource_id` | string |  | maxLength 1024 |  |
| `resource_type` | string |  | maxLength 1024 |  |
| `tags` | map of string |  |  |  |
| `zone` | string |  | maxLength 1024 |  |

#### CookieFlags

What a Set-Cookie header says about a cookie, without its value

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `is_http_only` | boolean |  |  | HttpOnly attribute |
| `is_persistent` | boolean |  |  | Expires or Max-Age set |
| `is_secure` | boolean |  |  | Secure attribute |
| `name` | string | yes | minLength 1; maxLength 128 | Cookie name (RFC 6265 token) |
| `same_site` | string |  | one of: strict, lax, none | SameSite attribute |

#### Criticality

Business criticality of the asset

Type: string. one of: critical, high, medium, low

#### DNSRecord

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string | yes | maxLength 512 |  |
| `ttl` | integer |  | minimum 0 | Time to live in seconds |
| `type` | string | yes | pattern `^[A-Z0-9]{1,16}$` | RR type mnemonic verbatim (A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV, CAA ...) |
| `value` | string | yes | maxLength 2048 |  |

#### DomainTechnical

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `dns_records` | array of `DNSRecord` |  |  |  |
| `expires_at` | string (date-time) |  | maxLength 64 |  |
| `nameservers` | array of string |  | items: maxLength 1024 |  |
| `registered_at` | string (date-time) |  | maxLength 64 |  |
| `registrar` | string |  | maxLength 1024 |  |
| `whois` | map of string |  |  |  |

#### Environment

Deployment environment; unknown is the fallback

Type: string. one of: production, staging, development, test, unknown

#### Geolocation

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `accuracy` | number |  | minimum 0 |  |
| `latitude` | number | yes | minimum -90; maximum 90 |  |
| `longitude` | number | yes | minimum -180; maximum 180 |  |

#### HTTPTechnical

What a probe saw on a web origin

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `cdn` | string |  | pattern `^[a-z0-9][a-z0-9_.-]{0,63}$` | Content delivery network in front of the origin, an open token |
| `content_type` | string |  | maxLength 255 | Content type of the response |
| `favicon_mmh3` | string |  | pattern `^-?[0-9]{1,10}$` | MurmurHash3 of the base64 favicon body, a signed 32-bit decimal |
| `jarm` | string |  | pattern `^[0-9a-f]{62}$` | JARM TLS server fingerprint (62 hex digits) |
| `redirect_url` | string |  | pattern `^[Hh][Tt][Tt][Pp][Ss]?://[^\s/?#]+[^\s]*$`; maxLength 2048 | Where the origin redirects to (http or https, redacted) |
| `security_headers` | `SecurityHeaders` |  |  |  |
| `status_code` | integer |  | minimum 100; maximum 599 | Status code of the probe's response |
| `title` | string |  | maxLength 512 | Page title (plain text) |
| `tls_version` | `TLSVersion` |  |  |  |
| `waf` | string |  | pattern `^[a-z0-9][a-z0-9_.-]{0,63}$` | Web application firewall in front of the origin, an open token |
| `web_server` | string |  | maxLength 255 | Server header (plain text) |

#### IPAddressTechnical

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `asn` | integer |  |  |  |
| `asn_org` | string |  | maxLength 1024 |  |
| `city` | string |  | maxLength 1024 |  |
| `country` | string |  | pattern `^[A-Z]{2}$` | ISO 3166-1 alpha-2 country code |
| `geolocation` | `Geolocation` |  |  |  |
| `hostname` | string |  | maxLength 1024 |  |
| `version` | integer |  | one of: 4, 6 |  |

#### IdentityHints

What a scanner observed about a host that helps match it to the same host seen by another tool. Remote observations, weaker than identifiers.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `agent_id` | string |  | maxLength 255 | Id of the scanner's agent on the host; unique per scanner, not across scanners |
| `cloud_resource_id` | string |  | maxLength 255 |  |
| `fqdn` | string |  | maxLength 255 |  |
| `mac_addresses` | array of string |  | items: maxLength 64 |  |
| `netbios_name` | string |  | maxLength 255 |  |
| `os_cpe` | string |  | maxLength 255 | CPE of the detected operating system |

#### IdentityTechnical

Technical details of an identity asset

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `kind` | string | yes | one of: user, service_account, role, group, workload | Kind of identity |
| `provider` | string |  | pattern `^[a-z0-9][a-z0-9_.-]{0,63}$` | Identity provider, an open token (aws, azure, gcp, okta, ldap) |

#### RepositoryTechnical

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `default_branch` | string |  | maxLength 1024 |  |
| `forks` | integer |  | minimum 0 |  |
| `languages` | map of integer |  |  |  |
| `last_commit_at` | string (date-time) |  | maxLength 64 |  |
| `last_commit_sha` | string |  | maxLength 1024 |  |
| `name` | string |  | maxLength 512 |  |
| `owner` | string |  | maxLength 1024 |  |
| `platform` | string |  | pattern `^[a-z0-9][a-z0-9_.-]{0,63}$` | Source-code host, an open token (github, gitlab, bitbucket, azure_devops) |
| `stars` | integer |  | minimum 0 |  |
| `url` | string |  | pattern `^[Hh][Tt][Tt][Pp][Ss]?://[^\s/?#]+[^\s]*$`; maxLength 2048 | Repository web URL (http or https) |
| `visibility` | string |  | one of: public, private, internal |  |

#### SecurityHeaders

Security posture of a web origin's response headers. Each value is the header as received, absent when the origin does not send it.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `access_control_allow_credentials` | string |  | maxLength 2048 | Access-Control-Allow-Credentials |
| `access_control_allow_origin` | string |  | maxLength 2048 | Access-Control-Allow-Origin |
| `content_security_policy` | string |  | maxLength 2048 | Content-Security-Policy |
| `cookies` | array of `CookieFlags` |  |  | Cookies the origin sets: names and flags, never values |
| `permissions_policy` | string |  | maxLength 2048 | Permissions-Policy |
| `referrer_policy` | string |  | maxLength 2048 | Referrer-Policy |
| `strict_transport_security` | string |  | maxLength 2048 | Strict-Transport-Security |
| `x_content_type_options` | string |  | maxLength 2048 | X-Content-Type-Options |
| `x_frame_options` | string |  | maxLength 2048 | X-Frame-Options |

#### ServiceTechnical

The one shape of a network service: technical details of a service asset (value host:port/transport), linked from its host or address by an exposes relationship

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `app_protocol` | string |  | pattern `^[a-z0-9]([a-z0-9-]{0,13}[a-z0-9])?$`; maxLength 1024 | Application protocol, an IANA service name (http, https, ssh, smtp, domain, microsoft-ds ...) |
| `auth_methods` | array of string |  | items: maxLength 64 | Authentication methods offered (password, publickey) |
| `banner` | string |  | maxLength 4096 | Banner as the probe saw it (plain text) |
| `cpe` | string |  | maxLength 1024 | CPE 2.3 name |
| `details` | map of string |  |  | Protocol-dependent details as strings (SSH algorithms, SMTP extensions) |
| `extra_info` | string |  | maxLength 4096 | Extra information from the probe (plain text) |
| `has_anonymous_access` | boolean |  |  | Anonymous access is allowed |
| `has_default_credentials` | boolean |  |  | Default credentials work |
| `is_auth_required` | boolean |  |  | Authentication is required |
| `is_tls` | boolean |  |  | The service speaks TLS |
| `port` | integer | yes | minimum 1; maximum 65535 | Port number |
| `product` | string |  | maxLength 1024 | Product name (OpenSSH, nginx) |
| `response_time_ms` | integer |  | minimum 0 | Response time in milliseconds |
| `state` | string |  | one of: open, closed, filtered | Port state |
| `tls_version` | `TLSVersion` |  |  |  |
| `transport` | string | yes | one of: tcp, udp, sctp | Transport protocol |
| `version` | string |  | maxLength 1024 | Product version |

#### TLSVersion

TLS or SSL protocol version

Type: string. one of: ssl3, tls1.0, tls1.1, tls1.2, tls1.3

#### Technology

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `categories` | array of string |  | items: maxLength 64 |  |
| `confidence` | integer |  | minimum 0; maximum 100 |  |
| `cpe` | string |  | maxLength 255 | CPE 2.3 name |
| `name` | string | yes | minLength 1; maxLength 128 |  |
| `version` | string |  | maxLength 64 |  |

### CTIS Finding (`finding.json`)

A security finding on one asset of the report

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `asset_ref` | `DocumentRef` | yes |  | The asset of this report the finding is on |
| `attachments` | array of `Attachment` |  |  | Relevant artifacts or evidence files |
| `attack_technique_ids` | array of string |  | items: pattern `^T[0-9]{4}(\.[0-9]{3})?$`; maxLength 1024 | MITRE ATT&CK techniques the finding enables (T1190, T1595.002) |
| `baseline_state` | string |  | one of: new, unchanged, updated, absent | Status relative to previous scan (SARIF baselineState) |
| `capec_ids` | array of string |  | items: pattern `^CAPEC-[1-9][0-9]{0,5}$` | CAPEC attack pattern ids |
| `category` | string |  | maxLength 1024 | Finding category/class |
| `compliance` | `ComplianceDetails` |  |  |  |
| `confidence` | integer |  | minimum 0; maximum 100 | Confidence score (0-100) |
| `correlation_id` | string |  | maxLength 1024 | Groups logically identical results across runs |
| `data_flow` | `DataFlow` |  |  |  |
| `dependency_ref` | `DocumentRef` |  |  | The dependency of this report the finding affects |
| `description` | string |  | maxLength 32768 | Detailed description |
| `evidence_items` | array of `evidence-item.json` |  |  | Typed evidence of the finding; sensitive values only inside marked spans |
| `exposure` | `FindingExposure` |  |  |  |
| `extensions` | `Extensions` |  |  |  |
| `fingerprint` | string |  | maxLength 1024 | The producer's fingerprint (recipe ctis-fp/2). Receivers recompute it and never trust it as a key. |
| `first_seen_at` | string (date-time) |  | maxLength 64 |  |
| `hosted_viewer_uri` | string |  | pattern `^[Hh][Tt][Tt][Pp][Ss]?://[^\s/?#]+[^\s]*$`; maxLength 2048 | Hosted viewer URL (SARIF hostedViewerUri), http or https |
| `id` | `DocumentRef` |  |  | Document-local reference |
| `kind` | string |  | one of: not_applicable, pass, fail, review, open, informational | Evaluation state of the finding (SARIF kind) |
| `last_seen_at` | string (date-time) |  | maxLength 64 |  |
| `location` | `FindingLocation` |  |  |  |
| `message` | string |  | maxLength 32768 | Primary message to display (the main human-readable finding message). If not set, title will be used as the message. |
| `misconfiguration` | `MisconfigurationDetails` |  |  |  |
| `native` | `NativeIdentity` |  |  |  |
| `network` | `NetworkLocation` |  |  |  |
| `occurrence_count` | integer |  | minimum 1 | Number of times this result was observed |
| `partial_fingerprints` | map of string |  |  | Contributing identity components for fingerprint calculation |
| `properties` | `Properties` |  |  |  |
| `rank` | number |  | minimum 0; maximum 100 | Priority/importance score (0-100, SARIF rank) |
| `references` | array of string |  | items: pattern `^[Hh][Tt][Tt][Pp][Ss]?://[^\s/?#]+[^\s]*$`; maxLength 2048 | References (http or https URLs). Receivers never fetch them. |
| `related_locations` | array of `FindingLocation` |  |  | Additional locations related to this finding |
| `remediation` | `Remediation` |  |  |  |
| `rule_id` | string |  | maxLength 1024 | Rule/check ID that detected this finding |
| `rule_name` | string |  | maxLength 1024 | Rule name |
| `scores` | array of `Score` |  |  | Every score of the finding with its source and date (CVSS v3.1 and v4.0 together, vendor scores, EPSS, SSVC). vulnerability.cvss_* stays the primary CVSS score. |
| `secret` | `SecretDetails` |  |  |  |
| `severity` | `Severity` | yes |  |  |
| `source_extra` | map of string |  |  | Source fields no CTIS member holds, as strings. At most 64 entries, keys of 128 characters, values of 4096, 32 KiB in all (the total is checked by receivers). |
| `source_lifecycle` | `SourceLifecycle` |  |  |  |
| `source_refs` | array of `SourceRef` |  |  | The producer's own identifiers of the finding in its own systems |
| `stacks` | array of `StackTrace` |  |  | Call stacks relevant to the finding |
| `status` | `FindingStatus` |  |  |  |
| `subcategories` | array of string |  | items: maxLength 1024 | Subcategories (e.g., audit, vuln, secure default) |
| `suppression` | `Suppression` |  |  |  |
| `tags` | array of string |  | items: maxLength 1024 |  |
| `technique` | `Technique` |  |  |  |
| `title` | string | yes | maxLength 1024 | Short title |
| `tool` | `Tool` |  |  |  |
| `type` | `FindingType` | yes |  |  |
| `validation` | `FindingValidation` |  |  |  |
| `vex` | `VEX` |  |  |  |
| `vulnerability` | `VulnerabilityDetails` |  |  |  |
| `vulnerability_classes` | array of string |  | items: maxLength 1024 | Vulnerability classes (e.g., SQL Injection, XSS) |
| `web` | `WebLocation` |  |  |  |
| `web3` | `web3-finding.json` |  |  |  |
| `work_item_uris` | array of string |  | items: pattern `^[Hh][Tt][Tt][Pp][Ss]?://[^\s/?#]+[^\s]*$`; maxLength 2048 | Associated tickets (SARIF workItemUris), http or https |

#### Advisory

A vendor advisory that addresses the finding (an id or a url)

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string |  | maxLength 128 |  |
| `source` | string |  | maxLength 64 |  |
| `url` | string |  | pattern `^[Hh][Tt][Tt][Pp][Ss]?://[^\s/?#]+[^\s]*$`; maxLength 2048 | Advisory URL (http or https) |

#### ArtifactLocation

Location of an artifact (SARIF artifactLocation)

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `index` | integer |  | minimum 0 | Index within the producer's artifacts list |
| `uri` | string |  | maxLength 2048 | Artifact URI as the source tool wrote it (a relative path or a URL); never fetched |
| `uri_base_id` | string |  | maxLength 1024 | Base URI id the uri is relative to |

#### Attachment

Artifact or evidence attachment (SARIF attachment)

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `artifact_location` | `ArtifactLocation` |  |  |  |
| `description` | string |  | maxLength 32768 |  |
| `regions` | array of `FindingLocation` |  |  | Relevant regions within the artifact |

#### CommitInfo

The commit that introduced the finding. Author fields are personal data; producers SHOULD omit author_email unless asked to send it.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `author` | string |  | maxLength 256 | Commit author |
| `author_email` | string |  | maxLength 320 | Commit author e-mail |
| `committed_at` | string (date-time) |  | maxLength 64 | Commit time |
| `sha` | string |  | pattern `^[0-9a-fA-F]{7,64}$` | Commit SHA |

#### ComplianceDetails

The control a compliance finding evaluates. The result is the finding's kind (pass, fail, review, not_applicable).

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `control_description` | string |  | maxLength 16384 |  |
| `control_id` | string |  | maxLength 1024 |  |
| `control_name` | string |  | maxLength 1024 |  |
| `framework` | `ComplianceFramework` |  |  |  |
| `framework_version` | string |  | maxLength 1024 |  |

#### ComplianceFramework

Compliance framework, an open token. Registry of known values: pci_dss, hipaa, soc2, iso27001, nist_csf, nist_800_53, cis, gdpr, fedramp, owasp_asvs.

Type: string. pattern `^[a-z0-9][a-z0-9_.-]{0,63}$`

#### ContainerLayer

Container layer information for image scans

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `diff_id` | string |  | maxLength 1024 | Layer diff ID |
| `digest` | string |  | maxLength 1024 | Layer digest (sha256:...) |

#### DataFlow

Taint tracking data flow from source to sink (SARIF codeFlows)

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `call_path` | array of string |  | items: maxLength 1024 | Call graph path (function names in order) |
| `confidence` | integer |  | minimum 0; maximum 100 | Flow confidence score (0-100) |
| `intermediates` | array of `DataFlowLocation` |  |  | Intermediate propagation steps |
| `is_cross_file` | boolean |  |  | Whether data flows across multiple files |
| `is_interprocedural` | boolean |  |  | Whether flow crosses function boundaries |
| `is_tainted` | boolean |  |  | Whether data is still tainted at the sink (false if properly sanitized) |
| `sanitizers` | array of `DataFlowLocation` |  |  | Sanitizer locations (where data is cleaned/escaped) |
| `sinks` | array of `DataFlowLocation` |  |  | Taint sink locations (where data reaches dangerous function) |
| `sources` | array of `DataFlowLocation` |  |  | Taint source locations (where untrusted data enters) |
| `summary` | string |  | maxLength 16384 | Human-readable summary of the flow |
| `taint_type` | string |  | one of: user_input, file_read, env_var, network, database, header, cookie, session, argv, external | Type of taint origin |

#### DataFlowLocation

Location in data flow trace (SARIF threadFlowLocation)

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `called_function` | string |  | maxLength 1024 | For function calls: the function being called |
| `class_name` | string |  | maxLength 1024 | Class/struct name (if applicable) |
| `column` | integer |  | minimum 1 | Column number (1-indexed) |
| `content` | string |  | maxLength 16384 | Code content at this location |
| `end_column` | integer |  | minimum 1 | End column |
| `end_line` | integer |  | minimum 1 | End line for multi-line spans |
| `function` | string |  | maxLength 1024 | Function/method name containing this location |
| `index` | integer |  | minimum 0 | Step index in the flow (0-indexed) |
| `label` | string |  | maxLength 1024 | Variable or expression name being tracked |
| `line` | integer |  | minimum 1 | Line number (1-indexed) |
| `module` | string |  | maxLength 1024 | Module/namespace |
| `notes` | string |  | maxLength 4096 | Notes for human understanding |
| `operation` | string |  | maxLength 1024 | Operation performed: assignment, call, return, parameter, concat, etc. |
| `parameter_index` | integer |  | minimum 0 | For parameters: the parameter index (0-indexed) |
| `path` | string |  | maxLength 4096 | File path |
| `taint_state` | string |  | one of: tainted, sanitized, unknown | Taint state at this location |
| `transformation` | string |  | maxLength 1024 | Transformation applied: encode, decode, escape, hash, encrypt, etc. |
| `type` | string |  | one of: source, sink, propagator, sanitizer, transform | Location type in the flow |

#### FindingExposure

CTEM exposure information for a finding

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `attack_prerequisites` | string |  | maxLength 4096 | Prerequisites for exploitation: auth_required, mfa_required, local_access, etc. |
| `is_internet_accessible` | boolean |  |  | Reachable from the internet. Absent means unknown. |
| `is_network_accessible` | boolean |  |  | Reachable from a network. Absent means unknown. |
| `vector` | string |  | one of: network, adjacent, local, physical | Attack vector (CVSS AV vocabulary) |

#### FindingLocation

Location information for code-based findings

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `branch` | string |  | maxLength 1024 | Git branch |
| `commit` | `CommitInfo` |  |  |  |
| `context_snippet` | string |  | maxLength 65536 | Broader context snippet |
| `context_start_line` | integer |  | minimum 1 | Line where context_snippet starts |
| `end_column` | integer |  | minimum 1 |  |
| `end_line` | integer |  | minimum 1 |  |
| `logical_location` | `LogicalLocation` |  |  |  |
| `path` | string |  | maxLength 4096 | File path |
| `snippet` | string |  | maxLength 65536 | Code snippet |
| `start_column` | integer |  | minimum 1 |  |
| `start_line` | integer |  | minimum 1 | Start line (1-indexed) |

#### FindingStatus

Finding status

Type: string. one of: open, resolved, suppressed, false_positive, accepted_risk, in_progress

#### FindingType

Finding type. Web3 is a profile (the web3 block), not a type.

Type: string. one of: vulnerability, weakness, secret, misconfiguration, compliance, exposure, malware, license

#### FindingValidation

Whether and how the finding was shown to be exploitable: pentest, attack simulation, retest, manual review

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `evidence_refs` | array of `DocumentRef` |  |  | Evidence of the validation: the content_sha256 of an evidence item (sha256:<hex>) or an attachment id |
| `method` | string |  | one of: pentest, bas, automated_exploit, retest, manual_review |  |
| `notes` | string |  | maxLength 4096 |  |
| `status` | string | yes | one of: exploited, not_exploited, blocked, detected, not_reproducible, not_tested |  |
| `validated_at` | string (date-time) |  | maxLength 64 |  |
| `validator` | string |  | maxLength 256 | Who validated: a person, team or tool name; personal data |

#### FixRegex

Regex-based auto-fix pattern (for tools like Semgrep)

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `count` | integer |  | minimum 0 | Number of replacements to make (0 = all) |
| `regex` | string |  | maxLength 4096 | Regular expression pattern to match |
| `replacement` | string |  | maxLength 4096 | Replacement string (may contain capture group references like $1, $2) |

#### LogicalLocation

Logical location within code structure

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `fully_qualified_name` | string |  | maxLength 1024 | Fully qualified name |
| `kind` | string |  | one of: function, method, class, module, namespace, type, property | Symbol kind |
| `name` | string |  | maxLength 512 | Symbol name (function, class, method) |
| `parent_index` | integer |  | minimum 0 | Index of the enclosing logical location (SARIF logicalLocation.parentIndex) |

#### MisconfigurationDetails

Misconfiguration-specific details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `actual` | string |  | maxLength 4096 |  |
| `cause` | string |  | maxLength 4096 |  |
| `expected` | string |  | maxLength 4096 |  |
| `namespace` | string |  | maxLength 1024 | Policy namespace (builtin.aws.s3) |
| `policy_id` | string |  | maxLength 1024 |  |
| `policy_name` | string |  | maxLength 1024 |  |
| `provider` | string |  | maxLength 1024 | Provider, an open token (aws, azure, gcp, kubernetes) |
| `query` | string |  | maxLength 4096 | Rego query path |
| `resource_name` | string |  | maxLength 1024 |  |
| `resource_type` | string |  | maxLength 1024 |  |
| `service` | string |  | maxLength 1024 | Service name (S3, EC2, IAM) |

#### NativeIdentity

The finding as the source tool names it. The normalized values stay in severity, status and source_lifecycle.state.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `detection_type` | string |  | one of: confirmed, potential, info | Whether the tool confirmed the issue, only suspects it, or gathered information |
| `family` | string |  | maxLength 256 | Tool family or category of the check |
| `instance_id` | string |  | maxLength 256 | Tool id of this occurrence (DefectDojo unique_id_from_tool, a detection id) |
| `is_credentialed` | boolean |  |  | The scan was authenticated on the target. Absent means unknown. |
| `raw_ref` | string |  | maxLength 1024 | Where the raw record can be found again (a URL into the source, a locator in the imported file). Receivers never fetch it. |
| `scheme` | string |  | pattern `^[a-z0-9][a-z0-9_.-]{0,63}$` | Vocabulary of the native values, an open token. Known values: nessus, qualys, defectdojo, sarif, other |
| `severity` | string |  | maxLength 64 | Severity exactly as the tool reported it ("4", "5", "High", "error") |
| `status` | string |  | maxLength 64 | Status exactly as the tool reported it ("Re-Opened", "fixed", "risk_accepted") |
| `vuln_id` | string |  | maxLength 256 | Tool id of the vulnerability or check: Nessus plugin ID, Qualys QID, DefectDojo vuln_id_from_tool, SARIF rule id |

#### NetworkLocation

Where a network/host finding was observed (Nessus/Tenable and other network scanners)

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `app_protocol` | string |  | pattern `^[a-z0-9]([a-z0-9-]{0,13}[a-z0-9])?$`; maxLength 1024 | Application protocol, an IANA service name |
| `host` | string |  | maxLength 253 | Host (canonical IP address or domain name); optional when the finding's asset is the host |
| `port` | integer |  | minimum 0; maximum 65535 | Port (0: not port-specific) |
| `transport` | string |  | one of: tcp, udp, sctp | Transport protocol |

#### Remediation

The one remediation object of a finding

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `advisories` | array of `Advisory` |  |  | Vendor advisories that address the finding |
| `effort` | string |  | one of: trivial, low, medium, high | Effort of the fix |
| `estimated_minutes` | integer |  | minimum 0; maximum 10000000 | Estimated time to fix in minutes |
| `fix_code` | string |  | maxLength 65536 | Replacement code |
| `fix_regex` | `FixRegex` |  |  |  |
| `is_auto_fixable` | boolean |  |  | The tool can apply the fix itself |
| `is_fix_available` | boolean |  |  | A fix exists. Absent means unknown; false means verified no fix. |
| `patch_published_at` | string (date-time) |  | maxLength 64 | When the vendor published the patch |
| `recommendation` | string |  | maxLength 16384 | Short recommendation (plain text) |
| `solution_type` | string |  | one of: vendor_fix, workaround, mitigation, no_fix_planned, none_available, config_change, upgrade | Kind of fix: the CSAF remediation categories (vendor_fix, workaround, mitigation, no_fix_planned, none_available) plus config_change and upgrade |
| `steps` | array of string |  | items: maxLength 4096 | Fix steps |

#### Score

One score with its source and date. cvss needs version and a value or a vector; cvss and vpr values are 0-10, epss and epss_percentile 0-1 (FIRST fractions); ssvc has no value and needs a vector or a label.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `as_of` | string (date-time) |  | maxLength 64 |  |
| `label` | string |  | maxLength 32 | Qualitative rating as the source states it |
| `source` | string |  | maxLength 64 | Who assigned it: nvd, ghsa, vendor, tenable, qualys, first, cisa, ... |
| `system` | string | yes | one of: cvss, epss, epss_percentile, ssvc, vendor |  |
| `value` | number |  |  |  |
| `vector` | string |  | maxLength 512 |  |
| `version` | string |  | maxLength 32 |  |

#### SecretDetails

Secret-specific details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `age_days` | integer |  | minimum 0 | Age of the secret in days, if known |
| `commit_count` | integer |  | minimum 0 | Number of commits the secret appears in |
| `entropy` | number |  | minimum 0 |  |
| `expires_at` | string (date-time) |  | maxLength 64 | When the secret expires |
| `is_history_only` | boolean |  |  | Secret only exists in git history (not current code) |
| `is_revoked` | boolean |  |  |  |
| `is_valid` | boolean |  |  | Verification result; absent means not verified |
| `length` | integer |  | minimum 1 |  |
| `masked_value` | string |  | maxLength 256 | Masked value (first/last chars) |
| `revoked_at` | string (date-time) |  | maxLength 64 | When the secret was revoked |
| `rotation_due_at` | string (date-time) |  | maxLength 64 | When secret rotation is due |
| `scopes` | array of string |  | items: maxLength 1024 | API scopes/permissions associated with the secret |
| `service` | string |  | maxLength 1024 | Service the secret belongs to, an open token (aws, github, stripe) |
| `type` | string |  | one of: api_key, password, token, certificate, private_key, oauth, jwt, ssh_key, aws_key, gcp_key, azure_key, generic_secret, database_credential, encryption_key |  |
| `verified_at` | string (date-time) |  | maxLength 64 | When validity was checked |

#### Severity

Severity level. unknown: the source gave none that maps; also the fallback for an unknown value

Type: string. one of: critical, high, medium, low, info, unknown

#### SourceLifecycle

The finding's history as the source tracks it, separate from the receiver's own lifecycle

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `first_found_at` | string (date-time) |  | maxLength 64 |  |
| `last_fixed_at` | string (date-time) |  | maxLength 64 |  |
| `last_found_at` | string (date-time) |  | maxLength 64 |  |
| `state` | string |  | one of: new, active, reopened, fixed |  |
| `times_found` | integer |  | minimum 0; maximum 1000000000 |  |

#### StackFrame

Single frame in a call stack

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `location` | `FindingLocation` |  |  |  |
| `module` | string |  | maxLength 1024 | Module/library name |
| `parameters` | array of string |  | items: maxLength 1024 | Function parameters |
| `thread_id` | integer |  |  |  |

#### StackTrace

Call stack trace (SARIF stack)

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `frames` | array of `StackFrame` |  |  | Stack frames from innermost to outermost |
| `message` | string |  | maxLength 32768 | Stack description |

#### Suppression

Finding suppression information (follows SARIF suppression: kind + status)

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `expires_at` | string (date-time) |  | maxLength 64 | When suppression expires |
| `justification` | string |  | maxLength 4096 | Detailed justification |
| `kind` | string |  | one of: in_source, external | in_source: suppressed by a comment or annotation in the code; external: suppressed outside the code (a baseline file, a scanner console) |
| `reason` | string |  | maxLength 1024 | Short reason code or phrase (false_positive, test_code, risk_accepted, ...) |
| `status` | string |  | one of: accepted, under_review, rejected | Review state of the suppression |
| `suppressed_at` | string (date-time) |  | maxLength 64 |  |
| `suppressed_by` | string |  | maxLength 1024 | Who suppressed (user/email) |

#### ThreatSignal

A threat assertion by a named source at a date. Receivers SHOULD prefer their own intelligence

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `as_of` | string (date-time) |  | maxLength 64 | When the source asserted it |
| `due_on` | string |  | pattern `^[0-9]{4}-(0[1-9]\|1[0-2])-(0[1-9]\|[12][0-9]\|3[01])$`; maxLength 1024 | Remediation due date (YYYY-MM-DD), such as a KEV due date |
| `ref` | string |  | maxLength 2048 | External reference (catalog id or URL); never fetched |
| `source` | string | yes | minLength 1; maxLength 64 | Who asserts it (a catalog, a feed, the producer) |
| `type` | string | yes | one of: kev, exploited_in_wild, public_exploit, ransomware_use, weaponized |  |

#### VEX

Exploitability statement (CSAF / OpenVEX vocabulary). not_affected needs a justification or a statement; a justification is only for not_affected.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `as_of` | string (date-time) |  | maxLength 64 |  |
| `justification` | string |  | one of: component_not_present, vulnerable_code_not_present, vulnerable_code_not_in_execute_path, vulnerable_code_cannot_be_controlled_by_adversary, inline_mitigations_already_exist |  |
| `native_justification` | string |  | maxLength 64 | The justification as the source document states it (a CycloneDX analysis.justification) |
| `source` | string |  | maxLength 512 | Who made the statement: a document id or URL, a vendor, a team |
| `statement` | string |  | maxLength 4096 | Impact or action statement, plain text |
| `status` | string | yes | one of: not_affected, affected, fixed, under_investigation |  |

#### VulnDataSource

Vulnerability data source information

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string |  | pattern `^[a-z0-9][a-z0-9_.-]{0,63}$` | Data source, an open token (nvd, ghsa, osv) |
| `name` | string |  | maxLength 512 | Data source name |
| `url` | string |  | pattern `^[Hh][Tt][Tt][Pp][Ss]?://[^\s/?#]+[^\s]*$`; maxLength 2048 | Data source URL (http or https) |

#### VulnerabilityDetails

Vulnerability-specific details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `affected_version_range` | string |  | maxLength 1024 | Affected version range, e.g. ">=1.0.0, <1.2.5" |
| `cpe` | string |  | maxLength 1024 |  |
| `cwe_ids` | array of string |  | items: pattern `^CWE-[1-9][0-9]{0,5}$` | All related CWE identifiers |
| `data_source` | `VulnDataSource` |  |  |  |
| `dependency_path` | array of string |  | items: maxLength 1024 | Dependency path from root to vulnerable package |
| `fixed_versions` | array of string |  | items: maxLength 1024 | All versions that fix the vulnerability |
| `ids` | array of `VulnerabilityID` |  |  | Every id of the vulnerability with its namespace (CVE, GHSA, OSV, vendor) |
| `installed_version` | string |  | maxLength 1024 | The installed (affected) version of the package |
| `is_direct` | boolean |  |  | The vulnerable package is a direct dependency (not transitive) |
| `layer` | `ContainerLayer` |  |  |  |
| `modified_at` | string (date-time) |  | maxLength 64 | Vulnerability last modified date |
| `owasp_ids` | array of string |  | items: pattern `^A(0[1-9]\|10):20[0-9]{2}$` | OWASP Top 10 identifiers (e.g., A01:2021, A03:2021) |
| `package_name` | string |  | maxLength 1024 | Affected package name |
| `published_at` | string (date-time) |  | maxLength 64 | Vulnerability published date |
| `purl` | string |  | maxLength 1024 | Package URL (purl spec) |
| `threat_signals` | array of `ThreatSignal` |  |  | Threat assertions with source and date |

#### VulnerabilityID

One identifier of a vulnerability with its namespace

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string | yes | pattern `^[A-Za-z0-9][A-Za-z0-9._:/+\-]*$`; maxLength 128 |  |
| `source` | string |  | maxLength 64 | Issuer of a vendor id (redhat, microsoft, ...) |
| `type` | string | yes | one of: cve, ghsa, osv, vendor |  |

#### WebLocation

Where on a web origin the finding was observed; the URL carries no query value, user info or fragment

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `endpoint_ref` | `DocumentRef` |  |  | The endpoint of this report the finding is on |
| `method` | string |  | one of: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE, CONNECT, ANY |  |
| `parameter` | `WebParameter` |  |  |  |
| `request_ref` | `DocumentRef` |  |  | Reference to the evidence item that holds the request |
| `status_code` | integer |  | minimum 0; maximum 599 |  |
| `url` | string | yes | minLength 1; maxLength 2048 |  |

#### WebParameter

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `location` | `ParamLocation` | yes |  |  |
| `name` | string | yes | minLength 1; maxLength 128 |  |

### CTIS Dependency (`dependency.json`)

Software component or library dependency (SBOM)

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `asset_ref` | `DocumentRef` |  |  | The asset of this report the component was found in |
| `depends_on` | array of `DocumentRef` |  |  | Ids of the dependencies of this report this one depends on |
| `extensions` | `Extensions` |  |  |  |
| `id` | `DocumentRef` |  |  | Document-local reference |
| `licenses` | array of string |  | items: maxLength 1024 | List of licenses |
| `locations` | array of `DependencyLocation` |  |  | All locations where this dependency is defined |
| `name` | string | yes | maxLength 512 | Component name |
| `properties` | `Properties` |  |  |  |
| `purl` | string |  | maxLength 1024 | Package URL (PURL) identifier |
| `relationship` | string |  | one of: root, direct, transitive | Place in the dependency graph |
| `source_id` | string |  | maxLength 1024 | The producer's own id of the component (a CycloneDX bom-ref, an SPDX element id) |
| `type` | string |  | one of: application, framework, library, container, platform, operating-system, device, device-driver, firmware, file, machine-learning-model, data, cryptographic-asset | Component type (CycloneDX component types, verbatim) |
| `version` | string |  | maxLength 1024 | Component version. Recommended; omit only when the version is genuinely unknown. |

#### DependencyLocation

A place where the dependency is declared

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `end_column` | integer |  | minimum 1 | End column number |
| `end_line` | integer |  | minimum 1 | End line number |
| `path` | string |  | maxLength 4096 | File path |
| `start_column` | integer |  | minimum 1 | Start column number |
| `start_line` | integer |  | minimum 1 | Start line number |

### CTIS Endpoint (`endpoint.json`)

One method and path a web origin serves, as a tool saw it. Parameters are named, never valued: a value member is refused.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `auth` | `EndpointAuth` |  |  |  |
| `content_type` | string |  | maxLength 255 |  |
| `extensions` | `Extensions` |  |  |  |
| `id` | `DocumentRef` |  |  | Document-local reference, named by finding.web.endpoint_ref |
| `kind` | `EndpointKind` |  |  |  |
| `method` | string |  | one of: , GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE, CONNECT, ANY | HTTP method; ANY or absent when unknown |
| `origin` | string | yes | maxLength 2048 | Normalised origin: scheme://host[:port] |
| `origin_ref` | `DocumentRef` |  |  | The web_origin asset of the origin in this report |
| `params` | array of `EndpointParam` |  |  |  |
| `parent_url` | string |  | maxLength 2048 | Page the endpoint was found on, redacted (no query value, user info or fragment) |
| `path` | string | yes | pattern `^/[^?#]*$`; maxLength 2048 | Concrete path without query or fragment |
| `source` | `EndpointSource` |  |  |  |
| `status_code` | integer |  | minimum 0; maximum 599 |  |
| `technologies` | array of `Technology` |  |  |  |
| `template` | string |  | pattern `^/[^?#]*$`; maxLength 2048 | Producer's path template; receivers recompute it |

#### EndpointAuth

Type: string. one of: none, required, redirect_login, unknown

#### EndpointKind

Type: string. one of: page, api, script, form, graphql, websocket, static, other

#### EndpointParam

A parameter the endpoint takes: a name and hints, never a value

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `is_required` | boolean |  |  |  |
| `location` | `ParamLocation` | yes |  |  |
| `name` | string | yes | minLength 1; maxLength 128 |  |
| `type_hint` | string |  | pattern `^[a-z][a-z0-9_]{0,31}$` |  |

#### EndpointSource

Type: string. one of: crawl, js, sitemap, robots, spec, har, archive, dast, probe, import

#### ParamLocation

Type: string. one of: query, path, header, cookie, form, json, multipart, graphql_arg

### CTIS Evidence Item (`evidence-item.json`)

One piece of typed evidence of a finding. Known kinds are validated whole; another kind is validated by its envelope and carries its own fields in data. Sensitive values may appear only inside the spans listed in sensitive, which receivers mask before display or forwarding.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `artifact` | `EvidenceArtifact` |  |  |  |
| `captured_at` | string (date-time) |  | maxLength 64 |  |
| `command` | string |  | maxLength 8192 |  |
| `content_sha256` | string |  | pattern `^sha256:[0-9a-f]{64}$` | Over the item as captured, before masking or truncation |
| `data` | object (free-form) |  |  | Fields of a kind this version of the schema does not know |
| `exit_code` | integer |  |  |  |
| `extracted` | array of string |  | items: maxLength 1024 |  |
| `file` | `EvidenceFile` |  |  |  |
| `http` | `EvidenceHTTP` |  |  |  |
| `kind` | string | yes | pattern `^[a-z0-9][a-z0-9_.-]{0,63}$` | http_exchange, raw_text, screenshot, file_excerpt, command_output, curl, or a newer kind |
| `label` | string |  | maxLength 200 |  |
| `match` | array of `EvidenceMatch` |  |  |  |
| `protocol` | string |  | pattern `^[a-z][a-z0-9_-]{0,31}$` |  |
| `sensitive` | array of `SensitiveSpan` |  |  |  |
| `text` | string |  | maxLength 65536 |  |
| `version` | integer |  | minimum 0; maximum 1000 |  |

#### EvidenceArtifact

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `media_type` | string | yes | maxLength 127 |  |
| `ref` | string |  | maxLength 256 |  |
| `sha256` | string | yes | pattern `^sha256:[0-9a-f]{64}$` |  |
| `size` | integer |  | minimum 0 |  |

#### EvidenceFile

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `end_line` | integer |  | minimum 0 |  |
| `path` | string | yes | minLength 1; maxLength 4096 |  |
| `snippet` | string |  | maxLength 65536 |  |
| `start_line` | integer |  | minimum 0 |  |

#### EvidenceHTTP

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `request` | `EvidenceRequest` |  |  |  |
| `response` | `EvidenceResponse` |  |  |  |

#### EvidenceHeader

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string | yes | pattern `^[!#$%&'*+.^_`\|~0-9A-Za-z-]{1,256}$` |  |
| `value` | string | yes | maxLength 8192 |  |

#### EvidenceMatch

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `end` | integer |  | minimum 0 |  |
| `location` | string | yes | one of: request, response |  |
| `matcher` | string |  | maxLength 128 |  |
| `part` | string | yes | one of: status, header, body, url |  |
| `start` | integer |  | minimum 0 |  |

#### EvidenceRequest

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `body` | string |  | maxLength 65536 |  |
| `body_encoding` | string |  | one of: , text, base64 |  |
| `body_size` | integer |  | minimum 0 |  |
| `body_truncated` | boolean |  |  |  |
| `headers` | array of `EvidenceHeader` |  |  |  |
| `http_version` | string |  | pattern `^(HTTP/[0-9](\.[0-9])?)?$`; maxLength 1024 |  |
| `method` | string |  | pattern `^([A-Za-z][A-Za-z0-9-]{0,31})?$`; maxLength 1024 |  |
| `url` | string |  | maxLength 8192 |  |

#### EvidenceResponse

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `body` | string |  | maxLength 65536 |  |
| `body_encoding` | string |  | one of: , text, base64 |  |
| `body_size` | integer |  | minimum 0 |  |
| `body_truncated` | boolean |  |  |  |
| `headers` | array of `EvidenceHeader` |  |  |  |
| `http_version` | string |  | pattern `^(HTTP/[0-9](\.[0-9])?)?$`; maxLength 1024 |  |
| `reason` | string |  | maxLength 128 |  |
| `status` | integer |  | minimum 0; maximum 599 |  |
| `time_ms` | integer |  | minimum 0 |  |

#### SensitiveSpan

A secret or personal value inside the item: the string at pointer (a JSON pointer into the item), whole or the byte range [start, end)

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `end` | integer |  | minimum 0 |  |
| `kind` | string |  | pattern `^[a-z][a-z0-9_]{0,31}$` |  |
| `pointer` | string | yes | pattern `^(/([^~/]\|~[01])*)+$`; maxLength 256 |  |
| `start` | integer |  | minimum 0 |  |

### Web3 Asset Technical Details (`web3-asset.json`)

Web3 profile: technical details of web3 assets. Vendor and product vocabularies are open tokens.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `address` | string |  | pattern `^0x[a-fA-F0-9]{40}$` | Contract/wallet address (EVM format) |
| `chain` | string |  | one of: ethereum, polygon, bsc, arbitrum, optimism, avalanche, fantom, base, solana, near, cosmos | Blockchain network name |
| `chain_id` | integer |  |  | EVM Chain ID (1=mainnet, 137=polygon, 56=bsc, etc.) |
| `contract` | `SmartContractDetails` |  |  |  |
| `defi` | `DeFiDetails` |  |  |  |
| `network_type` | string |  | one of: mainnet, testnet, devnet | Network type |
| `nft` | `NFTCollectionDetails` |  |  |  |
| `token` | `TokenDetails` |  |  |  |
| `wallet` | `WalletDetails` |  |  |  |

#### AuditReport

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `auditor` | string | yes | pattern `^[a-z0-9][a-z0-9_.-]{0,63}$` | Open token (vendor neutral since 2.0). Known values: trail_of_bits, openzeppelin, consensys_diligence, certik, hacken, peckshield, slowmist, quantstamp, cyfrin |
| `critical_count` | integer |  | minimum 0 |  |
| `high_count` | integer |  | minimum 0 |  |
| `low_count` | integer |  | minimum 0 |  |
| `medium_count` | integer |  | minimum 0 |  |
| `published_at` | string (date-time) |  | maxLength 64 | When the audit report was published |
| `report_url` | string |  | pattern `^[Hh][Tt][Tt][Pp][Ss]?://[^\s/?#]+[^\s]*$`; maxLength 2048 |  |
| `scope` | string |  | maxLength 1024 |  |

#### CoreContract

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `address` | string | yes | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `name` | string | yes | maxLength 512 |  |
| `role` | string |  | one of: router, factory, vault, controller, oracle, governance, timelock |  |

#### DeFiDetails

DeFi protocol-specific details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `audit_reports` | array of `AuditReport` |  |  |  |
| `bug_bounty_platform` | string |  | pattern `^[a-z0-9][a-z0-9_.-]{0,63}$` | Open token (vendor neutral since 2.0). Known values: immunefi, hackerone, code4rena, sherlock, hats |
| `core_contracts` | array of `CoreContract` |  |  |  |
| `governance_token` | string |  | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `has_bug_bounty` | boolean |  |  |  |
| `is_audited` | boolean |  |  |  |
| `is_paused` | boolean |  |  |  |
| `max_bounty_usd` | number |  | minimum 0 |  |
| `protocol_name` | string |  | maxLength 1024 |  |
| `protocol_type` | string |  | one of: dex, lending, yield, bridge, derivatives, insurance, staking, liquid_staking |  |
| `supported_chains` | array of string |  | items: maxLength 1024 |  |
| `timelock_seconds` | integer |  | minimum 0 | Governance timelock in seconds |
| `tvl_usd` | number |  | minimum 0 |  |
| `version` | string |  | maxLength 1024 |  |

#### NFTCollectionDetails

NFT collection-specific details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `base_uri` | string |  | maxLength 1024 |  |
| `creator` | string |  | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `floor_price` | string |  | maxLength 1024 |  |
| `floor_price_usd` | number |  | minimum 0 |  |
| `holder_count` | integer |  | minimum 0 |  |
| `is_revealed` | boolean |  |  |  |
| `marketplaces` | array of string |  | items: pattern `^[a-z0-9][a-z0-9_.-]{0,63}$` |  |
| `max_supply` | integer |  | minimum 0 |  |
| `metadata_storage` | string |  | one of: ipfs, arweave, centralized, onchain |  |
| `name` | string |  | maxLength 512 |  |
| `royalty_percent` | number |  | minimum 0; maximum 100 |  |
| `royalty_recipient` | string |  | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `standard` | string |  | one of: erc721, erc1155 |  |
| `symbol` | string |  | maxLength 1024 |  |
| `total_supply` | integer |  | minimum 0 |  |
| `total_volume` | string |  | maxLength 1024 |  |
| `total_volume_usd` | number |  | minimum 0 |  |

#### SmartContractDetails

Smart contract-specific details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `abi` | string |  | maxLength 1048576 | Contract ABI (JSON string) |
| `address` | string |  | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `balance` | string |  | maxLength 1024 | Contract balance in wei |
| `bytecode_hash` | string |  | maxLength 1024 |  |
| `compiler_version` | string |  | maxLength 1024 |  |
| `contract_type` | string |  | one of: erc20, erc721, erc1155, proxy, multisig, defi, governance, custom |  |
| `deployed_at` | string (date-time) |  | maxLength 64 |  |
| `deployer_address` | string |  | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `deployment_block` | integer |  | minimum 0 |  |
| `deployment_tx_hash` | string |  | pattern `^0x[a-fA-F0-9]{64}$` |  |
| `evm_version` | string |  | maxLength 1024 |  |
| `implementation_address` | string |  | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `interfaces` | array of string |  | items: maxLength 1024 | Implemented interfaces (ERC20, ERC721, etc.) |
| `is_optimization_enabled` | boolean |  |  |  |
| `is_ownership_renounced` | boolean |  |  |  |
| `is_proxy` | boolean |  |  |  |
| `is_upgradeable` | boolean |  |  |  |
| `is_verified` | boolean |  |  | Verified on block explorer |
| `libraries` | array of object |  |  |  |
| `license` | string |  | maxLength 1024 |  |
| `name` | string |  | maxLength 512 |  |
| `optimization_runs` | integer |  |  |  |
| `owner_address` | string |  | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `proxy_type` | string |  | one of: transparent, uups, beacon, diamond, minimal |  |
| `source_code_hash` | string |  | maxLength 1024 |  |
| `source_code_url` | string |  | pattern `^[Hh][Tt][Tt][Pp][Ss]?://[^\s/?#]+[^\s]*$`; maxLength 2048 |  |
| `tx_count` | integer |  | minimum 0 |  |

#### TokenBalance

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `balance` | string | yes | maxLength 1024 |  |
| `balance_formatted` | string |  | maxLength 1024 |  |
| `contract_address` | string | yes | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `decimals` | integer |  | minimum 0; maximum 18 |  |
| `name` | string |  | maxLength 512 |  |
| `symbol` | string |  | maxLength 1024 |  |
| `usd_value` | number |  | minimum 0 |  |

#### TokenDetails

Token-specific details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `decimals` | integer |  | minimum 0; maximum 18 |  |
| `has_blacklist` | boolean |  |  |  |
| `has_transfer_fee` | boolean |  |  |  |
| `holder_count` | integer |  | minimum 0 |  |
| `honeypot_reason` | string |  | maxLength 1024 |  |
| `is_burnable` | boolean |  |  |  |
| `is_honeypot` | boolean |  |  |  |
| `is_mintable` | boolean |  |  |  |
| `is_pausable` | boolean |  |  |  |
| `liquidity_usd` | number |  | minimum 0 |  |
| `market_cap_usd` | number |  | minimum 0 |  |
| `max_supply` | string |  | maxLength 1024 |  |
| `name` | string |  | maxLength 512 |  |
| `price_usd` | number |  | minimum 0 |  |
| `standard` | string |  | one of: erc20, erc721, erc1155, bep20, spl |  |
| `symbol` | string |  | maxLength 1024 |  |
| `total_supply` | string |  | maxLength 1024 |  |
| `trading_pairs` | array of `TradingPair` |  |  |  |
| `transfer_fee_percent` | number |  | minimum 0; maximum 100 |  |

#### TradingPair

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `dex` | string | yes | pattern `^[a-z0-9][a-z0-9_.-]{0,63}$` | Open token (vendor neutral since 2.0). Known values: uniswap_v2, uniswap_v3, sushiswap, pancakeswap, curve, balancer |
| `liquidity_usd` | number |  | minimum 0 |  |
| `pair_address` | string | yes | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `quote_token` | string | yes | maxLength 1024 |  |

#### WalletDetails

Wallet-specific details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `balance` | string |  | maxLength 1024 | Native token balance in wei |
| `ens_name` | string |  | maxLength 1024 |  |
| `first_tx_at` | string (date-time) |  | maxLength 64 |  |
| `labels` | array of string |  | items: one of: exchange, whale, hacker, contract, bridge, defi, nft_trader |  |
| `last_tx_at` | string (date-time) |  | maxLength 64 |  |
| `nft_count` | integer |  | minimum 0 |  |
| `owners` | array of string |  | items: pattern `^0x[a-fA-F0-9]{40}$` |  |
| `provider` | string |  | pattern `^[a-z0-9][a-z0-9_.-]{0,63}$` | Open token (vendor neutral since 2.0). Known values: metamask, ledger, safe, argent, coinbase, rainbow, trustwallet |
| `required_signatures` | integer |  | minimum 1 |  |
| `token_balances` | array of `TokenBalance` |  |  |  |
| `total_owners` | integer |  | minimum 1 |  |
| `tx_count` | integer |  | minimum 0 |  |
| `wallet_type` | string |  | one of: eoa, multisig, smart_wallet, mpc |  |

### Web3 Vulnerability Details (`web3-finding.json`)

Web3 profile: details of a smart-contract finding (a vulnerability or weakness finding with a web3 block). Vendor and product vocabularies are open tokens.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `access_control` | `AccessControlIssue` |  |  |  |
| `affected_value_usd` | number |  | minimum 0 |  |
| `attack_vector` | string |  | maxLength 1024 | Attack vector description |
| `attacker_addresses` | array of string |  | items: pattern `^0x[a-fA-F0-9]{40}$` |  |
| `bytecode_offset` | integer |  | minimum 0 | Bytecode offset |
| `chain` | string |  | maxLength 1024 | Chain name |
| `chain_id` | integer |  |  | EVM Chain ID |
| `contract_address` | string |  | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `detection_confidence` | string |  | one of: high, medium, low |  |
| `detection_tool` | string |  | pattern `^[a-z0-9][a-z0-9_.-]{0,63}$` | Open token (vendor neutral since 2.0). Known values: slither, mythril, securify, manticore, echidna, foundry, aderyn, wake, 4naly3er, solhint, mythx, certora, custom |
| `estimated_impact_usd` | number |  | minimum 0 |  |
| `flash_loan` | `FlashLoanIssue` |  |  |  |
| `function_selector` | string |  | pattern `^0x[a-fA-F0-9]{8}$` | Function selector (4 bytes) |
| `function_signature` | string |  | maxLength 1024 | Affected function signature (e.g., withdraw(uint256)) |
| `gas_issue` | `GasIssue` |  |  |  |
| `is_exploitable_on_mainnet` | boolean |  |  |  |
| `is_false_positive` | boolean |  |  |  |
| `oracle_manipulation` | `OracleManipulationIssue` |  |  |  |
| `poc` | `Web3POC` |  |  |  |
| `reentrancy` | `ReentrancyIssue` |  |  |  |
| `related_tx_hashes` | array of string |  | items: pattern `^0x[a-fA-F0-9]{64}$` |  |
| `swc_id` | string |  | pattern `^SWC-\d{3}$` | SWC Registry ID (e.g., SWC-107) |
| `vulnerability_class` | `Web3VulnerabilityClass` |  |  |  |
| `vulnerable_pattern` | string |  | maxLength 4096 | Vulnerable code pattern |

#### AccessControlIssue

Access control vulnerability details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `callable_by` | string |  | one of: anyone, owner_only, role_based, whitelist |  |
| `escalation_path` | string |  | maxLength 1024 |  |
| `missing_modifier` | string |  | maxLength 1024 |  |
| `missing_role_check` | string |  | maxLength 1024 |  |
| `unprotected_function` | string |  | maxLength 1024 |  |

#### FlashLoanIssue

Flash loan attack vulnerability details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `attack_steps` | array of string |  | items: maxLength 1024 |  |
| `attack_type` | string |  | one of: price_manipulation, governance_attack, collateral_theft, arbitrage, liquidation |  |
| `potential_profit_usd` | number |  | minimum 0 |  |
| `provider` | string |  | pattern `^[a-z0-9][a-z0-9_.-]{0,63}$` | Open token (vendor neutral since 2.0). Known values: aave, dydx, uniswap, balancer, compound, maker |
| `required_capital_usd` | number |  | minimum 0 |  |

#### GasIssue

Gas optimization issue details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `current_gas` | integer |  | minimum 0 |  |
| `optimized_gas` | integer |  | minimum 0 |  |
| `savings_percent` | number |  | minimum 0; maximum 100 |  |
| `suggestion` | string |  | maxLength 4096 |  |

#### OracleManipulationIssue

Oracle manipulation vulnerability details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `manipulation_method` | string |  | one of: flash_loan, sandwich, time_manipulation, multi_block |  |
| `missing_checks` | array of string |  | items: one of: staleness_check, min_answer_check, max_answer_check, sequencer_check, deviation_check |  |
| `oracle_address` | string |  | pattern `^0x[a-fA-F0-9]{40}$` |  |
| `oracle_type` | string |  | pattern `^[a-z0-9][a-z0-9_.-]{0,63}$` | Open token (vendor neutral since 2.0). Known values: chainlink, uniswap_twap, uniswap_spot, band, tellor, custom |
| `price_impact_percent` | number |  | minimum 0 |  |

#### ReentrancyIssue

Reentrancy vulnerability details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `callback` | string |  | maxLength 1024 |  |
| `entry_point` | string |  | maxLength 1024 |  |
| `external_call` | string |  | maxLength 1024 | Vulnerable external call |
| `max_depth` | integer |  | minimum 1 |  |
| `state_modified_after_call` | string |  | maxLength 1024 |  |
| `type` | string |  | one of: cross_function, cross_contract, read_only, single_function |  |

#### Web3POC

Proof of concept details

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `code` | string |  | maxLength 65536 | POC code or script |
| `expected_outcome` | string |  | maxLength 4096 |  |
| `fork_block_number` | integer |  | minimum 0 |  |
| `tested_on` | string |  | one of: mainnet_fork, testnet, local |  |
| `tx_data` | string |  | maxLength 65536 | Transaction data |
| `type` | string |  | one of: transaction, script, foundry_test, hardhat_test |  |

#### Web3VulnerabilityClass

Web3 vulnerability classification

Type: string. one of: reentrancy, integer_overflow, integer_underflow, access_control, unchecked_call, delegate_call, self_destruct, tx_origin, timestamp_dependence, blockhash_dependence, flash_loan_attack, oracle_manipulation, front_running, sandwich_attack, slippage_attack, price_manipulation, governance_attack, liquidity_drain, mev_vulnerability, honeypot, hidden_mint, hidden_fee, blacklist_abuse, fake_renounce, storage_collision, uninitialized_proxy, upgrade_vulnerability, weak_randomness, signature_malleability, replay_attack, dos_gas_limit, unbounded_loop, dos_block_stuffing, business_logic, invariant_violation

<!-- END GENERATED FIELD REFERENCE -->
