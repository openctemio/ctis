# CTIS 2.0 validation rules beyond the schema

This document is normative. The key words MUST, MUST NOT, SHOULD and MAY are used as described in RFC 2119 and RFC 8174.

A receiver MUST apply every rule below after schema validation against `schemas/v2` (or the equivalent strict decoding, see [spec.md](spec.md) sections 2.2 and 4), and MUST refuse a document that breaks one. A producer SHOULD apply them before sending. The Go reference is `(*Report).Validate` in the root package of `github.com/openctemio/ctis/v2`; `scripts/validate_schemas.py` shows the schema step.

Each rule has an id `V-<AREA>-<NNN>` that never changes meaning, and one or more invalid documents in [`conformance/v2/documents/manifest.json`](../conformance/v2/documents/manifest.json) that carry the id in their `rule` member. Each such document is valid against `schemas/v2` and breaks exactly that rule. An implementation matches on the category (`validate`, or `version` for V-VER-001) and treats the message substring as informative: it is the text the Go reference reports, and another implementation may word its messages differently.

Some rules could be stated in JSON Schema (a pattern, or a conditional subschema) but `schemas/v2` does not state them today. They are listed here so that a receiver that relies on the schema still applies them.

Member paths use `[]` for every element of an array. `source_refs[]` means every `source_refs` list of the document (`metadata`, assets and findings); `technologies[]` means those of assets and of endpoints; `tool` means the report's `tool` and every `findings[].tool`.

## Definitions

- **Blank**: a string that is empty or consists only of white space (characters with the Unicode `White_Space` property).
- **Control character**: U+0000 to U+001F, U+007F, U+0080 to U+009F, U+202E (right-to-left override), U+2028 (line separator) and U+2029 (paragraph separator).
- **Bytes**: the length of a string in its UTF-8 encoding. **Characters**: the number of Unicode code points.
- **Serialized size**: the number of bytes of a JSON value encoded without insignificant white space. The Go reference encodes the decoded value again: members left at their zero value are omitted, object keys of maps are sorted, and `<`, `>`, `&`, U+2028 and U+2029 are escaped as `\uXXXX`. Encoders that escape differently can judge a value close to a bound differently, so the vectors stay well clear of the bound and producers SHOULD too.
- **Canonical form**: the result of the canonical-form algorithms in [canonical-forms.md](canonical-forms.md) (vectors in `conformance/v2/canonical/`).

## Version (VER)

### V-VER-001: minor newer than the receiver

- **Rule.** A receiver that decodes strictly (it rejects unknown members and enum values, as the conformance runner does) MUST refuse a document whose `version` has the receiver's major and a minor greater than the newest minor it implements. A receiver that implements version-gated must-ignore applies [spec.md](spec.md) section 2.2 instead.
- **Condition.** `version` is `2.<m>` with `m` greater than the implemented minor (0 for this specification). Category `version`, checked before decoding.
- **Message.** `unsupported version "2.99"`
- **Vectors.** `invalid/version-minor-future.json`

## Metadata (META)

### V-META-001: generation time is set

- **Rule.** `metadata.generated_at` MUST NOT be the instant `0001-01-01T00:00:00Z`.
- **Condition.** The decoded time equals 0001-01-01 00:00:00 UTC (the zero time of the Go reference, which treats it as missing).
- **Message.** `metadata.generated_at is required`
- **Vectors.** `invalid/v-meta-001-generated-at-zero.json`

### V-META-002: work ends after it starts

- **Rule.** When `metadata.started_at` and `metadata.ended_at` are both present, `ended_at` MUST NOT be before `started_at`.
- **Condition.** Both set and `ended_at < started_at` as instants.
- **Message.** `metadata.ended_at is before metadata.started_at`
- **Vectors.** `invalid/v-meta-002-ended-before-started.json`

## Text (TEXT)

### V-TEXT-001: required text is not blank

- **Rule.** These members, when present, MUST NOT be blank: `tool.name`, `tool.content[].name`, `metadata.branch.name`, `source_refs[].id`, `assets[].value`, `technologies[].name`, `assets[].owners[].ref`, `findings[].title`, `rules[].rule_id`, `findings[].vulnerability.threat_signals[].source`, `dependencies[].name`, `endpoints[].params[].name`, `findings[].web.parameter.name`.
- **Condition.** The value is blank (the schema only requires a non-empty string).
- **Message.** `is required`; for the two parameter names `name must be 1 to 128 bytes without control characters`
- **Vectors.** `invalid/v-text-001-tool-name.json`, `invalid/v-text-001-finding-tool-name.json`, `invalid/v-text-001-tool-content-name.json`, `invalid/v-text-001-branch-name.json`, `invalid/v-text-001-source-ref-id.json`, `invalid/v-text-001-asset-value.json`, `invalid/v-text-001-technology-name.json`, `invalid/v-text-001-endpoint-technology-name.json`, `invalid/v-text-001-owner-ref.json`, `invalid/v-text-001-finding-title.json`, `invalid/v-text-001-rule-id.json`, `invalid/v-text-001-threat-signal-source.json`, `invalid/v-text-001-dependency-name.json`, `invalid/v-text-001-endpoint-param-name.json`, `invalid/v-text-001-web-parameter-name.json`

### V-TEXT-002: no control characters

- **Rule.** These members MUST NOT contain a control character: `source_refs[].id`, `endpoints[].path`, `endpoints[].template`, `endpoints[].content_type`, `endpoints[].params[].name`, `findings[].web.parameter.name`, and in `findings[].evidence_items[]`: `label`, `http.request.url`, `http.request.headers[].value`, `http.response.headers[].value`, `http.response.reason`, `file.path`, `artifact.ref`. URL members follow V-URL-001 and V-WEB-001, which exclude control characters too.
- **Condition.** Any code point of the value is a control character as defined above.
- **Message.** `has a control character`, `with control characters`, `without control characters`, `invalid template`, `invalid content_type`, `http.response.reason`, `artifact size or ref` (the message names the member)
- **Vectors.** `invalid/v-text-002-source-ref-id-c0.json`, `invalid/v-text-002-source-ref-id-c1.json`, `invalid/v-text-002-source-ref-id-line-separator.json`, `invalid/v-text-002-source-ref-id-bidi-override.json`, `invalid/v-text-002-endpoint-path.json`, `invalid/v-text-002-endpoint-template.json`, `invalid/v-text-002-endpoint-content-type.json`, `invalid/v-text-002-endpoint-param-name.json`, `invalid/v-text-002-web-parameter-name.json`, `invalid/v-text-002-evidence-label.json`, `invalid/v-text-002-evidence-header-value.json`, `invalid/v-text-002-evidence-request-url.json`, `invalid/v-text-002-evidence-response-reason.json`, `invalid/v-text-002-evidence-file-path.json`, `invalid/v-text-002-evidence-artifact-ref.json`

### V-TEXT-003: byte bounds

- **Rule.** These members MUST NOT be longer than the number of bytes given. The schema bounds strings in characters and cannot state a byte bound.

  | Member | Bytes |
  |---|---|
  | `metadata.targets[].target` | 2,048 |
  | `assets[].value` | 2,048 |
  | `source_refs[].id` | 256 |
  | `endpoints[].path`, `endpoints[].template` | 2,048 |
  | `endpoints[].content_type` | 255 |
  | `endpoints[].params[].name`, `findings[].web.parameter.name` | 128 |
  | evidence `http.request.body`, `http.response.body` | 65,536 |
  | evidence `text`, `file.snippet` | 65,536 |
  | evidence `http.request.headers[].value`, `http.response.headers[].value` | 8,192 |
  | evidence `http.request.url`, `command` | 8,192 |
  | evidence `file.path` | 4,096 |
  | evidence `extracted[]` | 1,024 |

  `findings[].web.url` and `endpoints[].parent_url` are bounded by V-WEB-001. The evidence bounds on `text` and `extracted[]` apply to the kinds listed in V-EVID-002.
- **Condition.** The UTF-8 length of the value exceeds the bound.
- **Message.** `longer than <n> bytes`, `longer than <n>` (the message names the member)
- **Vectors.** `invalid/v-text-003-target.json`, `invalid/v-text-003-asset-value.json`, `invalid/v-text-003-source-ref-id.json`, `invalid/v-text-003-endpoint-path.json`, `invalid/v-text-003-endpoint-content-type.json`, `invalid/v-text-003-endpoint-param-name.json`, `invalid/v-text-003-web-parameter-name.json`, `invalid/v-text-003-evidence-body.json`, `invalid/v-text-003-evidence-text.json`, `invalid/v-text-003-evidence-header-value.json`, `invalid/v-text-003-evidence-request-url.json`, `invalid/v-text-003-evidence-command.json`, `invalid/v-text-003-evidence-extracted.json`, `invalid/v-text-003-evidence-file-path.json`, `invalid/v-text-003-evidence-file-snippet.json`

## URLs (URL)

### V-URL-001: URL members are web URLs

- **Rule.** These members, when present, MUST be absolute `http` or `https` URLs (scheme compared case-insensitively) with a non-empty host, of at most 2,048 bytes, without control characters, that parse as an RFC 3986 URI: `metadata.branch.pull_request_url`, `metadata.branch.repository_url`, `tool.info_url`, `assets[].technical.repository.url`, `assets[].technical.http.redirect_url`, `findings[].references[]`, `findings[].work_item_uris[]`, `findings[].hosted_viewer_uri`, `findings[].vulnerability.data_source.url`, `findings[].remediation.advisories[].url`, `rules[].help_uri`.
- **Condition.** The schema checks only the shape `http(s)://host...`. The rule additionally refuses a host with a malformed percent-escape (`http://%zz/`), an unclosed IP literal (`http://[::1/`), and a control character anywhere in the URL.
- **Message.** `is not an http or https URL`
- **Vectors.** `invalid/v-url-001-bad-percent-host.json`, `invalid/v-url-001-unclosed-ipv6.json`, `invalid/v-url-001-control-character.json`, `invalid/v-url-001-branch-repository-url.json`

## Identifiers and references (REF)

Each kind of document-local id is its own name space: an asset and a finding may share an id. Ids compare as exact strings.

### V-REF-001: asset ids are unique

- **Rule.** Two `assets[]` MUST NOT share an `id`.
- **Condition.** A later asset repeats the `id` of an earlier one.
- **Message.** `duplicate id`
- **Vectors.** `invalid/duplicate-asset-id.json`

### V-REF-002: finding ids are unique

- **Rule.** Two `findings[]` that carry an `id` MUST NOT share it.
- **Condition.** A later finding repeats the `id` of an earlier one.
- **Message.** `duplicate id`
- **Vectors.** `invalid/v-ref-002-duplicate-finding-id.json`

### V-REF-003: dependency ids are unique

- **Rule.** Two `dependencies[]` that carry an `id` MUST NOT share it.
- **Condition.** A later dependency repeats the `id` of an earlier one.
- **Message.** `duplicate id`
- **Vectors.** `invalid/v-ref-003-duplicate-dependency-id.json`

### V-REF-004: rule ids are unique

- **Rule.** Two `rules[]` MUST NOT share an `id` ([spec.md](spec.md) section 6.7).
- **Condition.** A later rule repeats the `id` of an earlier one.
- **Message.** `duplicate id`
- **Vectors.** `invalid/rule-duplicate-id.json`

### V-REF-005: endpoint ids are unique

- **Rule.** Two `endpoints[]` that carry an `id` MUST NOT share it.
- **Condition.** A later endpoint repeats the `id` of an earlier one.
- **Message.** `duplicate id`
- **Vectors.** `invalid/v-ref-005-duplicate-endpoint-id.json`

### V-REF-006: a finding names an asset of the document

- **Rule.** `findings[].asset_ref` MUST name the `id` of an asset of the same document.
- **Condition.** No `assets[].id` equals `asset_ref`.
- **Message.** `names no asset in this report`
- **Vectors.** `invalid/dangling-asset-ref.json`

### V-REF-007: a finding's dependency resolves

- **Rule.** `findings[].dependency_ref`, when present, MUST name the `id` of a dependency of the same document.
- **Condition.** No `dependencies[].id` equals `dependency_ref`.
- **Message.** `names no dependency in this report`
- **Vectors.** `invalid/v-ref-007-dangling-dependency-ref.json`

### V-REF-008: a finding's rule resolves

- **Rule.** `findings[].rule_ref`, when present, MUST name the `id` of a rule of the same document.
- **Condition.** No `rules[].id` equals `rule_ref`.
- **Message.** `names no rule in this report`
- **Vectors.** `invalid/rule-ref-unknown.json`

### V-REF-009: a finding's endpoint resolves

- **Rule.** `findings[].web.endpoint_ref`, when present, MUST name the `id` of an endpoint of the same document.
- **Condition.** No `endpoints[].id` equals `endpoint_ref`.
- **Message.** `names no endpoint in this report`
- **Vectors.** `invalid/v-ref-009-dangling-endpoint-ref.json`

### V-REF-010: a dependency's asset resolves

- **Rule.** `dependencies[].asset_ref`, when present, MUST name the `id` of an asset of the same document.
- **Condition.** No `assets[].id` equals `asset_ref`.
- **Message.** `names no asset in this report`
- **Vectors.** `invalid/v-ref-010-dangling-dependency-asset-ref.json`

### V-REF-011: dependency edges resolve

- **Rule.** Every entry of `dependencies[].depends_on[]` MUST name the `id` of a dependency of the same document.
- **Condition.** No `dependencies[].id` equals the entry.
- **Message.** `names no dependency in this report`
- **Vectors.** `invalid/v-ref-011-dangling-depends-on.json`

### V-REF-012: relationship ends resolve

- **Rule.** `relationships[].from_ref` and `relationships[].to_ref` MUST each name the `id` of an asset of the same document ([spec.md](spec.md) section 7.1).
- **Condition.** No `assets[].id` equals the reference.
- **Message.** `names no asset in this report`
- **Vectors.** `invalid/v-ref-012-dangling-from-ref.json`, `invalid/v-ref-012-dangling-to-ref.json`

### V-REF-013: an endpoint's origin asset resolves

- **Rule.** `endpoints[].origin_ref`, when present, MUST name the `id` of an asset of the same document.
- **Condition.** No `assets[].id` equals `origin_ref`.
- **Message.** `names no asset in this report`
- **Vectors.** `invalid/v-ref-013-dangling-origin-ref.json`

## Rule catalog (RULE)

### V-RULE-001: a finding that names a rule carries its rule_id

- **Rule.** A finding whose `rule_ref` names a rule of the document MUST carry `rule_id` ([spec.md](spec.md) section 6.7).
- **Condition.** `rule_ref` resolves and `rule_id` is absent or empty.
- **Message.** `rule_id is required when rule_ref is set`
- **Vectors.** `invalid/v-rule-001-rule-ref-without-rule-id.json`

### V-RULE-002: the finding's rule_id equals the rule's

- **Rule.** When `findings[].rule_ref` names a rule, `findings[].rule_id` MUST equal that rule's `rule_id`.
- **Condition.** Exact string comparison fails.
- **Message.** `differs from rule_id`
- **Vectors.** `invalid/rule-ref-rule-id-differs.json`

### V-RULE-003: content_path is one line

- **Rule.** `rules[].content_path` MUST NOT contain U+0000, U+000A or U+000D.
- **Condition.** Any of the three code points occurs. (This rule uses this narrower set, not the control characters of V-TEXT-002.)
- **Message.** `content_path has a control character`
- **Vectors.** `invalid/v-rule-003-content-path-newline.json`, `invalid/v-rule-003-content-path-nul.json`

## Canonical values (CANON)

### V-CANON-001: asset values are canonical

- **Rule.** `assets[].value` MUST be the canonical form of itself for the asset's `type` ([spec.md](spec.md) section 5.2).
- **Condition.** The canonical-form algorithm for the type refuses the value, or returns a different string.
- **Message.** `has no canonical form for type` or `is not canonical for type`
- **Vectors.** `invalid/asset-value-not-canonical.json`, `invalid/v-canon-001-ip-no-canonical-form.json`, `invalid/v-canon-001-host-not-punycode.json`, `invalid/v-canon-001-service-uppercase.json`, `invalid/v-canon-001-package-with-version.json`

### V-CANON-002: certificate fingerprint equals the value

- **Rule.** For an asset of type `certificate`, `technical.certificate.sha256_fingerprint`, when present, MUST equal the asset's `value`.
- **Condition.** Exact string comparison fails.
- **Message.** `technical.certificate.sha256_fingerprint differs from the asset value`
- **Vectors.** `invalid/v-canon-002-certificate-fingerprint-differs.json`

### V-CANON-003: service port and transport agree with the value

- **Rule.** For an asset of type `service` whose `technical.service` has a port of at least 1 and a valid `transport`, the asset's `value` MUST end with `:<port>/<transport>` (port in decimal without leading zeros).
- **Condition.** The suffix differs.
- **Message.** `technical.service port and transport differ from the asset value`
- **Vectors.** `invalid/v-canon-003-service-port-differs.json`, `invalid/v-canon-003-service-transport-differs.json`

### V-CANON-004: package URLs parse

- **Rule.** `dependencies[].purl` and `findings[].vulnerability.purl`, when present, MUST be package URLs that the purl canonical-form algorithm accepts. They need not be in canonical form.
- **Condition.** The algorithm refuses the value (for example `pkg:npm` without a name, or a malformed percent-escape).
- **Message.** `is not a package URL`
- **Vectors.** `invalid/v-canon-004-dependency-purl.json`, `invalid/v-canon-004-vulnerability-purl.json`

### V-CANON-005: endpoint origins are normalised

- **Rule.** `endpoints[].origin` MUST be a normalised web origin: the canonical `web_origin` form `scheme://host[:port]` with lowercase scheme, lowercase ASCII host (Punycode for internationalized labels), the default port of the scheme omitted, and no path, query or fragment.
- **Condition.** The value does not parse as a web URL, or differs from the origin of its own normalised form.
- **Message.** `is not a normalised origin`
- **Vectors.** `invalid/v-canon-005-origin-default-port.json`, `invalid/v-canon-005-origin-uppercase-host.json`, `invalid/v-canon-005-origin-trailing-slash.json`

## Assets (ASSET)

### V-ASSET-001: identities say what kind they are

- **Rule.** An asset of type `identity` MUST carry `technical.identity` (whose `kind` the schema requires).
- **Condition.** `technical` or `technical.identity` is absent.
- **Message.** `identity needs technical.identity.kind`
- **Vectors.** `invalid/v-asset-001-identity-without-kind.json`

### V-ASSET-002: network device details belong to network devices

- **Rule.** `technical.network_device` MUST appear only on assets of type `network_device`.
- **Condition.** It is present on an asset of another type.
- **Message.** `technical.network_device is only for network_device assets`
- **Vectors.** `invalid/v-asset-002-network-device-on-host.json`

### V-ASSET-003: an asset is last seen after it is first seen

- **Rule.** When `assets[].first_seen_at` and `last_seen_at` are both present, `last_seen_at` MUST NOT be before `first_seen_at`.
- **Condition.** Both set and `last_seen_at < first_seen_at`.
- **Message.** `last_seen_at is before first_seen_at`
- **Vectors.** `invalid/v-asset-003-last-seen-before-first-seen.json`

### V-ASSET-004: cookie names are tokens

- **Rule.** `technical.http.security_headers.cookies[].name` MUST be an RFC 6265 cookie name: 1 to 128 bytes, each in U+0021 to U+007E and none of `( ) < > @ , ; : \ " / [ ] ? = { }`.
- **Condition.** Any byte is outside that set.
- **Message.** `is not a cookie name`
- **Vectors.** `invalid/v-asset-004-cookie-name-separator.json`, `invalid/v-asset-004-cookie-name-non-ascii.json`

## Coverage and absence (COV)

### V-COV-001: targets are unique

- **Rule.** Two `metadata.targets[]` MUST NOT have the same `target` ([spec.md](spec.md) section 13).
- **Condition.** A later entry repeats the `target` of an earlier one (exact string comparison).
- **Message.** `duplicate target`
- **Vectors.** `invalid/v-cov-001-duplicate-target.json`

### V-COV-002: done and unfinished targets take no class or cause

- **Rule.** A target whose `state` is `done` or `unfinished` MUST NOT carry `class` or `cause` ([spec.md](spec.md) section 7.2).
- **Condition.** Either member is present and non-empty.
- **Message.** `takes no class or cause`
- **Vectors.** `invalid/v-cov-002-done-with-class.json`, `invalid/v-cov-002-unfinished-with-cause.json`

### V-COV-003: failed and skipped targets carry a class of their state

- **Rule.** A target whose `state` is `failed` MUST carry a `class` other than `refused` and `excluded`. A target whose `state` is `skipped` MUST carry a `class` among `refused`, `excluded`, `edge_challenged` and `edge_blocked` ([spec.md](spec.md) section 7.2).
- **Condition.** `class` is absent or not one the state takes.
- **Message.** `does not fit state`
- **Vectors.** `invalid/v-cov-003-failed-refused.json`, `invalid/v-cov-003-skipped-timeout.json`, `invalid/v-cov-003-failed-without-class.json`

### V-COV-004: segment index is below the count

- **Rule.** `metadata.segment.index` MUST be less than `metadata.segment.count`.
- **Condition.** `index >= count`.
- **Message.** `metadata.segment.index`
- **Vectors.** `invalid/v-cov-004-segment-index.json`

### V-COV-005: a gone asset names its signal

- **Rule.** An asset with `state` `gone` MUST carry `state_reason` ([spec.md](spec.md) section 7.2).
- **Condition.** `state` is `gone` and `state_reason` is absent.
- **Message.** `state gone needs a state_reason`
- **Vectors.** `invalid/v-cov-005-gone-without-reason.json`

### V-COV-006: state_reason only for gone assets

- **Rule.** An asset MUST NOT carry `state_reason` unless its `state` is `gone`.
- **Condition.** `state_reason` is present and `state` is absent or `active`.
- **Message.** `state_reason is only for state gone`
- **Vectors.** `invalid/v-cov-006-reason-without-gone.json`, `invalid/v-cov-006-reason-without-state.json`

## Findings (FIND)

### V-FIND-001: due dates are calendar dates

- **Rule.** `findings[].vulnerability.threat_signals[].due_on`, when present, MUST be a date that exists in the proleptic Gregorian calendar.
- **Condition.** The value has the `YYYY-MM-DD` shape (the schema checks it) but names a day that does not exist, such as `2026-02-30`.
- **Message.** `is not a YYYY-MM-DD date`
- **Vectors.** `invalid/v-find-001-due-on-not-a-date.json`

### V-FIND-002: advisories name something

- **Rule.** Every `findings[].remediation.advisories[]` MUST carry `id` or `url`.
- **Condition.** Both are absent or empty.
- **Message.** `needs an id or a url`
- **Vectors.** `invalid/v-find-002-advisory-without-id-or-url.json`

### V-FIND-003: source_extra total size

- **Rule.** The keys and values of `findings[].source_extra` together MUST NOT exceed 32,768 bytes ([spec.md](spec.md) section 13).
- **Condition.** The sum of the UTF-8 lengths of every key and every value exceeds 32,768.
- **Message.** `source_extra is <n> bytes, at most 32768`
- **Vectors.** `invalid/v-find-003-source-extra-size.json`, `invalid/v-find-003-source-extra-size-multibyte.json`

### V-FIND-004: source_extra keys

- **Rule.** Every key of `findings[].source_extra` MUST be non-empty, at most 128 characters, and free of U+0000 to U+001F and U+007F.
- **Condition.** A key is empty, longer, or holds one of those code points.
- **Message.** `is empty, longer than 128 or holds control characters`
- **Vectors.** `invalid/v-find-004-source-extra-key-control.json`, `invalid/v-find-004-source-extra-key-empty.json`

## Scores (SCORE)

These rules apply to every entry of `findings[].scores[]` ([spec.md](spec.md) section 6.3).

### V-SCORE-001: CVSS scores state their version

- **Rule.** A score of system `cvss` MUST carry `version` `2.0`, `3.0`, `3.1` or `4.0`.
- **Condition.** `version` is absent or another value.
- **Message.** `cvss score needs version 2.0, 3.0, 3.1 or 4.0`
- **Vectors.** `invalid/v-score-001-cvss-without-version.json`

### V-SCORE-002: CVSS vector agrees with the version

- **Rule.** A score of system `cvss` with a `vector` MUST declare the version its vector declares.
- **Condition.** After trimming white space, the vector declares `3.0`, `3.1` or `4.0` when it starts with `CVSS:3.0/`, `CVSS:3.1/` or `CVSS:4.0/`; `2.0` when it starts with `AV:` or `(AV:`; and no version otherwise. The rule fails when the declared version differs from `version`, except that a vector declaring no version is accepted with `version` `2.0`.
- **Message.** `vector does not match cvss version`
- **Vectors.** `invalid/v-score-002-cvss-vector-v4-version-31.json`, `invalid/v-score-002-cvss-vector-v2-version-31.json`, `invalid/v-score-002-cvss-vector-unknown-version-31.json`, `invalid/v-score-002-cvss-vector-v31-version-20.json`

### V-SCORE-003: CVSS scores carry a value or a vector

- **Rule.** A score of system `cvss` MUST carry `value` or `vector`.
- **Condition.** Neither is present.
- **Message.** `cvss score needs a value or a vector`
- **Vectors.** `invalid/v-score-003-cvss-without-value-or-vector.json`

### V-SCORE-004: CVSS range

- **Rule.** The `value` of a `cvss` score MUST be within 0 to 10.
- **Condition.** `value < 0` or `value > 10`.
- **Message.** `is outside 0-10`
- **Vectors.** `invalid/v-score-004-cvss-value-range.json`

### V-SCORE-005: EPSS range

- **Rule.** The `value` of an `epss` or `epss_percentile` score MUST be within 0 to 1 (a percentile is a fraction, not a percentage).
- **Condition.** `value < 0` or `value > 1`.
- **Message.** `is outside 0-1`
- **Vectors.** `invalid/epss-percentile-0-100.json`, `invalid/v-score-005-epss-value-range.json`, `invalid/v-score-005-epss-percentile-negative.json`

### V-SCORE-006: SSVC has no number

- **Rule.** A score of system `ssvc` MUST NOT carry `value`.
- **Condition.** `value` is present.
- **Message.** `ssvc has no numeric value`
- **Vectors.** `invalid/v-score-006-ssvc-with-value.json`

### V-SCORE-007: SSVC carries a decision

- **Rule.** A score of system `ssvc` MUST carry `vector` or `label`.
- **Condition.** Both are absent or empty.
- **Message.** `ssvc needs a vector or a label`
- **Vectors.** `invalid/v-score-007-ssvc-without-vector-or-label.json`

### V-SCORE-008: vendor scores carry a value or a label

- **Rule.** A score of system `vendor` MUST carry `value` or `label`.
- **Condition.** `value` is absent and `label` is absent or empty.
- **Message.** `vendor score needs a value or a label`
- **Vectors.** `invalid/v-score-008-vendor-without-value-or-label.json`

### V-SCORE-009: vendor range

- **Rule.** The `value` of a `vendor` score MUST be within -1,000,000 to 1,000,000.
- **Condition.** The absolute value exceeds 1,000,000.
- **Message.** `is outside -1e+06-1e+06`
- **Vectors.** `invalid/v-score-009-vendor-value-range.json`

## Vulnerability ids (VULN)

### V-VULN-001: typed ids have the shape of their type

- **Rule.** Every `findings[].vulnerability.ids[]` entry MUST be recognized by the vulnerability-id algorithm, and an entry of type `cve` or `ghsa` MUST be an id of that type.
- **Condition.** After trimming white space, an id that starts with `CVE-` (case-insensitive) is recognized only when its upper-case form matches `^CVE-\d{4}-\d{4,}$`, and one that starts with `GHSA-` only when `GHSA-` followed by its lower-cased remainder matches `^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`; other ids are recognized when the schema accepts them. The rule fails when the id is not recognized, when `type` is `cve` and the id is not a CVE id, or when `type` is `ghsa` and the id is not a GHSA id. Other types keep any recognized id (an `osv` entry may hold a CVE id).
- **Message.** `is not a valid id of its type`
- **Vectors.** `invalid/v-vuln-001-cve-type-ghsa-id.json`, `invalid/v-vuln-001-ghsa-type-cve-id.json`, `invalid/v-vuln-001-cve-short-year.json`

## VEX (VEX)

### V-VEX-001: justification only for not_affected

- **Rule.** `findings[].vex.justification` MUST NOT be present unless `vex.status` is `not_affected`.
- **Condition.** A justification is present with another status.
- **Message.** `vex.justification is only for status not_affected`
- **Vectors.** `invalid/v-vex-001-justification-not-not-affected.json`

### V-VEX-002: not_affected says why

- **Rule.** A `vex.status` of `not_affected` MUST come with `justification` or `statement`.
- **Condition.** Both are absent or empty.
- **Message.** `vex status not_affected needs a justification or a statement`
- **Vectors.** `invalid/v-vex-002-not-affected-without-reason.json`

## Relationships (REL)

### V-REL-001: no self edges

- **Rule.** `relationships[].from_ref` and `to_ref` MUST name different assets ([spec.md](spec.md) section 7.1).
- **Condition.** The two references are equal.
- **Message.** `an asset cannot relate to itself`
- **Vectors.** `invalid/v-rel-001-self-relationship.json`

### V-REL-002: has_address points to an address

- **Rule.** The `to_ref` of a `has_address` relationship MUST name an asset of type `ip_address`.
- **Condition.** `to_ref` names an asset of the document whose `type` is not `ip_address`.
- **Message.** `has_address must point to an ip_address asset`
- **Vectors.** `invalid/has-address-to-name.json`, `invalid/v-rel-002-has-address-to-host.json`

### V-REL-003: has_address starts from a machine

- **Rule.** The `from_ref` of a `has_address` relationship MUST NOT name an asset of type `ip_address` or `ip_range`.
- **Condition.** `from_ref` names such an asset of the document.
- **Message.** `has_address cannot start from an`
- **Vectors.** `invalid/v-rel-003-has-address-from-ip.json`, `invalid/v-rel-003-has-address-from-range.json`

### V-REL-004: an edge is last seen after it is first seen

- **Rule.** When `relationships[].first_seen_at` and `last_seen_at` are both present, `last_seen_at` MUST NOT be before `first_seen_at`.
- **Condition.** Both set and `last_seen_at < first_seen_at`.
- **Message.** `last_seen_at is before first_seen_at`
- **Vectors.** `invalid/v-rel-004-last-seen-before-first-seen.json`

## Web (WEB)

### V-WEB-001: web URLs are redacted

- **Rule.** `findings[].web.url` and `endpoints[].parent_url` (when present) MUST be redacted web URLs: at most 2,048 bytes, an absolute `http` or `https` URL with a host, no user info, no control or white-space characters, and unchanged by redaction. Redaction removes the user info and the fragment and empties every query value while keeping each name followed by `=` (`?a=&b=`). The URL need not be normalised otherwise.
- **Condition.** The value does not parse as such a URL, or redaction changes it (a query value, a query name without `=`, user info or a fragment is present).
- **Message.** `url must be a redacted http(s) URL` or `parent_url must be a redacted URL`
- **Vectors.** `invalid/v-web-001-url-query-value.json`, `invalid/v-web-001-url-query-name-without-equals.json`, `invalid/v-web-001-url-user-info.json`, `invalid/v-web-001-url-fragment.json`, `invalid/v-web-001-url-too-long.json`, `invalid/v-web-001-parent-url-query-value.json`, `invalid/v-web-001-parent-url-not-http.json`

## Evidence (EVID)

These rules apply to every `findings[].evidence_items[]` entry ([spec.md](spec.md) section 6.5).

### V-EVID-001: item size

- **Rule.** An evidence item MUST NOT exceed 262,144 bytes (256 KiB) of serialized size.
- **Condition.** The serialized size of the item exceeds 262,144.
- **Message.** `larger than 262144 bytes`
- **Vectors.** `invalid/v-evid-001-item-too-large.json`

### V-EVID-002: known kinds carry no data

- **Rule.** An item of kind `http_exchange`, `raw_text`, `screenshot`, `file_excerpt`, `command_output` or `curl` MUST NOT carry `data`. `data` is for kinds this version does not define.
- **Condition.** `data` has at least one member on one of these kinds.
- **Message.** `data is only for kinds this version does not know`
- **Vectors.** `invalid/v-evid-002-known-kind-with-data.json`

### V-EVID-003: data size of other kinds

- **Rule.** For an item of any other kind, `data` MUST NOT exceed 65,536 bytes of serialized size.
- **Condition.** The serialized size of `data` exceeds 65,536.
- **Message.** `data larger than 65536 bytes`
- **Vectors.** `invalid/v-evid-003-unknown-kind-data-too-large.json`

### V-EVID-004: raw_text and curl carry text

- **Rule.** An item of kind `raw_text` or `curl` MUST carry a non-empty `text`.
- **Condition.** `text` is absent or empty.
- **Message.** `needs text`
- **Vectors.** `invalid/v-evid-004-raw-text-without-text.json`, `invalid/v-evid-004-curl-without-text.json`

### V-EVID-005: http_exchange carries an exchange

- **Rule.** An item of kind `http_exchange` MUST carry `http` with `request` or `response`.
- **Condition.** `http` is absent, or has neither member.
- **Message.** `http_exchange needs http.request or http.response`
- **Vectors.** `invalid/v-evid-005-http-exchange-empty.json`, `invalid/v-evid-005-http-exchange-without-http.json`

### V-EVID-006: command_output carries a command or output

- **Rule.** An item of kind `command_output` MUST carry a non-empty `command` or `text`.
- **Condition.** Both are absent or empty.
- **Message.** `command_output needs a command or text`
- **Vectors.** `invalid/v-evid-006-command-output-empty.json`

### V-EVID-007: file_excerpt carries a file

- **Rule.** An item of kind `file_excerpt` MUST carry `file`.
- **Condition.** `file` is absent.
- **Message.** `file_excerpt needs file`
- **Vectors.** `invalid/v-evid-007-file-excerpt-without-file.json`

### V-EVID-008: file lines in order

- **Rule.** In a `file_excerpt`, `file.end_line`, when greater than 0, MUST NOT be less than `file.start_line`.
- **Condition.** `end_line > 0` and `end_line < start_line`.
- **Message.** `file lines out of order`
- **Vectors.** `invalid/v-evid-008-file-lines-out-of-order.json`

### V-EVID-009: screenshot carries an artifact

- **Rule.** An item of kind `screenshot` MUST carry `artifact`.
- **Condition.** `artifact` is absent.
- **Message.** `screenshot needs artifact`
- **Vectors.** `invalid/v-evid-009-screenshot-without-artifact.json`

### V-EVID-010: artifact media type

- **Rule.** In a `screenshot`, `artifact.media_type` MUST match `^[a-z0-9][a-z0-9!#$&^_.+-]{0,62}/[a-z0-9][a-z0-9!#$&^_.+-]{0,62}$` (a lowercase `type/subtype`).
- **Condition.** The value does not match.
- **Message.** `artifact.media_type`
- **Vectors.** `invalid/v-evid-010-artifact-media-type-uppercase.json`, `invalid/v-evid-010-artifact-media-type-space.json`

### V-EVID-011: offsets in order

- **Rule.** In `match[]` and `sensitive[]` (of items of any kind for `sensitive`, of the kinds of V-EVID-002 for `match`), `start` MUST NOT be greater than `end` when both are present.
- **Condition.** Both set and `start > end`.
- **Message.** `start and end must be 0 <= start <= end`
- **Vectors.** `invalid/v-evid-011-match-start-after-end.json`, `invalid/v-evid-011-sensitive-start-after-end.json`

### V-EVID-012: matcher names

- **Rule.** `match[].matcher` MUST NOT contain U+0000 to U+001F or U+007F.
- **Condition.** One of those code points occurs.
- **Message.** `invalid matcher name`
- **Vectors.** `invalid/v-evid-012-matcher-control-character.json`

## Extensions (EXT)

### V-EXT-001: extensions size

- **Rule.** Every `extensions` object (on the report, `metadata`, assets, findings, dependencies, endpoints, relationships and rules) MUST NOT exceed 65,536 bytes (64 KiB) of serialized size ([spec.md](spec.md) section 8). The schema states the namespace form and the count of 32.
- **Condition.** The serialized size of the object exceeds 65,536.
- **Message.** `extensions is <n> bytes, at most 65536`
- **Vectors.** `invalid/v-ext-001-report.json`, `invalid/v-ext-001-finding.json`, `invalid/v-ext-001-relationship.json`

## Enforced by the schema (informative)

Some checks of `Report.Validate` are fully stated by `schemas/v2`, so they have no rule here: `metadata.id` as a lowercase UUIDv7; document references that follow the reference pattern and are not UUID-shaped (a `not` pattern); the `http(s)://` shape of URL members; the extension namespace form and the limit of 32 namespaces; every closed enum (asset and finding types, relationship types, score systems, VEX justifications, target classes); numeric ranges such as `confidence`, `rank`, ports and `metadata.segment.count`; the patterns of CWE, CAPEC and ATT&CK ids, of `due_on` and of SHA-256 digests; array and string bounds counted in items or characters.

## Accepted although they may look wrong (informative)

A receiver MUST NOT refuse a document for these, since the reference accepts them: a non-canonical but parseable `purl` in dependencies and vulnerabilities; a non-canonical vulnerability id (`cve-2024-1234` in lower case); `findings[].last_seen_at` before `first_seen_at`; `validation.evidence_refs[]` that name nothing in the document (they are only checked as references); a `web.url` that is redacted but not normalised (upper-case host, default port, dot segments); an id shared by items of different kinds.
