# Conformance protocol

A language-neutral way to run the conformance vectors against any CTIS implementation. The implementation provides a small server program that reads requests on its standard input and writes answers on its standard output; the harness [`scripts/conformance_harness.py`](../scripts/conformance_harness.py) walks the vectors, sends one request per case and compares the answers. The Go reference implements the server as `ctis conformance --serve`, and CI runs the harness against it, so the protocol itself is tested.

```sh
python3 scripts/conformance_harness.py -- ctis conformance --serve
python3 scripts/conformance_harness.py -- python3 -m mybinding.conformance   # another implementation
```

## Framing

- Both directions are UTF-8 JSON, one object per line (`\n`), no line breaks inside an object.
- The harness sends one request and waits for its answer before sending the next. An implementation answers every request, in order, and flushes after each answer.
- A request is `{"id": <id>, "op": "<op>", "input": <value>}`. `id` is any JSON value the harness chooses (a number in practice); the answer carries it unchanged. `info` takes no `input`.
- An answer is either `{"id": <id>, "output": <value>}` or `{"id": <id>, "error": {"category": "<category>", "message": "<text>"}}`, never both. `output` may be `null` where the operation says so.
- A line that is not a request object gets an error answer with `id` null and category `protocol`. Blank lines are ignored. The server exits with status 0 when its input ends.
- A request line is at most 64 MiB.

The answer to a vector that expects an error is an error answer of the expected category. `message` is for people: the vectors give the Go reference's wording as a substring, which the harness checks only with `--strict-messages`. The categories `protocol` (the request is malformed, or an input member is unknown or of the wrong type) and `unsupported` (the implementation does not provide the operation) are never the expected answer of a vector.

## Comparing outputs

The harness compares the parsed JSON of an output with the expected value: objects as unordered maps, arrays in order, numbers by value (`10` equals `10.0`), strings byte for byte. An implementation's own encoder is fine, with one rule for documents (the reports of `decode` and `mapping_apply`): an optional member that holds `false`, `0`, `""`, an empty array or an empty object is omitted, except the tri-state members of spec section 10 (rule 5), which keep `false`. The schemas give optional members no default, and the Go types omit such values; the vectors avoid them where the difference would show.

## Operations

Inputs are decoded strictly: a member an operation does not define is a `protocol` error.

| Op | Input | Output | Error categories | Vectors |
|---|---|---|---|---|
| `info` | (none) | `{"implementation", "version", "ctis": "2.0", "ops": [<ops it provides>]}` | | |
| `canonical` | `{"function", "value"}` | the canonical form: a string, or `{"identity", "version"}` for `CanonicalPurl` | `canonical` | `v2/canonical/*.json` |
| `asset_key` | `{"type", "value"}` | the asset key | | `v2/canonical/asset-key.json` |
| `vulnerability_id` | `{"id"}` | `{"type", "id"}`, or `null` when it is not an id | | `v2/vulnerability-id.json` |
| `preferred_id` | `{"vulnerability": <VulnerabilityDetails>}` | `{"type", "id"}`, or `null` | | `v2/preferred-id.json` |
| `location_key` | `{"finding": <Finding>}` (a partial finding: only the members the key reads) | the key (`""` for none) | | `v2/location-key.json` |
| `fingerprint` | `{"input": <recipe input>, "detect": <bool, optional>}` | `{"recipe", "parts", "value"}` | `fingerprint` | `v2/fingerprint/fingerprint.json` |
| `secret_digest` | `{"key_hex", "secret"}` | 64 lowercase hex digits | `fingerprint` | `v2/fingerprint/secret-digest.json` |
| `correlation_key` | `{"asset_key", "tool", "finding"}` | `{"vulnerability_id", "location_key", "key"}` | | `v2/correlation/correlation.json` |
| `web_url` | `{"url"}` | `{"origin", "path", "template", "params"}` | `web_url` | `v2/weburl/urls.json` |
| `decode` | `{"document": <JSON value>}` or `{"text": "<the document as text>"}` | `{"report", "unknown": [<entries>], "omitted"}` | `version`, `decode` | `v2/decode/decode.json` |
| `validate` | `{"document"}` or `{"text"}` | `{"valid": true}` | `version`, `decode`, `validate` | `v2/documents/manifest.json` |
| `mapping_apply` | `{"mapping", "input", "options"}` | `{"report", "stats"}` | `mapping`, `input` | `v2/mapping/vectors.json` |
| `interop_path_match` | `{"pattern", "path"}` | `true` or `false` | | `v2/interop-engine/path.json` |
| `interop_select` | `{"mappings": [...], "document"}` | the selected mapping's `version` | `mapping`, `input` | `v2/interop-engine/select.json` |
| `interop_collect` | `{"mapping", "document", "records": [<pointers>]}` | `{"version", "report", "records"}` | `mapping`, `input` | `v2/interop-engine/collect.json` |

Details:

- **`canonical`**: `function` is one of `CanonicalAssetValue` (value `{"type", "value"}`), `CanonicalDomain`, `CanonicalIP`, `CanonicalCIDR`, `CanonicalService` (value `{"host", "port", "transport"}`), `CanonicalOrigin`, `CanonicalURL`, `CanonicalRepository`, `CanonicalPurl`, `CanonicalCPE`, `CanonicalImage`, `CanonicalARN`, `CanonicalAzureResourceID`, `CanonicalGCPResourceName`, `CanonicalCertificateFingerprint`; the others take a string. The names are identifiers of the algorithms of [docs/canonical-forms.md](../docs/canonical-forms.md), not a requirement to name functions so. An unknown function is a `protocol` error.
- **`fingerprint`**: the input members are those of recipe `ctis-fp/2` ([docs/fingerprints.md](../docs/fingerprints.md)): `type`, `rule_id`, `vulnerability_id`, `file_path`, `start_line`, `end_line`, `snippet`, `logical_location`, `package_purl`, `secret_digest` (64 hex digits), `resource_type`, `resource_name`, `url`, `parameter`, `image_ref`, `asset_value`, `port`, `transport`, `framework`, `control_id`, `resource`, `chain_id`, `contract_address`, `function`. With `detect: true` and no `type`, the recipe is chosen by the detection order of fingerprints.md. `parts` are the normalised parts before encoding.
- **`correlation_key`**: `tool` is the tool name to use (the finding's own tool when it has one, else the report's: the caller decides). `vulnerability_id` is the second part of the key (the preferred id, or `rule:<tool>/<rule_id>`), `location_key` the third. With an empty `asset_key`, `key` is `""`.
- **`decode`** is the decoding of [docs/decoding.md](../docs/decoding.md) by a receiver of CTIS 2.0. `report` is the decoded document, `unknown` the entries `{path, kind, value?, fallback?}` sorted by `path`, then `kind`, and `omitted` the number of entries beyond the cap. A version problem is category `version`; anything else that refuses the document, `decode`.
- **`validate`** is a strict receiver: the version check (only the versions the implementation implements, so a newer minor is category `version`), strict decoding (an unknown member or a value of the wrong JSON type: `decode`), then the schema and [docs/validation-rules.md](../docs/validation-rules.md) (`validate`).
- **`mapping_apply`** applies a declarative mapping ([docs/mapping.md](../docs/mapping.md)). `mapping` is the mapping file as a JSON value, `input` the tool output as a string. `options`: `now` (RFC 3339; the report clock), `report_id`, `tool` (a CTIS `tool`), `channel`, `default_asset` (a CTIS asset), `observe` (boolean), `limits` (`max_input_bytes`, `max_record_bytes`, `max_records`, `max_outputs`, `max_issues`, `max_cell_bytes`, `max_xml_elements`). `stats` is `{records, assets, findings, dependencies, skipped, truncated, issues: [{record, rule}]}` plus `fields`, `fields_truncated` and `unmapped` with `observe`. Issue messages are not part of the output. A refused mapping file is category `mapping`, an input refused as a whole `input`.
- **`interop_select`** and **`interop_collect`** load the mappings with no hooks and no required tables ([docs/mapping-engine.md](../docs/mapping-engine.md)). `interop_collect` answers, for the document, the declared `version`, the report's extension value `report` (`null` when nothing was kept) and, for each requested record pointer, `{"extension": <extension value or null>, "set": {<dotted member>: <value>}}`: the members the set rules write into an empty record of the record's kind.

## Required and optional operations

`canonical`, `asset_key`, `vulnerability_id`, `preferred_id`, `location_key`, `fingerprint`, `secret_digest`, `correlation_key`, `web_url`, `decode` and `validate` are the core: every CTIS implementation provides them. `mapping_apply` (the declarative mapping language) and the `interop_*` operations (the adapter engine) are optional. An implementation lists what it provides in `info`; the harness skips optional operations that are not listed and fails required ones.

## Exit status of the harness

0 when every case of every provided operation passed, 1 when a case failed or a required operation is missing, 2 for a usage or protocol error (no answer within the timeout, an answer that is not JSON or does not carry the request's id).
