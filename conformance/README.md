# CTIS conformance vectors

Plain JSON files that pin the behaviour every CTIS 2.0 implementation must share, whatever its language. Each family has normative text (linked below) and vectors: an input and the output it must give, or the error category it must give. Run them through the line protocol of [PROTOCOL.md](PROTOCOL.md) with the harness:

```sh
python3 scripts/conformance_harness.py -- <your implementation's protocol server>
python3 scripts/conformance_harness.py -- ctis conformance --serve   # the Go reference
```

or read the files from your own test suite. This repository's Go implementation runs them in `go test ./...`, with `ctis conformance conformance/v2`, and through the harness in CI.

A vector says what the output must be for an input. Nothing here is a guess about a producer: receivers recompute these values and never trust a producer's. Every input object is decoded strictly: a member name an implementation does not know is a failure, not something to skip. A failing vector is a bug in the implementation or a deliberate difference that must be reported upstream; do not edit the vectors to make a run pass.

The vectors of CTIS 1.x are on branch `release/v1` and at the v1.x tags. The vectors of the interoperability adapters (upstream samples, round trips) are under [`interop/`](interop) and described in [docs/interop.md](../docs/interop.md).

## Index (`v2/`)

| Family (protocol op) | File | Normative text | Required |
|---|---|---|---|
| Canonical forms (`canonical`) | `canonical/*.json`: `asset-value.json` (every asset type), one file per algorithm (domain, IP, CIDR, service, origin, URL, repository, purl, CPE, image, cloud ids, certificate) | [canonical-forms.md](../docs/canonical-forms.md) sections 2 to 6 | yes |
| Asset key (`asset_key`) | `canonical/asset-key.json` | [canonical-forms.md](../docs/canonical-forms.md) section 7 | yes |
| Vulnerability ids (`vulnerability_id`) | `vulnerability-id.json` | [canonical-forms.md](../docs/canonical-forms.md) section 8.1 | yes |
| Preferred vulnerability id (`preferred_id`) | `preferred-id.json` | [canonical-forms.md](../docs/canonical-forms.md) section 8.2 | yes |
| Location key (`location_key`) | `location-key.json` | [canonical-forms.md](../docs/canonical-forms.md) section 9 | yes |
| Fingerprint recipe `ctis-fp/2` (`fingerprint`) | `fingerprint/fingerprint.json` (every recipe, recipe detection, refusals) | [fingerprints.md](../docs/fingerprints.md) | yes |
| Secret digest (`secret_digest`) | `fingerprint/secret-digest.json` | [fingerprints.md](../docs/fingerprints.md) | yes |
| Correlation key `ctis-ck/1` (`correlation_key`) | `correlation/correlation.json` | [fingerprints.md](../docs/fingerprints.md) | yes |
| Web URLs and path templates (`web_url`) | `weburl/urls.json` | [canonical-forms.md](../docs/canonical-forms.md) section 4.3 | yes |
| Version-gated decoding (`decode`) | `decode/decode.json` | [decoding.md](../docs/decoding.md), spec section 2.2 | yes |
| Documents: valid and invalid (`validate`) | `documents/manifest.json` | [spec.md](../docs/spec.md), [validation-rules.md](../docs/validation-rules.md) | yes |
| Declarative mappings (`mapping_apply`) | `mapping/vectors.json` | [mapping.md](../docs/mapping.md) | no |
| Interop engine paths (`interop_path_match`) | `interop-engine/path.json` | [mapping-engine.md](../docs/mapping-engine.md) section 2 | no |
| Interop engine detection (`interop_select`) | `interop-engine/select.json` | [mapping-engine.md](../docs/mapping-engine.md) section 3 | no |
| Interop engine set rules and passthrough (`interop_collect`) | `interop-engine/collect.json` | [mapping-engine.md](../docs/mapping-engine.md) sections 4 and 5 | no |

## File formats

- `canonical/*.json`: `function` names the algorithm (a vector may override it), each vector has `input`, and `output` or `error: true`; `note` explains an edge case.
- `vulnerability-id.json`, `location-key.json`, `preferred-id.json`: `cases` of `{name, <input member>, expected}`.
- `fingerprint/fingerprint.json`: `cases` of `{name, type, detect?, input, parts, expected}` or `error: true`. `parts` are the normalised parts, so each step can be compared. `detect: true` leaves the recipe to the detection order.
- `fingerprint/secret-digest.json`: `key_hex` and `cases` of `{secret, expected}`.
- `correlation/correlation.json`: `cases` of `{name, asset_key, tool, finding, vulnerability_id, location_key, expected}`.
- `weburl/urls.json`: `cases` of `{in, origin, path, template, params}` or `{in, error: true}`.
- `decode/decode.json`: `cases` of `{name, document | text, expected: {report, unknown, omitted}}` or `error: {category}`, for a 2.0 receiver.
- `documents/manifest.json`: see below.
- `mapping/vectors.json`: `cases` of `{name, mapping | mapping_file, input | input_file, options, expected_report | expected_report_file, expected_stats}` or `error: {category}`; `*_file` paths are relative to `mapping/`.
- `interop-engine/path.json`: `cases` of `{pattern, path, match}`. `select.json`: `mappings` and `cases` of `{name, document, expected}` or `error`. `collect.json`: `cases` of `{name, mapping, document, records, expected}`.

## Document manifest

Each entry has `file` (relative to the manifest) and `result`:

- `valid`: a strict receiver accepts the document;
- `invalid`: it refuses it, with `category` (`version`: a version this release does not implement, checked first, so a 1.x document is a version problem; `decode`: not JSON, an unknown member or a value of the wrong JSON type; `validate`: the schema or a semantic rule failed) and `error`, a substring of the message. An implementation that words its messages differently matches on `category` and treats `error` as informative.

`"schema_level": false` marks a document that `schemas/v2` alone accepts and only the semantic rules refuse. `rule` names the rule of [validation-rules.md](../docs/validation-rules.md) the document breaks; every rule there has at least one such document. A pure JSON Schema implementation skips the `schema_level: false` documents; `scripts/validate_schemas.py` does.

## Adding vectors

Add a vector to the matching file, or a document plus its manifest entry (a test fails when an example is missing from the manifest, and when a validation rule has no document). Run `go test ./...` and the harness. Fingerprint values are frozen: a new recipe gets its own file, and published values never change. A new behaviour gets normative text, a vector family and a protocol operation together.
