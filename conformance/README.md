# CTIS conformance vectors

Plain JSON files that pin the behaviour every CTIS implementation must share: canonical forms, the correlation key and the fingerprint recipe, and which documents are valid. They are language neutral. Run them from your own test suite; this repository's Go implementation runs them with `go test ./...` and with `ctis conformance conformance`.

A vector says what the output must be for an input. Nothing here is a guess about a producer: receivers recompute these values and never trust a producer's.

## Files

| File | What it pins |
|---|---|
| `canonical/*.json` | `ctis.NormalizeAssetName`: asset `type` and `input` value to the `expected` canonical value, one file per family (domain, ip, host, repository, url, other). URL values keep the case of path and query. |
| `location-key.json` | `LocationKey`: a partial `finding` object to the expected key (`pkg:`, `url:`, `file:`, `net:`, `resource:`). Branch order: package, url from `web.url` then `location.path`, file, net, resource. |
| `preferred-id.json` | `PreferredVulnerabilityID`: a `vulnerability` object to the expected `{type, id}`, or `null`. CVEs compare numerically by year, then sequence number. |
| `fingerprint.json` | Fingerprint recipe v1 (`ctis-fp/1`, frozen): a finding `type` and `input` to the expected 64 hex characters. Input members are the snake_case names of the Go `fingerprint.Input` fields. |
| `documents/manifest.json` | Every document and the result to reach, see below. |
| `documents/valid`, `documents/invalid` | Documents owned by this directory; the manifest also points at `examples/` and `examples/invalid/`. |

Every vector file has a `cases` array (documents use `documents`). Unknown members are ignored.

## Document manifest

Each entry has `file` (relative to the manifest) and `result`:

- `valid`: a strict receiver accepts the document;
- `invalid`: it refuses it, with `category` (`decode`: not JSON or an unknown member, `version`: not a version this release implements, `validate`: a semantic rule failed) and `error`, a substring of the message. An implementation that words its messages differently should match on `category` and treat `error` as informative.

`"schema_level": false` marks a document that `schemas/v1` alone accepts and only semantic checks refuse (unique ids, references, the implemented version). A pure JSON Schema implementation skips those; `scripts/validate_schemas.py` does.

## Running them in another implementation

1. Read each file with any JSON parser.
2. For every case, compute the output with your implementation and compare it to `expected` byte for byte.
3. For `documents`, run your strict decoder and validator over each file and compare the result with the manifest.

A failing vector is a bug in the implementation or a deliberate difference that must be reported upstream; do not edit the vectors to make a run pass.

## Adding vectors

Add a case to the matching file, or a document plus its manifest entry (a test fails when an example is missing from the manifest). Fingerprint values are frozen: a new recipe gets its own file (`fingerprint-v2.json`) when it exists, and v1 values never change.
