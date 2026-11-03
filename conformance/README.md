# CTIS conformance vectors

Plain JSON files that pin the behaviour every CTIS 2.0 implementation must share: canonical forms and asset keys, location keys, the preferred vulnerability id, fingerprint recipe v2, the secret digest, the correlation key, and which documents are valid. They are language neutral. Run them from your own test suite; this repository's Go implementation runs them with `go test ./...` and with `ctis conformance conformance/v2`.

A vector says what the output must be for an input. Nothing here is a guess about a producer: receivers recompute these values and never trust a producer's. Every input object is decoded strictly: a member name an implementation does not know is a failure, not something to skip.

The vectors of CTIS 1.x are on branch `release/v1` and at the v1.x tags.

## Files (under `v2/`)

| File | What it pins |
|---|---|
| `canonical/*.json` | The canonical-form functions: `function` names the function, each vector has `input`, and `output` or `error: true`. `asset-value.json` (`CanonicalAssetValue`) covers every 2.0 asset type; `asset-key.json` covers `AssetKey`; the other files cover one function each (domain, IP, CIDR, service, origin, URL, purl, image, cloud ids, certificate, CPE). |
| `location-key.json` | `LocationKey`: a partial 2.0 `finding` object to the expected key (`pkg:`, `url:`, `file:`, `net:`, `resource:`). |
| `preferred-id.json` | `PreferredVulnerabilityID`: a `vulnerability` object to the expected `{type, id}`, or `null`. CVEs compare numerically by year, then sequence number. |
| `fingerprint/fingerprint.json` | Recipe `ctis-fp/2`: the input, the normalised `parts`, the expected value, and inputs that must be refused (`error`). Text: [docs/fingerprints.md](../docs/fingerprints.md). |
| `fingerprint/secret-digest.json` | The HMAC-SHA256 secret digest. |
| `correlation/correlation.json` | Correlation key `ctis-ck/1`: the finding, the tool, the intermediate parts and the expected key. |
| `documents/manifest.json` | Every document and the result to reach, see below. |
| `documents/valid`, `documents/invalid` | Documents owned by this directory; the manifest also points at `examples/` and `examples/invalid/`. |

## Document manifest

Each entry has `file` (relative to the manifest) and `result`:

- `valid`: a strict receiver accepts the document;
- `invalid`: it refuses it, with `category` (`version`: a version this release does not implement, checked first, so a 1.x document is a version problem; `decode`: not JSON or an unknown member; `validate`: a semantic rule failed) and `error`, a substring of the message. An implementation that words its messages differently should match on `category` and treat `error` as informative.

`"schema_level": false` marks a document that `schemas/v2` alone accepts and only semantic checks refuse (unique ids, references, canonical asset values, score ranges per system, the implemented version). A pure JSON Schema implementation skips those; `scripts/validate_schemas.py` does.

## Running them in another implementation

1. Read each file with any JSON parser.
2. For every case, compute the output with your implementation and compare it to the expected value byte for byte.
3. For `documents`, run your strict decoder and validator over each file and compare the result with the manifest.

A failing vector is a bug in the implementation or a deliberate difference that must be reported upstream; do not edit the vectors to make a run pass.

## Adding vectors

Add a vector to the matching file, or a document plus its manifest entry (a test fails when an example is missing from the manifest). Fingerprint values are frozen: a new recipe gets its own file, and published values never change.
