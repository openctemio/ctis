# Porting CTIS to a new language

CTIS is specified independently of Go: the format is the JSON Schema in [`schemas/v2`](../schemas/v2), the behaviour is normative text with conformance vectors in [`conformance/v2`](../conformance/v2), and a line protocol ([conformance/PROTOCOL.md](../conformance/PROTOCOL.md)) lets one harness test any implementation. A binding for another language (Python, Rust, ...) is therefore mostly generated and tested, not translated from the Go code. This page says how. Bindings live under [`bindings/`](../bindings/README.md).

## 1. Types: generate them from the schemas

The schemas are the source of truth. Go keeps hand-written types behind a strict parity test (`TestSchemaGoParity`: both directions, types, required members, enums, `additionalProperties`); another language generates its types from `schemas/v2` with its JSON Schema tooling (a code generator that reads JSON Schema 2020-12) and commits the generated code with the generator version that made it.

Check the generated types against these rules, which every implementation needs:

- Load all eight schemas: `report.json` references the others by relative `$ref` (`scripts/validate_schemas.py` builds the registry).
- Strict decoding: every object except the bags (`properties`, `extensions`) and the typed maps (`partial_fingerprints`, `source_extra`, `whois`, `languages`, `technical.cloud.tags`, `technical.service.details`) refuses unknown members. Most generators need an option for this.
- Enums are closed, except the open vocabularies of spec section 2.2. Version-gated decoding ([decoding.md](decoding.md)) needs to know, per enum, its fallback; keep that table next to the generated types.
- The tri-state booleans of spec section 10 (rule 5) need a type that tells absent from `false`. Other optional members may be omitted when they hold their zero value (PROTOCOL.md, "Comparing outputs").
- Timestamps are RFC 3339 with an offset; dates (`*_on`) are `YYYY-MM-DD`.

Regenerate when the schema changes; a parity test like Go's (generated types against the schema) keeps them honest.

## 2. Behaviour: implement the families in order

Each family has normative text and vectors. Implement them in this order, because later ones use earlier ones:

| Step | Family (protocol op) | Text |
|---|---|---|
| 1 | Canonical forms (`canonical`), asset key (`asset_key`) | [canonical-forms.md](canonical-forms.md) sections 1 to 7 |
| 2 | Vulnerability ids (`vulnerability_id`), preferred id (`preferred_id`) | [canonical-forms.md](canonical-forms.md) section 8 |
| 3 | Location key (`location_key`) | [canonical-forms.md](canonical-forms.md) section 9 |
| 4 | Web URLs (`web_url`) | [canonical-forms.md](canonical-forms.md) section 4.3 |
| 5 | Fingerprint recipe v2 (`fingerprint`), secret digest (`secret_digest`), correlation key (`correlation_key`) | [fingerprints.md](fingerprints.md) |
| 6 | Version-gated decoding (`decode`) | [decoding.md](decoding.md) |
| 7 | Validation (`validate`): the schema, then the rules beyond it | [validation-rules.md](validation-rules.md) |
| 8 (optional) | Declarative mappings (`mapping_apply`) | [mapping.md](mapping.md) |
| 9 (optional) | Interop engine (`interop_path_match`, `interop_select`, `interop_collect`) | [mapping-engine.md](mapping-engine.md) |

Traps the vectors catch (each has a vector):

- Lowercasing is the Unicode *simple* mapping, per code point. A language's default "lower" often applies the full mapping (`İ` to two code points, a final sigma).
- Trimming removes `White_Space` code points only; some "strip" functions also remove U+001C to U+001F.
- IDNA is "lite": Punycode of the lowercased label, no UTS 46 mapping, no NFC. An IDNA library gives different answers for fullwidth letters, `ß` and decomposed accents.
- IPv4 parts with a leading zero are refused, not read as octal or decimal; IPv6 is written per RFC 5952 without an embedded dotted quad.
- The location key does not reuse the canonical URL: it keeps the path as written.
- Fingerprint parts are length-prefixed UTF-8 bytes joined with 0x1F; there is no Unicode normalisation anywhere.
- Validation counts bytes, not characters, for the bounds that `validation-rules.md` says so.

## 3. The protocol server and the harness

Write a small program that reads requests from standard input and answers on standard output ([PROTOCOL.md](../conformance/PROTOCOL.md)): about one function per operation, each calling the binding. List the operations you provide in `info`. Then run:

```sh
python3 scripts/conformance_harness.py -- <command that starts your server>
```

The harness walks every vector, reports passed, failed and skipped cases per operation, and exits 0 only when every required operation passes. Run it in the binding's CI against the vectors of the CTIS version the binding claims; pin that version (the vectors are versioned with the specification). `--only canonical,asset_key` runs a subset while you work; `--list` shows the cases without running anything.

A binding is conformant for CTIS 2.0 when the harness passes for all required operations.

## 4. Required and optional parts

Required (the core): the generated types, strict and version-gated decoding, validation, canonical forms and asset keys, vulnerability ids, location keys, web URLs, fingerprints, the secret digest and the correlation key: the operations `canonical`, `asset_key`, `vulnerability_id`, `preferred_id`, `location_key`, `fingerprint`, `secret_digest`, `correlation_key`, `web_url`, `decode`, `validate`.

Optional:

- the declarative mapping language (`mapping_apply`), for a binding that imports tool output without code;
- the interop engine (`interop_*`) and the adapters (SARIF, CycloneDX, SPDX, CSAF, OpenVEX, OCSF). An adapter is its mapping files (data, reusable as they are) plus hooks (code of the adapter, specified by its mapping notes and its vectors under `conformance/interop/`);
- the tool importers of the Go `importer` package, the converters and the exporters. These are Go conveniences, not part of the format.

A producer-only binding still needs the canonical forms, the asset key and the fingerprints (it computes values receivers recompute), and SHOULD run validation before sending.

## 5. Keeping up

- A patch release of CTIS never changes the format; it may add vectors and text. Re-run the harness on each release.
- A minor release adds members and enum values: regenerate the types, add the new enum fallbacks, and run the new vectors.
- When a vector fails and you believe the vector is wrong, report it upstream instead of changing it: the vectors are the shared contract.
