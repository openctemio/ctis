# Version-gated decoding

This document is normative. It gives the steps of the compatibility rule of [spec.md](spec.md) section 2.2 ("version-gated must-ignore") as a receiver applies it, so that two implementations ignore, map and remove exactly the same things. The Go reference is `ctis.Decode`; the vectors are [`conformance/v2/decode/decode.json`](../conformance/v2/decode/decode.json), written for a receiver of CTIS 2.0.

Decoding checks shape only. A receiver runs the validation rules ([validation-rules.md](validation-rules.md) and the schema) on the result.

## 1. Version

1. Parse the document as JSON (RFC 8259). A document that is not one JSON value, or has data after it, is refused (category `decode`).
2. Read the top-level `version`. It is refused (category `version`) when it is missing, when it is not a string of the form `MAJOR.MINOR` (ASCII digits, at most four per number, no leading zero except `0` itself: `2.0` parses, `2`, `v2.0`, `2.01` and `2.0.0` do not), or when its major is not the receiver's. A 2.x receiver refuses every 1.x and 3.x document; the error names the major it reads. There is no conversion between majors.
3. A minor equal to or older than the receiver's newest minor is decoded **strictly** (section 2); a newer minor **leniently** (section 3).

## 2. Strict decoding

Every member of every object must be a member of the CTIS type at that place (the schemas set `additionalProperties: false` everywhere except the bags and typed maps of spec section 4). An unknown member, a value of the wrong JSON type, or trailing data refuses the document (category `decode`). Enum values are not judged here; an unknown one is refused by validation (the schema enum).

## 3. Lenient decoding (newer minor)

Walk the document along the CTIS types, starting at the report, and change it in place. Every change adds an entry to the list of section 4.

- **Object of a CTIS type.** Visit its members in the byte order of their names. A member the type does not have is removed (entry `member`). A known member's value is walked; when the walk says the value cannot be kept:
  - an optional member is removed (entry `removed`);
  - a required member (one the schema lists in `required`) cannot be removed: the whole object cannot be kept, and the walk stops in this object and hands the loss to the enclosing member or array item.
- **Array.** Each item is walked; an item that cannot be kept is removed from the array (entry `dropped`, at the item's pointer as received).
- **Enum value.** A known value is kept. A value of an open vocabulary (`native.scheme`, `compliance.frameworks[]`, `compliance.framework`) that is a token (`^[a-z0-9][a-z0-9_.-]{0,63}$`) is kept. Otherwise the value is unknown (entry `enum_value` with the value):
  - an enum with a fallback takes the fallback (the entry names it) and is kept;
  - `metadata.targets[].class` makes the enclosing target item unkeepable, so the target is dropped and never counts as done;
  - every other enum loses the value: it cannot be kept.
- **Typed map** (an object whose values have one CTIS type): an entry whose value cannot be kept is removed (entry `removed`).
- Bags and free-form values (`properties`, `extensions`, `partial_fingerprints`, `source_extra`, `whois`, `languages`, `technical.cloud.tags`, `technical.service.details`) are not walked. A value of the wrong JSON type is left for the strict decoding below.
- When the report itself cannot be kept, the document is refused (category `decode`).

Fallbacks:

| Enum | Fallback |
|---|---|
| `findings[].severity`, `rules[].default_severity` | `unknown` |
| `assets[].type`, `metadata.targets[].kind` | `unclassified` |
| `assets[].environment` | `unknown` |
| `endpoints[].kind` | `other` |
| `endpoints[].auth` | `unknown` |
| `technical.network_device.kind` | `other` |
| every other enum | none |

After the walk, an asset whose `state` is `gone` and that has no `state_reason` (because its reason was unknown and removed) loses its `state` (entry `removed` at `/assets/<i>/state`): an absence needs an authoritative reason the receiver understands.

The result is then decoded strictly (section 2).

Examples (all in the vectors): a finding of an unknown `type` is dropped; a target with an unknown `state` or `class` is dropped; an unknown `status` is removed; an unknown technique is dropped from `tool.techniques`; an unknown `severity` becomes `unknown`.

## 4. What was ignored

Each change is an entry `{path, kind, value, fallback}`:

- `path` is a JSON Pointer (RFC 6901) into the document **as received**;
- `kind` is `member` (an unknown member, removed), `enum_value` (an unknown enum value; `value` holds it, cut to 64 characters followed by `...` when longer, and `fallback` the value it was mapped to, absent when there is none), `removed` (an optional member removed because its value could not be kept) or `dropped` (an array item removed).

An unknown enum value without a fallback gives two entries: `enum_value`, then `removed` or `dropped` where the loss ends. The list is a set; the conformance protocol lists it sorted by path, then by kind. A receiver SHOULD keep it (or show it) so an operator sees what a newer producer sent. At most 1,000 entries are listed; the rest are counted.

A document of the receiver's minor or older has no entries: it is strict.
