# Interoperability mapping engine

This document is normative for the engine that reads the adapter mapping files (`apiVersion: openctem.io/interop/v1`) of the interoperability layer: the file format, the path grammar, version detection, set rules and their transform registry, and the passthrough with its bounds and scrubbing. [interop.md](interop.md) describes the adapters that use it; the Go reference is the package `interop/engine`. The declarative mapping language for tool output (`openctem.io/mapping/v2`) is a different language, specified in [mapping.md](mapping.md).

The engine does the field-to-field part of a conversion. What is not field to field is a **hook**: a function of the adapter that a mapping names. Hooks are code of each adapter and are not specified here; an implementation of the engine without the hooks of an adapter cannot run that adapter's mappings, but it can run the engine vectors ([`conformance/v2/interop-engine`](../conformance/v2/interop-engine)), which use no hooks.

## 1. File

A mapping file is one JSON object, at most 512 KiB. Unknown members are errors. An implementation refuses the whole file when any rule below fails.

| Member | Rule |
|---|---|
| `apiVersion` | `openctem.io/interop/v1` |
| `format` | `^[a-z][a-z0-9-]*$`, at most 32 bytes |
| `version` | the upstream version, `^[0-9]+(\.[0-9]+){0,3}$` |
| `direction` | `import` or `export` |
| `namespace` | the extensions namespace of the passthrough: reverse-DNS, as for `extensions` (spec section 8) |
| `title` | non-empty, at most 2048 bytes; `source` at most 2048 bytes |
| `notes` | at most 64, each at most 4096 bytes |
| `detect` | import only; at most 8 predicates (section 3) |
| `version_pointer` | import only; a JSON Pointer with at least one token |
| `fold` | at most 16 rules `{from, to}`: both start with `/`, `from` is longer than `to`, `from` at most 1024 bytes, no `*` in either |
| `records` | at most 16 records `{name, path, kind}`: `name` matches `^[a-z][a-z0-9_.]{0,63}$` and is unique, `path` starts with `/` and has at most 1024 bytes, `kind` is `finding`, `asset`, `dependency` or `vex` |
| `fields` | 1 to 2000 fields with distinct `path`s (section 1.1) |
| `tables` | at most 64 tables; a name matches `^[a-z][a-z0-9_.]{0,63}$`; each has `map` (1 to 512 entries, keys and values at most 2048 bytes), optional `match` (`exact`, the default, `fold` or `token`) and optional `default`. Every key must already be in its match form (section 4.2). |
| `hooks` | the adapter functions the mapping uses; each must be registered by the adapter and name at least one field |
| `reemit_from` | export only; dotted versions |
| `passthrough` | lower limits (section 5.3) |

An adapter also names the tables its code looks up; a mapping without one of them is refused.

### 1.1 Fields

A field is `{path, ...}` with exactly one of: a target (`target`, `set` or `hook`, or several of them) or `ignored` (the reason it is dropped).

- `path` starts with `/` and has at most 1024 bytes (section 2).
- `target` is text for readers; `(container)` marks a member that only groups others.
- `hook` must be listed in `hooks`.
- A **set rule** (`set`, import only) names `record` (a declared record) and optional `transform` (at most 8, section 4.2). Its `path` starts with the record's path followed by `/`, has no `[]` after the record's path and no `*` anywhere: a set rule reads one member of its record. `set` is a dotted member name (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){0,7}$`) of the record's CTIS type (`finding`, `asset`, `dependency`, or the VEX statement for `vex`): every name but the last is an object member, the last is a text, integer, number or boolean member. The first name is never `id`, `asset_ref`, `dependency_ref`, `rule_ref`, `fingerprint`, `depends_on`, `extensions` or `properties`. A set rule has no hook.

## 2. Paths

A **path** names the members of a source document the way the engine walks it:

- an object member is `/` followed by its **path key**: the member name with every control character (below U+0020, and U+007F), `/`, `[` and `]` replaced by `_`, cut to 128 bytes on a character boundary;
- an array element is its array's path followed by `[]`; the elements of a top-level array are `/[]`.

`{"runs": [{"results": [{"ruleId": "x"}]}]}` has the paths `/runs`, `/runs[]`, `/runs[]/results`, `/runs[]/results[]` and `/runs[]/results[]/ruleId`.

A **pattern** is a path in which a segment (the text between two `/`) may contain `*`, which matches any run of characters within one segment (including none, and including `[]`), and a segment `**` matches zero or more whole segments. A pattern without `*` matches only the identical path. Matching splits both at `/` and is case-sensitive.

A pattern matches **below** a path when it can match some path that continues it: the path is a proper prefix of a matched path, segment by segment; a `**` can always continue, and a pattern segment `x[]` continues a path whose last segment is `x` (the array elements are below the array).

A **pointer** is an RFC 6901 JSON Pointer to one value (`/runs/0/results/3`). Its path replaces each array index (a token of digits without a leading zero, in an array) by `[]` on the previous segment.

**Fold** rules make a recursive structure one list of paths: before a path is matched, the first rule whose `from` equals the path, or is followed in the path by `/` or `[`, replaces that prefix with `to`; this repeats until no rule applies (at most 64 times). With `{"from": "/components[]/components", "to": "/components"}`, `/components[]/components[]/name` reads as `/components[]/name`.

Vectors: `conformance/v2/interop-engine/path.json`.

## 3. Detection

An adapter loads the import mappings of all its upstream versions side by side and picks the one for a document:

1. Collect the pointers of every predicate of every mapping. Read the document once and take, for each pointer, the **first** value found at it, following object members only (a pointer never steps into an array). A string is its text, a number its JSON text as written, `true` and `false` their names; an object or an array is *present without a value*; `null` counts as absent.
2. A predicate `{pointer, <test>, or_absent}` holds:
   - `absent: true`: when the pointer is absent;
   - otherwise, when the pointer is absent: when `or_absent` is true;
   - when present without a value: never;
   - `equals`: the text is equal; `in` (a list): the text is one of them; `prefix`: the text starts with it; `matches`: an RE2 regular expression (at most 256 bytes) matches somewhere in the first 4096 bytes of the text.
   A predicate has exactly one test; `or_absent` does not go with `absent`.
3. The mapping is the first, in the order the adapter gives them (adapters give them by version), that has at least one predicate and whose predicates all hold. When none does, the document is refused.

Vectors: `conformance/v2/interop-engine/select.json`.

## 4. Records and set rules

### 4.1 Records

While walking the document, the first value whose path (after folding) matches a record's `path`, and that is not already inside a record, starts a record of that kind; its pointer identifies the record. The values below it belong to it.

A set rule's value is the scalar found at its path within a record (the JSON token: string, number, boolean or `null`). The adapter applies the set rules of a record to the CTIS record it builds, in field order:

1. The text of the value: a string as it is; a number as its shortest decimal form without an exponent (`1e2` is `100`, `1.0` is `1`, `42.5` stays `42.5`); `true` or `false`. `null`, an object or an array gives no value.
2. The transforms, in order. A transform that rejects the value makes it missing; a missing value leaves the member as it was.
3. The text is cut to 64 KiB on a character boundary.
4. It is converted to the member's type: text as it is; an integer from the trimmed text in base 10 with an optional sign, at most 2^53 in absolute value; a number from the trimmed decimal or exponent form (not NaN); a boolean from the trimmed text, one of `1`, `t`, `T`, `TRUE`, `true`, `True` and `0`, `f`, `F`, `FALSE`, `false`, `False`. A value that does not convert leaves the member as it was. Objects on the way to the member are created.

### 4.2 Transform registry

| Transform | Effect |
|---|---|
| `trim` | remove leading and trailing white space (Unicode `White_Space`) |
| `lower`, `upper` | Unicode simple case mapping, code point by code point |
| `token` | trim, lowercase, then remove every `_`, `-` and space |
| `line` | remove every control character (Unicode `Cc`) except TAB, LF and CR, then replace every run of white space with one space and trim |
| `table:<name>` | look the value up in the table: normalise it by the table's `match` (`exact`: as it is; `fold`: trimmed and lowercased; `token`: as `token`), take the entry's value, else the table's `default`, else reject |
| `max_bytes:<n>` | cut to `n` bytes (1 to 1048576) on a character boundary |
| `http_url` | reject the value unless it is an absolute `http` or `https` URL with a host, at most 2048 bytes, without control characters (the free-form definition of [canonical-forms.md](canonical-forms.md)) |

No other transform exists: a mapping that names one is refused. The language has no expressions, loops, code, file or network access.

Vectors: the set rules of `conformance/v2/interop-engine/collect.json`.

## 5. Passthrough

### 5.1 What is kept

The engine walks the import document once. For each value (not the document itself) it computes the path and folds it, and classifies it by the fields:

- the first field whose pattern matches the path decides whether it is **listed** and whether it is **ignored**;
- it has something **below** when some field's pattern matches below the path.

Then:

1. A listed, ignored value is skipped with everything below it: it is never kept, whatever is inside.
2. A listed value, or one with something listed below, is not kept itself; the walk continues inside it.
3. Any other value is **kept** whole: on its record when it is inside one, with a pointer relative to the record's pointer (`/note` for `/results/0/note`), otherwise on the report with its absolute pointer.

### 5.2 Scrubbing

A kept value is scrubbed before it is stored:

- A member whose name matches, case-insensitively, `passw|passwd|pwd$|secret|token|api[-_]?key|authori[sz]ation|cookie|credential|private[-_]?key|^env$|environment[-_]?variables|command[-_]?line|^arguments$` is dropped, at any depth. A kept value whose own member name matches is dropped silently (it does not mark the object truncated).
- A string held by a member whose name ends in `uri`, `url` or `href` (case-insensitive; an array item takes its array's member name) is dropped when, trimmed, it starts with a scheme (`^[A-Za-z][A-Za-z0-9+.-]*:`) other than `http` or `https`. A relative reference is kept.
- Every remaining string has its credentials masked (the Go reference uses `ctis.RedactCodeSecrets`: quoted values assigned to credential names, the password of a URL's user info, tokens of a recognisable form and private key blocks). The exact mask is not part of the vectors; an implementation MUST mask at least what that function masks, and MAY mask more.
- The adapter masks a secret finding's raw match in its record's kept values too.

A kept value is never interpreted and never placed into a core member.

### 5.3 Bounds

| Limit | Default | Hard maximum |
|---|---|---|
| `max_entries`: kept members per object (the report, or one record) | 64 | 256 |
| `max_bytes`: bytes kept per object | 16 KiB | 32 KiB |
| `max_depth`: nesting inside one kept value | 12 | 16 |
| `max_records`: records that keep members | 10,000 | 100,000 |
| `max_total_bytes`: bytes kept for the document | 8 MiB | 32 MiB |

A mapping's `passthrough` lowers a limit (0 keeps the default); a value above the hard maximum refuses the mapping. For each value to keep, in this order:

1. When its encoded text is longer than `max_bytes`, or the object already holds `max_entries` members, it is dropped and the object is marked truncated.
2. When it nests deeper than `max_depth` (the value is depth 0 and each object or array adds one; a scalar at depth `max_depth` is still allowed), it is dropped and the object marked truncated. When scrubbing (5.2) drops the value itself, it is dropped without the mark.
3. Its size is the length of its pointer plus the length of its scrubbed encoding plus 6. When the object's kept size plus this exceeds `max_bytes`, or the document's kept size plus this exceeds `max_total_bytes`, it is dropped and the object marked truncated.
4. Otherwise it is kept and the sizes grow.

A record beyond `max_records` keeps nothing. Encodings are compact JSON with object members sorted by name, numbers as written and no escaping of `<`, `>` and `&`; an encoder that differs can judge a value close to a byte bound differently, so the vectors stay clear of the bounds.

### 5.4 Where it goes

The kept members of an object become its extension value under the mapping's namespace:

```json
{"version": "<upstream version>", "unmapped": {"<pointer>": <value>}, "truncated": true}
```

`truncated` is present only when something was dropped by a bound. An object that kept nothing and was not truncated gets no extension value. The version is the document's: the scalar at `version_pointer` when it matches `^[0-9]+(\.[0-9]+){0,3}$`, else the mapping's `version`.

Vectors: `conformance/v2/interop-engine/collect.json` (unmapped members on the report and on records, ignored subtrees, credential names, URL schemes, each bound, fold, the declared version).

### 5.5 Write-back (export)

An export mapping writes the kept members back (`Mapping.Reemit`) when the document's extension value comes from a version in `reemit_from` or the mapping's own: only at a pointer where the output has no member yet and that the export mapping does not own (no field matches it or anything below it); it never overwrites a mapped member, never creates array elements, and scrubs the values again. Which parts of a format are written back is the adapter's choice ([interop.md](interop.md)); it is covered by the adapter vectors under `conformance/interop/`, not by the engine vectors.
