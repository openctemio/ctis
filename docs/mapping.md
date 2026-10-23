# Declarative mappings (`openctem.io/mapping/v1`)

A mapping turns the JSON, JSON Lines, CSV or XML output of a tool, or an export of a product, into a CTIS report without parser code. The package is `github.com/openctemio/ctis/importer/mapping`:

```go
m, err := mapping.Load(mappingJSON)          // strict; refuses anything outside the language
report, stats, err := m.Apply(ctx, toolStdout, mapping.Options{
    Now:  clock,                              // injected for reproducible output
    Tool: &ctis.Tool{Name: "example-portscan", Version: "1.2.0"},
})
digest := m.Digest()                          // "sha256:<hex>" of the canonical mapping
```

The file is JSON. A tool that keeps its mapping in YAML converts it to JSON first; `Load` is the authority on what is valid.

## 1. File

```json
{
  "apiVersion": "openctem.io/mapping/v1",
  "source": "jsonl",
  "notes": "free text for readers",
  "records": [
    {
      "when": {"path": "/port", "exists": true},
      "kind": "asset",
      "set": {
        "type": {"const": "open_port"},
        "value": {"template": "{ip}:{port}", "vars": {"ip": "/ip", "port": "/port"}},
        "properties.host": "/ip",
        "properties.port": {"path": "/port", "as": "integer"},
        "properties.protocol": {"path": "/protocol", "lower": true, "default": "tcp"}
      }
    }
  ]
}
```

| Member | Meaning |
|---|---|
| `apiVersion` | Always `openctem.io/mapping/v1`. |
| `source` | `jsonl`: one JSON value per line. `json`: one document. `csv`: a header row, then one record per row (§1.1). `xml`: one document (§1.2). |
| `each` | `json`: the path of the list of records. Absent: a top-level list is the records; any other value is one record. `xml` (required): the elements that are records. Not allowed for `jsonl` and `csv`. |
| `csv` | `csv` only: `delimiter` and `skip_rows` (§1.1). |
| `identity` | The finding members that identify a finding (§2.1). |
| `records` | The rules, 1 to 200. **Every** rule whose `when` holds emits one CTIS record for the input record, in rule order. |
| `notes` | Free text, ignored. |

Unknown members are errors everywhere.

### 1.1 CSV

```json
{"apiVersion": "openctem.io/mapping/v1", "source": "csv", "csv": {"delimiter": "auto", "skip_rows": 0}, "records": [...]}
```

- `delimiter` is `,`, `;`, `\t`, `|` or `auto` (the default). `auto` takes the one of these that occurs most often outside double quotes in the header row; a tie goes to the earlier one in that list, and a header with none is one column. Set it when a header could mislead the count.
- `skip_rows` (0 to 100) are lines before the header row, such as a report title or an export date.
- Quoting follows RFC 4180: a quoted cell may hold the delimiter, a line break, or a doubled quote (`""`). A row whose quoting is malformed is skipped with an issue; the rows after it are read.
- A UTF-8 byte order mark is removed. A UTF-16 byte order mark fails the input with `ErrEncoding` (save the file as UTF-8).
- Each data row is a record: an object of its cells keyed by column name. Paths are `/` plus the column name with JSON Pointer escapes: column `CVE ID` is `/CVE ID`, column `a/b` is `/a~1b`.
- Column names are trimmed. An empty name becomes `column_<n>` (1-based) and a repeated one gets `_2`, `_3`, ... so every column has a path.
- A cell is text, exactly as written. A cell that is empty or only spaces is left out of the record, so `exists` tells a filled cell from an empty one. Use `as: integer` for numbers.
- A cell is never evaluated: `=HYPERLINK(...)` is the text `=HYPERLINK(...)`. A receiver that writes values back into a spreadsheet neutralises such text there.
- Cells beyond the header row are ignored with an issue. Records are numbered by the line their row starts on.

### 1.2 XML

```json
{"apiVersion": "openctem.io/mapping/v1", "source": "xml", "each": "//testcase", "records": [...]}
```

- `each` is an absolute element path from the root (`/testsuites/testsuite/testcase`) or `//name`: every element of that name at any depth. An element nested in a record is part of it, never a record of its own. Names are local names: namespace prefixes are left out.
- An element becomes a value:
  - with no attributes and no child elements, its text, trimmed;
  - otherwise an object: each attribute as `@name`, each child element by its name, and the element's own text, when it has some, as `#text`.
- A child element that occurs more than once is a list in document order.
- Paths walk this leniently, because one document may hold one `<item>` where the next holds several:
  - a step through a repeated element reads its first occurrence (`/failure/@message`);
  - index 0 of a single element is the element (`/ref[0]`);
  - `#text` of a text-only element is its text.
  - A path that ends on a repeated element gives the list: use `first` or `join` for one value. Set on a list member such as `tags`, it is the list.
- The reader is hardened, and an input that breaks one of these rules fails as a whole:
  - no document type declaration of any kind, so no entity can be declared or expanded (no billion laughs) and no external resource is named or read (no XXE);
  - only the five predefined entities;
  - UTF-8, US-ASCII or ISO-8859-1;
  - one root element;
  - depth at most 64, at most `MaxXMLElements` elements (default 4 000 000) and 64 attributes per element, a text node or attribute at most `MaxRecordBytes`.
- A record element larger than `MaxRecordBytes` is skipped with an issue. `each` that matches nothing is an issue, not an error.

## 2. Rules

| Member | Meaning |
|---|---|
| `when` | A predicate object or a list of up to 16 that must all hold. Absent: always. |
| `kind` | `asset`, `finding` or `dependency`. |
| `set` | CTIS member (dotted path) → value, 1 to 100 entries. |

Predicates take a `path` and exactly one of:

- `exists` (`true`/`false`; a JSON `null` does not exist);
- `equals` (a string, number or boolean, compared as text);
- `in` (1 to 256 such values);
- `matches` (an RE2 regular expression of at most 256 bytes, matched against the first 4 KiB of the value).

A predicate on an object or a list is false.

### Targets

A target is a dotted path of CTIS JSON member names relative to the record of the rule's kind: `value`, `technical.certificate.not_after`, `network.port`, `vulnerability.cve_id`. `Load` checks every target against the CTIS types:

- An object is set member by member: `location.path`, not `location`. Two targets may not overlap.
- Lists of strings may be set (`tags`, `vulnerability.cwe_ids`). Lists of objects may not.
- A free-form map takes exactly one key below it: `properties.<key>`, `technical.service.details.<key>`, `source_extra.<key>`.
- Never settable: report-level members (`metadata`, `tool`, `$schema`), `id`, and the links between records (`asset_ref`, `related_assets`, `depends_on`, `related_locations`, `stacks`, `attachments`, `data_flow`). A tool's output cannot forge references or claim to be another tool.
- Required: `type` and `value` for an asset, `title` and `severity` for a finding, `name` for a dependency. A constant asset `type` must be a CTIS asset type.
- A constant `fingerprint` is refused: every finding of the rule would be one finding.
- One value set on a list member is a one-item list.

### 2.1 Identity

`identity` lists 1 to 8 finding members, such as `["rule_id", "location.path"]`, that tell one finding from another. It documents which inputs decide identity, so a receiver can show them and notice when a new version of a mapping changes them.

- Every finding rule must set every listed member.
- In no rule may all listed members be constants: that would make every finding of the rule one finding.
- A finding whose listed members are all empty is skipped with an issue.
- The mapping never computes a fingerprint from them. The receiver decides identity from the CTIS members, as for any other report.

A receiver reads `Identity()` and `Rules()`: the kind, targets, canonical value spec, and constant targets of every rule. It uses them to apply its own policy (members it reserves) and to compare two versions of a mapping.

### Values

A bare string is a source path. An object takes exactly one source:

| Source | Meaning |
|---|---|
| `path` | A source path. |
| `const` | A string, number, boolean or list of strings. |
| `template` + `vars` | Text with named variables: `"{host}:{port}"`, `vars: {"host": "/ip", "port": "/port"}`. Every variable is declared and every declared variable is used. Other braces are errors. A missing or empty variable makes the value missing. |

It then applies the transforms in this order:

1. `first`: the first element of a list (a single value is its own first).
2. `trim`, `lower` or `upper`: on a string, or on every string of a list.
3. `split`: a string to a list, at a separator of at most 16 bytes. Items are trimmed, empties are dropped, and at most 1000 are kept.
4. `map`: a table of at most 256 entries. An unmapped value is missing, and an unmapped list item is dropped.
5. `join`: a list to a string. Objects and empty items are skipped.
6. `as`: `integer` (whole numbers within ±2^53−1, from a number or a numeric string), `boolean`, or `string`. A value that does not convert is missing.
7. `max_bytes`: truncate (1 to 1 MiB) on a UTF-8 boundary.

`default` (a string, number, boolean or list of strings) replaces a missing or empty result. Without one, a missing value leaves the member unset.

A source object is never a value.

### Paths

- Paths are `/a/b`, `/a/0`, `/a[0]` and `/` (the record).
- Member names use JSON Pointer escapes (`~1` for `/`, `~0` for `~`).
- A path has at most 32 steps and 512 bytes.

## 3. Output and checks

- The report has `version`, `$schema`, `metadata.timestamp` (`Options.Now`, UTC), `metadata.source_type: scanner`, and `tool` from `Options.Tool` only.
- A finding without a `type` is a `vulnerability`.
- A `secret` finding goes through `ctis.RedactSecretFinding`, so a raw secret mapped into the title, snippet or `secret.masked_value` is masked.
- Each emitted record is decoded strictly into its CTIS type and validated with `Report.Validate`. A record that fails is skipped, and `Stats.Issues` says why, with the input record number and the rule index.
- Output is deterministic for the same input, mapping and clock.
- With `Options.Observe`, `Stats.Fields` lists the input's fields as source paths, at most 512, with `Stats.FieldsTruncated` set when there were more. For CSV they are the header columns in order; for JSON and XML, the leaf paths without list indexes, sorted. `Stats.Unmapped` lists the fields that no predicate, value or template variable reads. A path covers itself and everything below it. A mapping editor shows both.

## 4. Limits (hostile input)

| Limit | Default | Option |
|---|---|---|
| Input | 64 MiB, else `ErrInputTooLarge` | `MaxInputBytes` |
| One JSON Lines line, CSV row or XML record | 1 MiB, longer ones are skipped | `MaxRecordBytes` |
| One CSV cell | 64 KiB, the row is skipped | `MaxCellBytes` |
| CSV columns | 1024, else an error | — |
| XML elements | 4 000 000, else an error | `MaxXMLElements` |
| Input records | 200 000, then `Stats.Truncated` | `MaxRecords` |
| Emitted records | 200 000, then `Stats.Truncated` | `MaxOutputs` |
| Issues kept | 200 | `MaxIssues` |
| JSON nesting | 64 (a deeper line is skipped; a deeper `json` document is an error) | — |
| String members | 4 KiB; free-text members (`evidence`, `description`, `message`, `snippet`, `context_snippet`, `banner`, `impact`, `recommendation`) 64 KiB | — |
| Mapping file | 256 KiB, 200 rules, 100 targets per rule, nesting 32 | — |

- Control characters are removed from every string. Free-text members keep tab, newline and carriage return; other members turn them into spaces.
- Invalid UTF-8 is replaced.
- Issue messages are one line of at most 300 bytes.
- The language has no loops, expressions, code, file or network access, so its cost is linear in the input.

## 5. Examples

`importer/mapping/testdata/` holds six samples, each with its input and the expected report (`expect.ctis.json`, validated against the CTIS schema in CI):

- `naabu-jsonl`: one `open_port` asset per JSON line.
- `json-each`: a document with a list of TLS results. Each result gives a certificate asset and, for a weak grade, a misconfiguration finding.
- `findings-jsonl`: template-scanner matches to vulnerability findings, with CVE, CWE, evidence, tags and network location.
- `generic-csv`: one finding per row from `title`, `severity`, `asset`, `asset_type`, `cve` and `description` columns. The input has a byte order mark, CRLF line ends, quoted cells with commas, quotes and line breaks, and a formula cell kept as text.
- `generic-json`: a document with a `findings` list.
- `junit-xml`: JUnit-style results. A failed test case is a misconfiguration finding and an errored one a low finding; passed and skipped cases give nothing.

The last three are the starter mappings a receiver can offer.
