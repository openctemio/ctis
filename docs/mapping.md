# Declarative mappings (`openctem.io/mapping/v1`)

A mapping turns the JSON or JSON Lines output of a command-line tool into a CTIS report without parser code. The package is `github.com/openctemio/ctis/importer/mapping`:

```go
m, err := mapping.Load(mappingJSON)          // strict; refuses anything outside the language
report, stats, err := m.Apply(ctx, toolStdout, mapping.Options{
    Now:  clock,                              // injected for reproducible output
    Tool: &ctis.Tool{Name: "acme-portscan", Version: "1.2.0"},
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
| `source` | `jsonl`: one JSON value per line. `json`: one document. |
| `each` | `json` only: the path of the list of records. Absent: a top-level list is the records; any other value is one record. |
| `records` | The rules, 1 to 200. **Every** rule whose `when` holds emits one CTIS record for the input record, in rule order. |
| `notes` | Free text, ignored. |

Unknown members are errors everywhere.

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

## 4. Limits (hostile input)

| Limit | Default | Option |
|---|---|---|
| Input | 64 MiB, else `ErrInputTooLarge` | `MaxInputBytes` |
| One JSON Lines line | 1 MiB, longer lines are skipped | `MaxRecordBytes` |
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

`importer/mapping/testdata/` holds three samples, each with its input and the expected report (`expect.ctis.json`, validated against the CTIS schema in CI):

- `naabu-jsonl`: one `open_port` asset per JSON line.
- `json-each`: a document with a list of TLS results. Each result gives a certificate asset and, for a weak grade, a misconfiguration finding.
- `findings-jsonl`: template-scanner matches to vulnerability findings, with CVE, CWE, evidence, tags and network location.
