### Added: declarative mappings for any JSON tool output (`importer/mapping`)

- `mapping.Load` reads a mapping file (`openctem.io/mapping/v1`, JSON). `(*Mapping).Apply` turns the JSON or JSON Lines output of a command-line tool into a CTIS report, so wrapping a tool needs no parser code. `(*Mapping).Digest` is the SHA-256 of the canonical mapping, for tool descriptors to record.
- Rules:
  - closed predicates: `exists`, `equals`, `in`, and RE2 `matches` (at most 256 bytes);
  - kinds: `asset`, `finding`, `dependency`;
  - values: a source path, a constant or a named template;
  - transforms: `first`, `trim`, `lower`, `upper`, `split`, `map`, `join`, `as`, `max_bytes`, `default`.
- Every target is checked against the CTIS Go types when the mapping loads.
- Each emitted record is decoded strictly and validated. A record that fails is skipped and reported in `Stats.Issues` with its record number and rule.
- Three samples with golden reports (a port scanner's JSON Lines, a JSON document with a result list, template-scanner findings). The golden reports are validated against the CTIS schema in CI.
- Fuzz targets `FuzzApply` and `FuzzLoad` run in CI.
- Spec: `docs/mapping.md`.

### Security

- The language has no loops, expressions, code, file or network access, so its cost is linear in the input.
- A mapping cannot set:
  - report-level members (`metadata`, `tool`, `$schema`);
  - record ids;
  - links between records (`asset_ref`, `related_assets`, `depends_on`, ...).
  
  Tool output therefore cannot forge references, and the report's tool comes only from the caller.
- Input limits:
  - 64 MiB per input;
  - 1 MiB per JSON Lines line;
  - 200 000 input and output records;
  - JSON nesting 64;
  - 4 KiB per string (64 KiB for free-text members).
- Strings lose control characters and invalid UTF-8.
- Issue messages that quote input are one bounded, clean line.
- Mapping-file limits: 256 KiB, 200 rules, 100 targets per rule, 256 `map` and `in` entries.
- Secret findings are masked with `ctis.RedactSecretFinding`.
- `RedactSecretFinding` no longer sizes an allocation from the number of masking candidates, which come from hostile text.
