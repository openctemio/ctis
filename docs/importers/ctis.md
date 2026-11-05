# CTIS report mapping

Generated from `importer/spec_ctis.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `ctis`
- Source versions: CTIS 2.0 and newer 2.x minors (members of a newer minor are dropped with an issue)
- Fields: 21 mapped, 15 ignored on purpose (58% mapped)

## Rules

- Decoded strictly with ctis.Decode and validated record by record: an invalid asset, finding, dependency, relationship or endpoint is left out with the reason.
- Kept as written: assets, rules, findings, dependencies, relationships and endpoints. The tool's name, version, vendor, info URL and techniques are kept unless Options.ToolName is set.
- Not kept: the report's id, time and channel (the importer sets them), metadata, properties and report-level extensions.
- Removed everywhere: the io.openctem extensions (the receiver profile: scope verdicts, candidate exposures, web content). A document cannot say that a host is in scope or that an exposure was verified.
- Removed from every finding: validation. A claim that a finding was verified carries no weight in a file; verification is the receiver's own step.
- Every host-bearing asset then carries the importer's own extensions[io.openctem].import_scope relative to Options.ScopeDomains; the receiver judges scope.
- Secret findings are masked as for every format (ctis.RedactSecretFinding).

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/version` | `checked by ctis.Decode (major 2)` |  |
| `/$schema` |  | an identifier; never fetched |
| `/metadata` |  | the importer sets the report's id, time and channel |
| `/metadata/**` |  | the importer sets the report's id, time and channel |
| `/tool` | `tool` |  |
| `/tool/**` | `tool (name, version, vendor, info_url, techniques)` |  |
| `/properties` |  | an opaque bag of the producer |
| `/properties/**` |  | an opaque bag of the producer |
| `/extensions` |  | report-level producer data |
| `/extensions/**` |  | report-level producer data |
| `/assets` | `assets[]` |  |
| `/assets[]/extensions/io.openctem` |  | the receiver profile: set by the importer and the receiver, never by a document |
| `/assets[]/extensions/io.openctem/**` |  | the receiver profile: set by the importer and the receiver, never by a document |
| `/assets[]/**` | `assets[] (the same member)` |  |
| `/assets[]` | `assets[]` |  |
| `/rules` | `rules[]` |  |
| `/rules[]` | `rules[]` |  |
| `/rules[]/**` | `rules[] (the same member)` |  |
| `/findings` | `findings[]` |  |
| `/findings[]` | `findings[]` |  |
| `/findings[]/validation` |  | verification is the receiver's own step |
| `/findings[]/validation/**` |  | verification is the receiver's own step |
| `/findings[]/extensions/io.openctem` |  | the receiver profile |
| `/findings[]/extensions/io.openctem/**` |  | the receiver profile |
| `/findings[]/**` | `findings[] (the same member)` |  |
| `/dependencies` | `dependencies[]` |  |
| `/dependencies[]` | `dependencies[]` |  |
| `/dependencies[]/**` | `dependencies[] (the same member)` |  |
| `/relationships` | `relationships[]` |  |
| `/relationships[]` | `relationships[]` |  |
| `/relationships[]/**` | `relationships[] (the same member)` |  |
| `/endpoints` | `endpoints[]` |  |
| `/endpoints[]` | `endpoints[]` |  |
| `/endpoints[]/extensions/io.openctem` |  | the receiver profile |
| `/endpoints[]/extensions/io.openctem/**` |  | the receiver profile |
| `/endpoints[]/**` | `endpoints[] (the same member)` |  |
