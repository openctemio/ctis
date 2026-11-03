# Interoperability layer

CTIS converts to and from the formats tools already speak without letting their shapes into the core (spec section 9). The core module models CTEM concepts only. Each standard format is an **adapter**: its own Go module, with declarative mapping files per upstream version, lossless passthrough, vendored upstream schemas and conformance vectors.

| Format | Module | Upstream versions | Directions | Namespace of the passthrough |
|---|---|---|---|---|
| SARIF | `github.com/openctemio/ctis/v2/interop/sarif` | 2.1.0 | import, export | `org.ctis.interop.sarif` |
| CycloneDX | `github.com/openctemio/ctis/v2/interop/cyclonedx` | 1.5 (and 1.2-1.4), 1.6 (and later 1.x) | import, export (1.6) | `org.ctis.interop.cyclonedx` |
| SPDX | `github.com/openctemio/ctis/v2/interop/spdx` | 2.3 (and earlier 2.x) | import | `org.ctis.interop.spdx` |
| CSAF | `github.com/openctemio/ctis/v2/interop/csaf` | 2.0 | import | `org.ctis.interop.csaf` |
| OpenVEX | `github.com/openctemio/ctis/v2/interop/openvex` | 0.2.0 (and 0.0.1) | import | `org.ctis.interop.openvex` |
| OCSF | `github.com/openctemio/ctis/v2/interop/ocsf` | 1.3.0 | export | none (no importer) |

Tool-specific importers (scanner and product exports: Nessus, Qualys, trivy, semgrep, gitleaks, OSV, ...) stay in the core package `importer`, and the generic declarative mappings of tool output stay in `importer/mapping` ([mapping.md](mapping.md)).

## Using an adapter

```go
import (
    "github.com/openctemio/ctis/v2/importer"
    "github.com/openctemio/ctis/v2/interop/sarif"
    _ "github.com/openctemio/ctis/v2/interop/cyclonedx" // registers cyclonedx with importer
)

report, err := sarif.Import(logBytes, nil)            // SARIF -> CTIS report
out, err := sarif.Export(report, nil)                 // CTIS -> SARIF 2.1.0
res, err := importer.Parse(ctx, r, importer.Options{}) // detects the format; cyclonedx works because it is imported
```

- `sarif.Import(data, *sarif.Options) (*ctis.Report, error)` and `sarif.Export(*ctis.Report, *sarif.ExportOptions) ([]byte, error)`.
- `cyclonedx`, `spdx`, `csaf`, `openvex`: `Import(data, *importer.Options) (*importer.Result, error)`. A standard-format import also gives VEX statements, counts and issues, so these return the whole `importer.Result`. `cyclonedx.Export(*ctis.Report, *cyclonedx.ExportOptions) ([]byte, error)` writes CycloneDX 1.6.
- `ocsf.Events(*ctis.Report, *ocsf.Options) ([]ocsf.Event, error)` and `ocsf.Export` (the events as one JSON array).
- Every adapter registers its formats with `importer.Register` from its `init` function. `importer.Parse` with format detection then reads them in any program that imports the adapter. Without the adapter, Parse detects the format and fails with `ErrUnknownFormat`, naming the module to import (`importer.AdapterModule`). The core never imports an adapter.
- Each adapter has `Versions()`, which lists the upstream versions it reads, and `Namespace`.
- The command `ctis` (module `github.com/openctemio/ctis/v2/cmd/ctis`) links every adapter: `ctis import [--format F] file` and `ctis export --format sarif|cyclonedx|ocsf file`.

Every adapter depends on the Go standard library and the core module only.

## Mapping files

```
v2/interop/<format>/<upstream-version>/import.json
v2/interop/<format>/<upstream-version>/export.json
```

A mapping file describes one direction of one upstream version. `apiVersion` is `openctem.io/interop/v1`. The engine is specified normatively in [mapping-engine.md](mapping-engine.md), with vectors in `conformance/v2/interop-engine`; this section summarises it. The package `interop/engine` loads it strictly: unknown members are errors, and so are hooks the adapter does not register and tables the adapter looks up that are missing. The adapter embeds its mapping directories and loads every version side by side (`engine.LoadFS`).

| Member | Meaning |
|---|---|
| `apiVersion`, `format`, `version`, `direction` | Identity: `import` or `export` of one upstream version. The version equals the directory name. |
| `namespace` | The extensions namespace of the passthrough (reverse-DNS). |
| `title`, `source`, `notes` | For readers. The import spec of `docs/importers/<format>.md` is generated from them. |
| `detect` (import) | Predicates on members of the document (`pointer` plus one of `equals`, `in`, `prefix`, `matches`, `absent`; `or_absent`). The engine picks the mapping whose predicates all hold (`Set.Select`). Several versions load side by side. |
| `version_pointer` (import) | The member that declares the document's version. The passthrough records that version. |
| `fold` | Path prefixes read as another prefix, so a recursive structure is listed once (CycloneDX nested components). |
| `records` (import) | Source objects that become one CTIS record each (`name`, `path`, `kind`: finding, asset, dependency, vex). Passthrough below a record is kept on that record, and `set` rules apply to it. |
| `fields` | Every member of the format the adapter knows, in document order. A field has a `path` (pattern: `[]` arrays, `*` within a segment, `**` any depth) and either a target or `ignored` with the reason. The target is one of: `target` (what keeps the value; `(container)` for a member that only groups others), `hook` (the Go function of the adapter that maps it), or `set` (a rule the engine applies; see below). |
| `tables` | Value tables the conversion looks values up in (`map`, `default`, `match`: exact, fold or token). Examples: severity maps, the SARIF level table, VEX state and justification tables, CVSS method names, OCSF severity and status ids. |
| `hooks` | The adapter's Go functions this mapping relies on. Each must map at least one field. |
| `reemit_from` (export) | Other upstream versions whose passthrough this mapping writes back. |
| `passthrough` | Lower passthrough limits (see below). |

A **set rule** copies one scalar member of a record to a CTIS member of that record (`"set": "correlation_id"`, `"record": "result"`), through transforms from a fixed registry: `trim`, `lower`, `upper`, `token`, `line`, `table:<name>`, `max_bytes:<n>`, `http_url`. Load checks the target against the CTIS Go types: only text, integer, number and boolean members, and never `id`, `*_ref`, `fingerprint`, `properties` or `extensions`. A value that a transform rejects leaves the member unset. The SARIF `correlationGuid`, `baselineState` and `kind` are set rules.

The parts of a conversion that are not field to field are **hooks**: Go functions of the adapter that the mapping names. Examples: SARIF code flows, the rule catalog, secret masking, CycloneDX dependency graphs and VEX product resolution. The language has no expressions, loops, code, file or network access.

The tests of each adapter enforce the mapping discipline:
- Every source field of every fixture is listed (mapped or ignored).
- Every mapped field occurs in a fixture.
- An export mapping lists every member the exporter's output types can hold (`interoptest.ExportCoverage`).

## Passthrough

Members of a source document that its mapping does not list are kept, as data, under the extensions namespace of the format:

```json
"extensions": {"org.ctis.interop.sarif": {"version": "2.1.0", "unmapped": {"/runs/0/language": "en-US"}}}
```

- Members outside a record go on the report, with absolute JSON pointers. Members below a record go on that record (a finding), with pointers relative to the record object.
- A member below an `ignored` field is never kept. Ignored members are dropped on purpose (SARIF `invocations` hold command lines and environments).
- Bounds per object: 64 members and 16 KiB by default. A mapping can lower them; the hard maxima are 256 members and 32 KiB, well below the 64 KiB a CTIS object's extensions may hold. A kept value nests at most 12 deep (hard 16). At most 10,000 records keep members, and at most 8 MiB per document. A member over a limit is dropped and the object is marked `"truncated": true`.
- Scrubbing, at any depth:
  - A member whose name says it holds a credential is dropped: password, secret, token, api key, authorization, cookie, credential, private key, environment variables, command line.
  - A URL-like member (name ending in uri, url or href) whose value has a scheme other than http or https is dropped.
  - Every string goes through `ctis.RedactCodeSecrets`.
  - A secret finding's kept members are masked with the finding (`ctis.RedactSecretFinding` walks them).
- A kept value is never interpreted and never placed into a core member.
- The exporter writes kept members back (`Mapping.Reemit`) only where its output has no member yet and the export mapping does not own the place. It never overwrites a mapped member, never creates array elements, and checks the members again: a CTIS document may come from anyone.
  - SARIF writes back the members of each result, and the run members when the log has one run.
  - CycloneDX writes back only the document members whose pointer crosses no array index: it orders components and vulnerabilities its own way.
- `NoPassthrough` (in `importer.Options`, `sarif.Options` and the export options) turns the passthrough off.

A member that a later upstream version adds is kept this way until a mapping lists it. Example: a CycloneDX 1.7 document read with the 1.6 mapping keeps `citations` (vector `conformance/interop/cyclonedx/1.6/newer-minor`).

## Vectors

`conformance/interop/<format>/<version>/vectors.json` lists the vectors of one adapter version:

- Import vectors: an upstream sample document and its golden CTIS output (`*.expect.json`: the report and the VEX statements).
- `roundtrip`: import, export, import again. The reports must be equal except for the accepted `losses`, each with its reason.
- `kept` and `reemitted`: the passthrough must keep these members and write them back.
- `never`: strings that must not appear in the report or the export, such as raw secrets, command lines and script URLs.
- Export-only vectors (OCSF): a CTIS document and its golden output.

Each adapter's tests run the vectors of every version the adapter reads (`TestConformanceVectors`). CI runs them on every change. The sample documents validate against the vendored upstream schema (`scripts/check_interop_schemas.py --validate`, offline).

## Upstream watcher

`interop/upstreams.json` pins, per format:
- the official schema repository and the tag pattern of its releases;
- the schema files;
- the vendored versions, with the ref and the sha256 of each copy under `v2/interop/<format>/schemas/<version>/`.

CI checks the vendored files against the sha256 values.

`.github/workflows/interop-upstream.yml` runs weekly and on demand (`scripts/interop_watch.py`). For the newest new version of each format, and for a corrected schema of a vendored version, it:
1. vendors the schema files and records their sha256;
2. writes `schema-diff.md`;
3. copies the latest mapping directory to `v2/interop/<format>/<new-version>/` (a new version only);
4. runs the adapter's tests and vectors;
5. opens a pull request labelled `upstream-update`.

Security of the watcher:
- Network access goes only to `api.github.com` and `raw.githubusercontent.com`, over https; redirects elsewhere are refused.
- Upstream files are parsed as JSON and never executed.
- Go builds without a module proxy.
- The job holds `contents: write` and `pull-requests: write` only, and no secret beyond `GITHUB_TOKEN`.
- Actions are pinned by SHA.

## Adding an upstream version

1. Run the watcher (Actions, "Interop upstream watcher", or `python3 scripts/interop_watch.py apply <format> <version> <tag>`), or vendor the schema by hand and record its sha256 in `upstreams.json`.
2. In the copied mapping directory, adjust `detect`, so that each document selects exactly one version, and `version`.
3. List the members the schema diff adds. Until they are listed they are passthrough. Map them with `set` rules, a table entry, a hook, or `ignored` with a reason.
4. Add vectors under `conformance/interop/<format>/<version>/` and run `go test ./...` in the adapter (`-update` writes the golden files).
5. Add an entry to the adapter's `CHANGELOG.md` and release only that adapter: tag `v2/interop/<format>/vX.Y.Z`. The core version changes only when the CTEM model changes.

No Go code changes for a field-to-field addition. A new structure that needs a hook is Go code in the adapter.

## Modules, versions and releases

- The core module `github.com/openctemio/ctis/v2` is tagged `vX.Y.Z`. Each adapter `github.com/openctemio/ctis/v2/interop/<format>` is tagged `v2/interop/<format>/vX.Y.Z`, and the command `v2/cmd/ctis` is tagged `v2/cmd/ctis/vX.Y.Z`. `release.yml` validates an adapter tag: module path, changelog, zero external dependencies, build on every platform, tests.
- An adapter's `go.mod` requires the core `v2.0.0` and has a `replace` to `../..` so the repository builds before the core tag. A consumer's build ignores the replace. Once v2.0.0 and the adapter tags exist, the replace lines go (`v2/cmd/ctis` needs that for `go install ...@version`).
- The adapters share internal helpers of the core module: `internal/importkit` (text, package URL and reference helpers), `internal/exportkit` (the exporters' common rules) and `internal/interoptest` (test helpers). A Go `internal` package is importable by every module under the same path prefix. These helpers are not public API; an adapter release requires a core release whose internals it builds with.
