# CTIS: CTEM Interchange Schema

[![Code: Apache-2.0](https://img.shields.io/badge/code-Apache_2.0-blue.svg)](LICENSE) [![Spec: CC BY 4.0](https://img.shields.io/badge/spec-CC_BY_4.0-lightgrey.svg)](LICENSE-docs)
[![CI](https://github.com/openctemio/ctis/actions/workflows/ci.yml/badge.svg)](https://github.com/openctemio/ctis/actions/workflows/ci.yml)

CTIS is an open JSON document format for continuous threat exposure management: security tools and platforms use it to exchange the assets they observe, the findings on them, software components, the relationships between assets and the web endpoints an origin serves. A document carries natural keys (canonical forms) and the producer's own references, never a receiver's database keys, so any producer can talk to any receiver.

This repository holds the standard and its reference implementation:

- **Specification**: [`docs/spec.md`](docs/spec.md), normative and receiver-neutral, with a field reference generated from the schema.
- **JSON Schemas**: [`schemas/v2/`](schemas/v2), JSON Schema 2020-12, with immutable versioned `$id`s (`https://schemas.openctem.io/ctis/2.0/report.json`; identifiers, never fetched).
- **Conformance vectors**: [`conformance/v2/`](conformance/README.md), plain JSON every implementation runs: canonical forms, asset keys, location keys, preferred ids, fingerprints, correlation keys, valid and invalid documents.
- **Validator CLI**: `ctis`, a single static binary.
- **Go reference implementation** (root package `github.com/openctemio/ctis/v2`): types, `Decode`, `Validate`, canonical forms, fingerprints (`fingerprint/`), severity mapping (`severity/`), web URLs (`weburl/`), importers (`importer/`), exporters and converters.
- **Examples**: [`examples/`](examples), validated in CI.

The current specification version is **2.0**. Upgrading from 1.x: [docs/migration-2.0.md](docs/migration-2.0.md). History: [CHANGELOG.md](CHANGELOG.md).

## Media type and files

`application/vnd.ctis+json; version=2.0`, file suffix `.ctis.json`.

## Installation (Go)

```bash
go get github.com/openctemio/ctis/v2
```

The module has no dependencies outside the Go standard library.

```go
import (
    "github.com/openctemio/ctis/v2"
    "github.com/openctemio/ctis/v2/fingerprint"
    "github.com/openctemio/ctis/v2/severity"
)

// Produce. NewReport stamps version 2.0, the schema id, a fresh UUIDv7
// metadata.id (the idempotency key: re-send it on retry) and generated_at.
report := ctis.NewReport()
report.Tool = &ctis.Tool{Name: "my-scanner", Version: "1.0.0", Techniques: []ctis.Technique{ctis.TechniqueSAST}}
report.Assets = append(report.Assets, ctis.Asset{ID: "repo", Type: ctis.AssetTypeRepository, Value: "github.com/org/repo"})
report.Findings = append(report.Findings, ctis.Finding{
    Type:        ctis.FindingTypeWeakness,
    Title:       "SQL injection",
    Severity:    ctis.Severity(severity.FromCVSS(8.8)),
    AssetRef:    "repo",
    RuleID:      "sqli",
    Location:    &ctis.FindingLocation{Path: "app/db.go", StartLine: 42, Snippet: snippet},
    Fingerprint: fingerprint.V2SASTContent("app/db.go", "sqli", "db.Find", snippet),
})
if err := report.Validate(); err != nil {
    log.Fatal(err)
}

// Consume: decode under the compatibility rule, then validate. A document
// of this module's minor or an older one decodes strictly (a typo is an
// error); a newer minor has unknown members ignored and unknown enum values
// mapped to their fallback; another major (any 1.x document) is refused.
in, unknown, err := ctis.Decode(io.LimitReader(r, 64<<20))
if err != nil { /* reject */ }
if err := in.Validate(); err != nil { /* reject */ }
_ = unknown.Entries // log what was ignored

// Key assets on their canonical value; never trust a producer's key.
v, _ := ctis.CanonicalAssetValue(ctis.AssetTypeDomainName, "Bücher.Example.") // "xn--bcher-kva.example"
key := ctis.AssetKey(ctis.AssetTypeDomainName, v)
```

## Schemas

| Schema | Description |
|---|---|
| `report.json` | Report: version, metadata, tool, assets, findings, dependencies, relationships, endpoints, extensions |
| `asset.json` | Assets and their technical details |
| `finding.json` | Findings: location, network and web location, vulnerability, scores, threat signals, remediation, validation |
| `dependency.json` | Software components (SBOM) |
| `endpoint.json` | Web endpoints: a method and a path on an origin, parameters by name only |
| `evidence-item.json` | Typed evidence: HTTP exchanges, text, command output, file excerpts, screenshots, with marked sensitive spans |
| `web3-asset.json`, `web3-finding.json` | The optional web3 profile |

Every object sets `additionalProperties: false` except the `properties` bags (opaque: receivers give them no meaning) and `extensions` (namespaced data, keyed by reverse-DNS namespace). Every member carries a bound; URL members admit only http and https.

## Validate a document

`ctis` checks a document the way a strict receiver does: the version must be one this release implements, unknown members are refused, and `Report.Validate` must pass. It reads only the files you name (or `-` for standard input) and never fetches a URL.

```bash
go install github.com/openctemio/ctis/v2/cmd/ctis@latest   # or download a release binary
ctis validate report.ctis.json             # exit 0 valid, 1 invalid, 2 usage or I/O error
ctis validate --json a.json b.json         # one JSON object per file
ctis validate --max-size 1048576 -         # standard input, at most 1 MiB (default 64 MiB)
ctis canon domain_name WWW.Example.COM.    # canonical value and asset key
ctis conformance conformance/v2            # run the conformance vectors
```

With another validator, load all eight schemas (`report.json` references the others by relative `$ref`) into a JSON Schema 2020-12 validator; [`scripts/validate_schemas.py`](scripts/validate_schemas.py) shows how with python-jsonschema. Schema validation checks shape; `Report.Validate()` also checks what a schema cannot (unique ids, references that resolve, canonical asset values, score ranges per system).

## Asset types

| Group | Types |
|---|---|
| External surface | `domain_name`, `ip_address`, `ip_range`, `certificate`, `autonomous_system` |
| Applications and services | `web_origin`, `web_application`, `api`, `mobile_app`, `saas_application`, `service` |
| Code and artifacts | `repository`, `package`, `container_image`, `ai_model` |
| Cloud | `cloud_account`, `cloud_resource`, `storage`, `database`, `serverless`, `container_registry` |
| Infrastructure and devices | `host`, `container`, `kubernetes_cluster`, `kubernetes_namespace`, `kubernetes_workload`, `endpoint_device`, `iot_device`, `ot_device`, `network_device` |
| Network | `vpc`, `subnet`, `load_balancer`, `firewall` |
| Identity | `identity` (`technical.identity.kind`) |
| Web3 profile | `smart_contract`, `wallet`, `nft_collection`, `defi_protocol`, `token`, `blockchain` |
| Fallback | `unclassified` |

A port is a `service` asset (`host:port/transport`) linked from its host by an `exposes` relationship; a web origin's paths are `endpoints`, not assets.

## Finding types

`vulnerability` (an advisory id), `weakness` (no advisory id: most SAST results), `secret`, `misconfiguration`, `compliance` (the result is `kind`), `exposure`, `malware`, `license`. Web3 is a profile: a `web3` block on a vulnerability or weakness.

## Importing other tools' exports

The `importer` package converts exported files to CTIS 2.0: Nessus, Qualys (with the KnowledgeBase), DefectDojo Generic JSON, CycloneDX, SPDX, osv-scanner, CSAF, OpenVEX, SARIF 2.1.0, the ZAP report, generic bug-bounty reports, and the native JSON of trivy, grype, nuclei, semgrep, opengrep, betterleaks, gitleaks and vuls. `Detect` names the format from the first bytes; `Parse` converts the file:

```go
res, err := importer.Parse(ctx, file, importer.Options{})
// res.Report: the CTIS document; res.VEX: statements of a VEX document;
// res.Stats, res.Issues (with line numbers), res.Unmapped.
```

Each format has a mapping spec: every source field, the CTIS member that keeps it or why it is ignored on purpose ([docs/importers](docs/importers/README.md)). Inputs are treated as hostile: size, depth, element, text and record limits; no XML entities or external resources; `OpenZip` refuses traversal, links, nested archives and decompression bombs. Scan credentials and account names are never copied.

The `importer/mapping` package turns the JSON, JSON Lines, CSV or XML output of any tool into CTIS through a declarative, closed mapping language ([docs/mapping.md](docs/mapping.md)).

## Exporters

`ToSARIF`, `ToCycloneDX` and `ToOCSF` write a document as SARIF 2.1.0, a CycloneDX 1.6 BOM with its vulnerabilities (VDR/VEX), and OCSF 1.3.0 Vulnerability and Compliance Finding events. Output is deterministic, needs no network and never carries a raw secret. Round trips against the importers are tested; the mapping and the accepted losses per format are in [docs/exporters.md](docs/exporters.md).

## Converters

`ctis.FromSARIF` converts a SARIF log; `ctis.ConvertReconToCTIS` and `ctis.MergeReconReports` convert subdomain, DNS, port, HTTP probe and crawl results into the 2.0 asset graph (domain names, addresses, services with `exposes`, web origins with their certificate, endpoints).

## Web URLs

The `weburl` package parses, normalises, templates and redacts web URLs, so a crawler, a scanner and a receiver give one endpoint the same identity:

```go
u, err := weburl.Parse("HTTPS://Shop.Example.COM:443/api/v1/orders/42/?token=x")
u.Origin()   // "https://shop.example.com"
u.Template() // "/api/v1/orders/{int}"
u.Params     // ["token"]: names only, never values
weburl.RedactURL("https://u:p@a.example/x?api_key=k#t") // "https://a.example/x?api_key="
```

## Fingerprints

Recipe `ctis-fp/2` and the cross-tool correlation key `ctis-ck/1` are specified in [docs/fingerprints.md](docs/fingerprints.md) and implemented in the `fingerprint` package (`V2Auto`, `V2SAST`, `V2SCA`, `V2Secret` with an HMAC digest, `V2VA`, ...) and `ctis.CorrelationKey`. Recipe v1 stays in the package, deprecated, for receivers migrating stored data.

## Versioning

- `version` is the specification version, `MAJOR.MINOR`. A minor only adds optional members or values; receivers decode their own or older minors strictly and ignore what they do not know in a newer minor; another major is refused.
- Module `v2.MINOR.x` implements CTIS `2.MINOR`.

Details: [docs/spec.md, section 2](docs/spec.md#2-versioning-and-compatibility).

## Contributing

Contributions are made under the Developer Certificate of Origin (`git commit -s`); format changes go through a [proposal](proposals/README.md). See [CONTRIBUTING.md](CONTRIBUTING.md).

Every change to the format updates the schema, the Go types, the examples, the conformance vectors and the CHANGELOG together. `go test ./...` fails when the schema and the Go types disagree, when an example does not validate, or when the generated field reference in `docs/spec.md` is stale (`go test -run TestSpecFieldReference -update`).

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

- Specification text and other prose (`docs/`, `proposals/`): [Creative Commons Attribution 4.0 International](LICENSE-docs).
- Schemas, examples, conformance vectors and code: [Apache License 2.0](LICENSE). See also [NOTICE](NOTICE).
- Patent commitment for implementers: [PATENTS.md](PATENTS.md).

Governance and the proposal process: [GOVERNANCE.md](GOVERNANCE.md), [proposals/README.md](proposals/README.md).
