# CTIS: CTEM Ingest Schema

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/openctemio/ctis/actions/workflows/ci.yml/badge.svg)](https://github.com/openctemio/ctis/actions/workflows/ci.yml)

CTIS is the JSON format security tools use to send assets, findings and dependencies (SBOM) to a CTEM platform such as [OpenCTEM](https://github.com/openctemio). This repository is the single source of truth for:

- **The specification**: [`docs/spec.md`](docs/spec.md), normative, with a field reference generated from the schema.
- **JSON Schemas** (`schemas/v1/`): draft-07, language-agnostic.
- **Go types** (root package): what OpenCTEM decodes reports into.
- **Severity** (`severity/`) and **fingerprint** (`fingerprint/`) helpers.
- **Converters**: SARIF and recon (subfinder, dnsx, naabu, httpx, katana) output to CTIS.
- **Examples** (`examples/`): one report per finding type, validated in CI.
- **Web URLs** (`weburl/`): parse, normalise, template and redact web URLs.
- **Capability taxonomy** (`capability/`): the closed list of acts a scan tool performs and the contract of each ([docs/capabilities.md](docs/capabilities.md)).

The current specification version is **1.5**. See [CHANGELOG.md](CHANGELOG.md).

## Installation (Go)

```bash
go get github.com/openctemio/ctis
```

The module has no dependencies outside the Go standard library.

```go
import (
    "github.com/openctemio/ctis"
    "github.com/openctemio/ctis/fingerprint"
    "github.com/openctemio/ctis/severity"
)

// Produce
report := ctis.NewReport() // version 1.5, $schema set, timestamp now
report.Tool = &ctis.Tool{Name: "my-scanner", Version: "1.0.0", Capabilities: []string{"sast"}}
report.Assets = append(report.Assets, ctis.Asset{ID: "repo", Type: ctis.AssetTypeRepository, Value: "github.com/org/repo"})
report.Findings = append(report.Findings, ctis.Finding{
    Type:        ctis.FindingTypeVulnerability,
    Title:       "SQL injection",
    Severity:    ctis.Severity(severity.FromCVSS(8.8)),
    AssetRef:    "repo",
    RuleID:      "sqli",
    Location:    &ctis.FindingLocation{Path: "app/db.go", StartLine: 42, Snippet: snippet},
    Fingerprint: fingerprint.GenerateSASTStable("app/db.go", "sqli", "db.Find", snippet),
})
if err := report.Validate(); err != nil {
    log.Fatal(err)
}

// Consume: decode strictly, as OpenCTEM does, then validate.
dec := json.NewDecoder(r)
dec.DisallowUnknownFields()
var in ctis.Report
if err := dec.Decode(&in); err != nil { /* reject */ }
if err := in.Validate(); err != nil { /* reject */ }

// Convert SARIF (Semgrep, CodeQL, Trivy, ...)
report, err := ctis.FromSARIF(sarifBytes, nil)
```

## Schemas

| Schema | Description |
|---|---|
| `report.json` | Report envelope: version, metadata, tool, assets, findings, dependencies |
| `asset.json` | Assets (domains, IPs, hosts, repositories, cloud, Web3, ...) |
| `finding.json` | Security findings |
| `dependency.json` | SBOM dependencies |
| `web3-asset.json` | Web3 asset details |
| `web3-finding.json` | Web3 vulnerability details |

Each schema's `$id` resolves:

```
https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/report.json
https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/asset.json
https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/finding.json
https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/dependency.json
https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/web3-asset.json
https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/web3-finding.json
```

Replace `main` with a release tag (`v1.3.0`) for an immutable copy. Every object sets `additionalProperties: false` except the `properties` bags: put producer-specific data in `properties`.

## Validating CTIS reports

`report.json` references the other schemas, so load all six.

### Python

```bash
pip install "jsonschema[format-nongpl]"
```

```python
import glob, json
from jsonschema import Draft7Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

schemas = [json.load(open(p)) for p in glob.glob("schemas/v1/*.json")]
registry = Registry().with_resources(
    (s["$id"], Resource.from_contents(s, default_specification=DRAFT7)) for s in schemas
)
report_schema = next(s for s in schemas if s["$id"].endswith("/report.json"))
validator = Draft7Validator(report_schema, registry=registry, format_checker=FormatChecker())

errors = list(validator.iter_errors(json.load(open("my-report.json"))))
for e in errors:
    print("/".join(map(str, e.path)), e.message)
```

`scripts/validate_schemas.py` does this for the examples in CI.

### Node.js

```bash
npm install ajv ajv-formats
```

```javascript
const Ajv = require('ajv');
const addFormats = require('ajv-formats');
const fs = require('fs');

const ajv = new Ajv({ allErrors: true });
addFormats(ajv);
for (const f of fs.readdirSync('schemas/v1')) {
  ajv.addSchema(JSON.parse(fs.readFileSync(`schemas/v1/${f}`, 'utf8')));
}
const validate = ajv.getSchema('https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/report.json');
if (!validate(myReport)) console.log(validate.errors);
```

Schema validation checks shape. `Report.Validate()` in Go also checks what a schema cannot: unique IDs, `asset_ref` resolution, the spec version and score ranges ([spec section 3.3](docs/spec.md#33-reportvalidate)).

## Importing other tools' exports

The `importer` package converts exported files to CTIS 1.5: Nessus, Qualys (with the KnowledgeBase), DefectDojo Generic JSON, CycloneDX, SPDX, osv-scanner, CSAF, OpenVEX, SARIF 2.1.0, and the native JSON of trivy, nuclei, semgrep, betterleaks and vuls. `Detect` names the format from the first bytes; `Parse` converts the file:

```go
res, err := importer.Parse(ctx, file, importer.Options{})
// res.Report: the CTIS report; res.VEX: statements of a VEX document;
// res.Stats, res.Issues (with line numbers), res.Unmapped.
```

Each format has a mapping spec: every source field, the CTIS member that keeps it or why it is ignored on purpose ([docs/importers](docs/importers/README.md), generated from the code). The tests fail when a fixture holds a field its spec does not list, or a spec maps a field no fixture holds. Inputs are treated as hostile: size, depth, element, text and record limits; no XML internal subsets, entities or external resources; UTF-8, US-ASCII or ISO-8859-1 only; `OpenZip` refuses traversal, links, nested archives and decompression bombs. Scan credentials and account names are never copied into a report.

## Web URLs

The `weburl` package parses, normalises and templates web URLs, so a crawler, a scanner and the platform give one endpoint the same identity:

```go
u, err := weburl.Parse("HTTPS://Shop.Example.COM:443/api/v1/orders/42/?token=x")
u.Origin()   // "https://shop.example.com"
u.Template() // "/api/v1/orders/{int}"
u.Params     // ["token"]: names only, never values
weburl.RedactURL("https://u:p@a.example/x?api_key=k#t") // "https://a.example/x?api_key="
weburl.PathHash("GET", u.Template())                      // the endpoint's dedup key
```

`Parse` refuses anything that is not a plain absolute http(s) URL: user info, control and bidi characters, malformed escapes, invalid ports, ambiguous numeric hosts and URLs over 2,048 bytes. A query value is never kept.

## Capability taxonomy

The `capability` package is the closed, versioned list of acts a scan tool can perform (`discover.subdomains@1`, `scan.ports@1`, `sast.code@1`, ...). The capability, not the tool, carries the facts about the act: its phase and CTEM stage, its tier floor (how intrusive it is at minimum), its typed input and output ports with the CTIS asset types they carry, its standard params, the CTIS paths every report of it must carry, and its MITRE ATT&CK, D3FEND and CAPEC references. A tool only declares which capabilities it implements.

```go
c, ok := capability.Lookup("scan.ports@1")
c.Accepts("ip_address")          // true: an input port carries it
c.MayEmit("asset:repository")    // false: no port carries it
violations, err := c.Check(report, capability.CheckOptions{})
```

`Check` reports outputs the capability may not emit and records that miss a required path; producers run it before upload and receivers again at ingest. The reference page [docs/capabilities.md](docs/capabilities.md) is generated from the data.

## Mapping any JSON tool output

The `importer/mapping` package turns the JSON or JSON Lines output of any command-line tool into CTIS through a declarative mapping file (`openctem.io/mapping/v1`), so wrapping a tool needs no parser code:

```go
m, err := mapping.Load(mappingJSON)
report, stats, err := m.Apply(ctx, stdout, mapping.Options{Tool: &ctis.Tool{Name: "acme-portscan"}})
```

The language is closed: predicates (`exists`, `equals`, `in`, RE2 `matches`), source paths, constants, named templates and a fixed list of transforms. It has no expressions, code, file or network access. Targets are checked against the CTIS types. Ids, links between records and the report's `tool` cannot be set. Input is bounded in size, depth, line length and record count. See [docs/mapping.md](docs/mapping.md).

## Asset types

| Group | Types |
|---|---|
| External attack surface | `domain`, `subdomain`, `ip_address`, `certificate` |
| Applications | `website`, `web_application`, `api`, `mobile_app`, `service` |
| Code | `repository` |
| Cloud | `cloud_account`, `compute`, `storage`, `database`, `serverless`, `container_registry` |
| Infrastructure | `host`, `server`, `container`, `kubernetes`, `kubernetes_cluster`, `kubernetes_namespace` |
| Network | `network`, `vpc`, `subnet`, `load_balancer`, `firewall` |
| Identity / IAM | `iam_user`, `iam_role`, `service_account` |
| Recon results | `http_service`, `open_port`, `discovered_url` |
| Web3 | `smart_contract`, `wallet`, `token`, `nft_collection`, `defi_protocol`, `blockchain` |
| Other | `unclassified` |

## Finding types

| Type | Description |
|---|---|
| `vulnerability` | Code, dependency, host or web vulnerabilities |
| `secret` | Exposed secrets and credentials |
| `misconfiguration` | IaC, cloud and configuration issues |
| `compliance` | Compliance control failures |
| `web3` | Smart contract vulnerabilities |

## Versioning

- `version` in a report is the spec version, `MAJOR.MINOR`. Receivers accept any minor of their major.
- Minor versions only add optional members or values. Receivers decode strictly, so a producer must not send members newer than the receiver's minor: **upgrade receivers first, then producers.**
- Module `v1.MINOR.x` implements spec `1.MINOR`.

Details: [docs/spec.md, section 2](docs/spec.md#2-versioning-and-compatibility).

## Contributing

Every change to the format updates the schema, the Go types, the examples and the CHANGELOG together. `go test ./...` fails when the schema and the Go types disagree, when an example does not validate, or when the generated field reference in `docs/spec.md` is stale (refresh it with `go test -run TestSpecFieldReference -update`). Proposed additions are collected in [docs/proposals-1.4.md](docs/proposals-1.4.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
