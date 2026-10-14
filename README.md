# CTIS: CTEM Ingest Schema

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/openctemio/ctis/actions/workflows/ci.yml/badge.svg)](https://github.com/openctemio/ctis/actions/workflows/ci.yml)

CTIS is the JSON format security tools use to send assets, findings and dependencies (SBOM) to a CTEM platform such as [OpenCTEM](https://openctem.io). Product documentation: <https://docs.openctem.io>. This repository is the single source of truth for:

- **The specification**: [`docs/spec.md`](docs/spec.md), normative, with a field reference generated from the schema.
- **JSON Schemas** (`schemas/v1/`): draft-07, language-agnostic.
- **Go types** (root package): what OpenCTEM decodes reports into.
- **Severity** (`severity/`) and **fingerprint** (`fingerprint/`) helpers.
- **Converters**: SARIF and recon (subfinder, dnsx, naabu, httpx, katana) output to CTIS.
- **Examples** (`examples/`): one report per finding type, validated in CI.
- **Web URLs** (`weburl/`): parse, normalise, template and redact web URLs.
- **Politeness keys** (`politeness/`): which hosts a scan job touches and when two jobs touch the same host.
- **Capability taxonomy** (`capability/`): the closed list of acts a scan tool performs and the contract of each ([docs/capabilities.md](docs/capabilities.md)).
- **Tool settings** (`settings/`): the closed JSON Schema subset a tool manifest declares its configuration in, the validator, and layered resolution of the values a scan runs with.
- **Tool options** (`tooloption/`): the common execution options of scan tools (timeout, rate, concurrency, retries), their bounds and how layers may narrow them.

The current specification version is **1.6**. See [CHANGELOG.md](CHANGELOG.md).

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
report := ctis.NewReport() // version 1.6, $schema set, timestamp now
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
| `report.json` | Report envelope: version, metadata, tool, assets, findings, dependencies, endpoints |
| `asset.json` | Assets (domains, IPs, hosts, repositories, cloud, Web3, ...) |
| `finding.json` | Security findings, with their web location (`web`) and typed evidence (`evidence_items`) |
| `dependency.json` | SBOM dependencies |
| `endpoint.json` | Web endpoints: a method and a path on an origin, parameters by name only (1.6) |
| `evidence-item.json` | Typed evidence of a finding: HTTP exchanges, text, command output, file excerpts, screenshots, with marked sensitive spans (1.6) |
| `web3-asset.json` | Web3 asset details |
| `web3-finding.json` | Web3 vulnerability details |

Each schema's `$id` resolves:

```
https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/report.json
https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/asset.json
https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/finding.json
https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/dependency.json
https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/endpoint.json
https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/evidence-item.json
https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/web3-asset.json
https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/web3-finding.json
```

Replace `main` with a release tag (`vX.Y.Z`) for an immutable copy. Every object sets `additionalProperties: false` except the `properties` bags: put producer-specific data in `properties`.

## Validating CTIS reports

`report.json` references the other schemas, so load all eight.

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

The `importer` package converts exported files to CTIS 1.6: Nessus, Qualys (with the KnowledgeBase), DefectDojo Generic JSON, CycloneDX, SPDX, osv-scanner, CSAF, OpenVEX, SARIF 2.1.0, the ZAP traditional report (JSON and XML), and the native JSON of trivy, grype, nuclei, semgrep, betterleaks, gitleaks and vuls. `Detect` names the format from the first bytes; `Parse` converts the file:

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

## Politeness keys

The `politeness` package is the one definition of the per-host politeness keys of scan work, shared by the platform (which holds the keys while a job runs and sends them with the job) and the sensor runtime (which admits the job under the same keys):

```go
keys := politeness.Keys([]string{"https://www.example.com/x", "10.0.0.5", "10.0.1.0/24"}, "")
// ["10.0.0.5" "in:10.0.0.0/24" "net:10.0.1.0/24" "www.example.com"]
politeness.Conflicts(keys) // the keys another job must not hold at the same time
```

A name, the host of a URL or a service, an address (with the marker of its /24 or /120 bucket) and a range (one key per bucket) each have a key. An address and a range scan of its bucket conflict, two addresses of one bucket do not. With a network id, the keys of private addresses and of names carry the network, so overlapping private ranges at two sites stay two sets of hosts; public addresses never do.

## Capability taxonomy

The `capability` package is the closed, versioned list of acts a scan tool can perform (`discover.subdomains@1`, `scan.ports@1`, `sast.code@1`, ...). The capability, not the tool, carries the facts about the act: its phase and CTEM stage, its tier floor (how intrusive it is at minimum), its typed input and output ports with the CTIS asset types they carry, its standard params, the CTIS paths every report of it must carry, and its MITRE ATT&CK, D3FEND and CAPEC references. A tool only declares which capabilities it implements.

```go
c, ok := capability.Lookup("scan.ports@1")
c.Accepts("ip_address")          // true: an input port carries it
c.MayEmit("asset:repository")    // false: no port carries it
violations, err := c.Check(report, capability.CheckOptions{})
```

`Check` reports outputs the capability may not emit and records that miss a required path; producers run it before upload and receivers again at ingest. The reference page [docs/capabilities.md](docs/capabilities.md) is generated from the data.

## Tool settings

The `settings` package is the tool settings contract: the closed subset of JSON Schema 2020-12 (plus `x-octm-*` annotations) in which a tool manifest declares its configuration, the validator, and the layered resolution of the values a task runs with. The platform validates what an administrator enters with it and the sensor validates the same values again before a task uses them; both import this one implementation, so the two never disagree.

```go
s, err := settings.ParseSchema(manifestConfigJSON)
err = s.Validate(map[string]any{"rate_limit": 100})
eff, err := s.Resolve(
	settings.Layer{Source: settings.SourceSensor, Values: sensorValues},
	settings.Layer{Source: settings.SourceScan, Values: scanValues},
)
eff.Source("rate_limit") // which layer set the effective value
```

Annotations: `x-octm-scope` (`sensor` or `scan`: the lowest layer that may set the key), `x-octm-tier` (the safety class of a non-default value: `T0` safe, `T1` impact, `T2` dangerous), `x-octm-common` (the key is a common tool option, see below), `x-octm-flag` (the tool's native flag, shown in a job's effective configuration), and presentation hints. Layers, in order: tenant policy, the sensor's configuration, a scan profile or workflow step, the scan, the platform's decision for one job; only tenant and sensor layers may set `sensor`-scope keys.

## Tool options

The `tooloption` package defines the execution options almost every scan tool has, once, so every tool, the sensor runtime and the platform mean the same thing by each name:

| Option | Unit | Bounds | Narrows |
|---|---|---|---|
| `timeout` | seconds per request or probe | 1..300 | no |
| `rate` | requests or packets per second | 1..100000 | down |
| `concurrency` | targets or requests at once | 1..1000 | down |
| `retries` | repeats of an unanswered request | 0..10 | down |

A tool declares its options in the configuration schema of its tool manifest; a property that is a common option carries `"x-octm-common": "<name>"`, must have the common type and may only narrow the common bounds (`CheckProperty`). Settings are layered (platform defaults, tenant policy, sensor configuration, scan or workflow step, the platform's decision for one job); for an option that narrows down, only an administrator's layer (tenant, sensor) may raise it above the tool's default, and a layer closer to the job may only lower the value in force (`NarrowValue`). `proxy`, `user_agent` and `headers` are reserved: the platform's egress and HTTP policy set them, never a tool option (`Reserved`).

```go
o, _ := tooloption.Lookup("rate")
o.CheckProperty("integer", nil, &max) // a tool's "rate" property is compatible
v, ok := o.NarrowValue(100, 500)      // 100, false: a scan cannot raise the sensor's rate
```

## Mapping any JSON tool output

The `importer/mapping` package turns the JSON or JSON Lines output of any command-line tool into CTIS through a declarative mapping file (`openctem.io/mapping/v1`), so wrapping a tool needs no parser code:

```go
m, err := mapping.Load(mappingJSON)
report, stats, err := m.Apply(ctx, stdout, mapping.Options{Tool: &ctis.Tool{Name: "example-portscan"}})
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

Every change to the format updates the schema, the Go types, the examples and the CHANGELOG together. `go test ./...` fails when the schema and the Go types disagree, when an example does not validate, or when the generated field reference in `docs/spec.md` is stale (refresh it with `go test -run TestSpecFieldReference -update`). The design record of the 1.4 to 1.6 additions, with the status of each proposal, is [docs/proposals-1.4.md](docs/proposals-1.4.md).

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
