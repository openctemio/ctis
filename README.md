# CTIS — CTEM Ingest Schema

Official JSON schemas and Go types for the CTIS format — the standard for ingesting security data into the OpenCTEM platform.

## Overview

CTIS supports assets, findings, and metadata from various security tools. This repo is the single source of truth for:
- **JSON Schemas** (`schemas/v1/`) — language-agnostic format definitions
- **Go Types** (root package) — strongly-typed structs for Go consumers
- **Severity** (`severity/`) — severity enum with parsing and comparison
- **Fingerprint** (`fingerprint/`) — SHA256-based finding deduplication

## Installation (Go)

```bash
go get github.com/openctemio/ctis
```

```go
import (
    "github.com/openctemio/ctis"
    "github.com/openctemio/ctis/severity"
    "github.com/openctemio/ctis/fingerprint"
)

// Parse a CTIS report
var report ctis.Report
json.Unmarshal(data, &report)

// Severity parsing
sev := severity.FromString("high")

// Finding fingerprint for dedup
fp := fingerprint.GenerateSAST("src/main.go", "sql-injection", 42, 42)
```

## Schemas

JSON Schema definitions in `schemas/v1/`:

| Schema | Description |
|---|---|
| `report.json` | Main CTIS report envelope |
| `asset.json` | Asset schema (domains, IPs, repos, cloud, Web3) |
| `finding.json` | Security finding schema |
| `dependency.json` | SBOM dependency schema |
| `web3-asset.json` | Web3-specific asset details |
| `web3-finding.json` | Web3 vulnerability details |

Schema URLs:
```
https://schemas.openctem.io/ctis/v1/report.json
https://schemas.openctem.io/ctis/v1/asset.json
https://schemas.openctem.io/ctis/v1/finding.json
```

## Validating CTIS Reports

### Python

```bash
pip install jsonschema
```

```python
import json
from jsonschema import validate

with open('schemas/v1/report.json') as f:
    schema = json.load(f)

with open('my-report.json') as f:
    report = json.load(f)

validate(instance=report, schema=schema)
```

### Node.js

```bash
npm install ajv ajv-formats
```

```javascript
const Ajv = require('ajv');
const addFormats = require('ajv-formats');
const ajv = new Ajv({ allErrors: true });
addFormats(ajv);

const schema = require('./schemas/v1/report.json');
const validate = ajv.compile(schema);
const valid = validate(myReport);
```

## Asset Types

| Type | Example | Description |
|---|---|---|
| `domain` | `example.com` | Domain names |
| `subdomain` | `api.example.com` | Subdomains |
| `ip_address` | `192.168.1.1` | IPv4/IPv6 addresses |
| `host` | `web-server-01` | Hosts/servers |
| `repository` | `github.com/org/repo` | Code repositories |
| `certificate` | `SHA256:abc123` | SSL/TLS certificates |
| `cloud_account` | `aws:123456789` | Cloud accounts |
| `container` | `sha256:abc` | Container images |
| `kubernetes` | `cluster/namespace` | K8s resources |
| `database` | `db-prod-01` | Databases |
| `service` | `host:443:tcp` | Network services |
| `application` | `https://app.example.com` | Web applications |
| `identity` | `arn:aws:iam::123:user/admin` | IAM users/roles |

## Finding Types

| Type | Description |
|---|---|
| `vulnerability` | Code/infrastructure vulnerabilities |
| `secret` | Exposed secrets/credentials |
| `misconfiguration` | IaC/configuration issues |
| `compliance` | Compliance violations |
| `web3` | Smart contract vulnerabilities |

## Design Principles

- **Zero external dependencies** — stdlib only (Go package)
- **Backward compatible** — new fields are additive, never breaking
- **Semantic versioning** — major version = breaking schema change
- **Shared contract** — used by API (consumer), SDK-Go (agent framework), and Agent (producer)

## License

MIT License — see [LICENSE](LICENSE)
