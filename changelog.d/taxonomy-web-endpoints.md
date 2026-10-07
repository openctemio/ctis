### Added: web endpoints in the capability taxonomy

- Port type `endpoint`: a stream of web endpoints (CTIS 1.6 `report.endpoints`), which are sub-inventory of a `url` and not assets.
- Output kind `endpoint`. A capability may report endpoints through an endpoint port (in or out) or the `endpoint` extra output, and a required-output rule may `select: "endpoints"` (no type filter). `Check` reports endpoints from a capability that may not emit them as `not_allowed` at `/endpoints`.
- `crawl.web@1` gains the out port `endpoint` and an `endpoints` rule (`origin`, `path`). Legacy `discovered_url` reports still conform.
- `dast.web@1` and `vuln.templates@1` gain the in port `endpoint`, and `web.url` joins their findings `any_of`.
- `verify.finding@1` retests a web finding at its `finding.web` location.
- `probe.http@1` gains the boolean param `api_schema` (fetch OpenAPI or GraphQL schema documents at well-known paths), and may report endpoints.
- New `import.api_spec@1`: collect, T0, planned, cross-cutting, no input, out `endpoint`.
- `docs/capabilities.md` is regenerated.

### Upgrade notes

- The change is additive. The platform capability ids and the params it exposes are unchanged, and new params only follow the existing ones. No rule became stricter for a report without endpoints.
