# arjun JSON output mapping

Generated from `importer/spec_arjun.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `arjun`
- Source versions: arjun 2.x -oJ (an object keyed by URL)
- Fields: 3 mapped, 2 ignored on purpose (60% mapped)

## Rules

- An inventory format: every URL's origin is a web_origin asset and the URL an endpoint of it (source import) with the parameter names arjun found. No findings.
- Method GET puts the names in the query; POST in a form; JSON in a JSON body (all POST); XML in a body (POST, form location).
- At most 200 names per endpoint; a name is cut to 128 bytes. Parameter values are never part of the file.
- The request headers arjun sent are never read: they hold the person's cookies and tokens.
- A key that is not an http(s) URL is skipped with an issue.
- Every web origin carries extensions[io.openctem].import_scope relative to Options.ScopeDomains; the receiver judges scope.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/*` | `assets[] (web_origin), endpoints[] (the key is the URL)` |  |
| `/*/method` | `endpoints[].method, params[].location` |  |
| `/*/params` | (container) |  |
| `/*/params[]` | `endpoints[].params[].name` |  |
| `/*/headers` |  | request headers with cookies and tokens: never read |
| `/*/headers/**` |  | request headers with cookies and tokens: never read |
