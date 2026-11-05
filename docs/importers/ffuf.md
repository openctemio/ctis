# ffuf JSON output mapping

Generated from `importer/spec_ffuf.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `ffuf`
- Source versions: ffuf 2.x -of json
- Fields: 4 mapped, 16 ignored on purpose (20% mapped)

## Rules

- An inventory format: every result is a URL that answered. Its origin is a web_origin asset and the URL an endpoint of it (source import) with the status code and content type; parameter names are kept, values never, and user info is removed. No findings.
- The command line and the configuration are never read: they hold the headers, cookies, tokens and proxy the person gave ffuf.
- The fuzzed words (input) are not kept: the URL already holds what was found.
- A result whose URL is not http(s) is skipped with an issue.
- Every web origin carries extensions[io.openctem].import_scope relative to Options.ScopeDomains; the receiver judges scope.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/commandline` |  | the command line holds headers, cookies and tokens: never read |
| `/config` |  | the configuration holds headers, cookies, tokens and proxies: never read |
| `/config/**` |  | the configuration holds headers, cookies, tokens and proxies: never read |
| `/time` |  | run time |
| `/results` | (container) |  |
| `/results[]` | `assets[] (web_origin), endpoints[]` |  |
| `/results[]/url` | `assets[].value (origin), endpoints[] (method GET, template, parameter names)` |  |
| `/results[]/status` | `endpoints[].status_code` |  |
| `/results[]/content-type` | `endpoints[].content_type` |  |
| `/results[]/host` |  | the host of the URL |
| `/results[]/input` |  | the fuzzed words; the URL holds what was found |
| `/results[]/input/**` |  | the fuzzed words; the URL holds what was found |
| `/results[]/position` |  | position in the word list |
| `/results[]/length` |  | response size |
| `/results[]/words` |  | response word count |
| `/results[]/lines` |  | response line count |
| `/results[]/redirectlocation` |  | the redirect target: another URL, not probed |
| `/results[]/scraper` |  | scraper output (free text) |
| `/results[]/scraper/**` |  | scraper output (free text) |
| `/results[]/duration` |  | response time |
| `/results[]/resultfile` |  | a local file name |
