# Line list mapping

Generated from `importer/spec_lines.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `lines`
- Source versions: one value per line: the plain output of name, address and URL tools (gau, waymore, puredns, massdns -o S, subfinder or dnsx without -json, crlfuzz -o, dnstake -o)
- Fields: 1 mapped, 0 ignored on purpose (100% mapped)

## Rules

- Never detected: choose it with Options.Format, and say what the lines name with Options.LinesAs (auto, host, domain, ip, url).
- Each line is trimmed; an empty line is ignored and a line starting with # is a comment. The value is the first word of the line, so "name. A address" (massdns -o S) reads the name.
- auto: a value with :// is a URL, then an address or a CIDR block, else a DNS name. host: a DNS name or an address. A trailing dot of a DNS name is removed.
- A URL (http or https only) is a web_origin asset and an endpoint of it (source import): parameter names are kept, values never, user info is removed, and an e-mail address in a path becomes {email}.
- An address is an ip_address asset and a CIDR block an ip_range asset.
- A line that is longer than 64 KiB, is not valid UTF-8, holds a control character or names nothing usable is skipped and counted in one issue. At most 2 000 000 lines are read.
- An inventory format: assets and endpoints, never findings. The tool name is Options.ToolName (default lines).
- Every host-bearing asset carries extensions[io.openctem].import_scope relative to Options.ScopeDomains; the receiver judges scope.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/line` | `assets[] (domain_name, ip_address, ip_range, web_origin), endpoints[]` |  |
