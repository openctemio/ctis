# Fingerprints and the correlation key (CTIS 2.0)

This page is normative for recipe v2 (`ctis-fp/2`) and the correlation key (`ctis-ck/1`). Both ship in CTIS 2.0. The Go implementation is the `fingerprint` package and `CorrelationKey`; any other language implements the text below and runs the vectors in `conformance/v2/fingerprint/` and `conformance/v2/correlation/`.

Recipe v1 (`ctis-fp/1`) is not part of the 2.0 format. The Go code for it stays, deprecated, only so a receiver can compute the old and the new value of a stored finding when it migrates.

## Output

A fingerprint is `ctis-fp/2:` followed by 64 lowercase hexadecimal characters: the SHA-256 of the canonical input.

## Canonical input

The canonical input is built from a list of elements: the recipe name first, then the recipe's parts in the order given below.

1. Each element is its UTF-8 bytes, written as `<n>:<bytes>` where `<n>` is the byte length in decimal without leading zeros (`0:` for an empty element).
2. The encoded elements are joined with the single byte `0x1F`.

Example: recipe `sca`, parts `a:b` and `c` give the bytes `3:sca`, `0x1F`, `3:a:b`, `0x1F`, `1:c`.

Because every element states its own length, no content (a `:` in a Maven name, a `0x1F`, text that looks like a length prefix) can move into a neighbouring element. Two different part lists never share a canonical input. Bytes are taken as given: there is no Unicode normalisation, so a precomposed and a decomposed accent are different.

## Normalisation rules

Applied to each part before encoding.

| Part | Rule |
|---|---|
| identifier (rule id, vulnerability id, resource type and name, framework, control id, parameter, function, logical location) | trim white space; case kept |
| file path | trim white space; every `\` becomes `/`; empty and `.` segments are dropped (so `./a`, `a//b` and `a/./b` lose their extra parts); a leading `/` is kept; `..` is not resolved; case kept |
| host or address (VA asset value) | trim; lowercase; one trailing `.` removed |
| URL | parsed as an http(s) URL with the rules of package `weburl`: lowercase scheme and host, default port dropped, IDNA host, path normalised with its case kept, query and fragment dropped. The parts are the origin (`scheme://host[:port]`) and the path. A URL that does not parse gives no fingerprint |
| package | a package URL without version, qualifiers and subpath, type in lowercase (`pkg:maven/org.x/lib@1?type=jar` becomes `pkg:maven/org.x/lib`). A value that is not a package URL (`maven/org.x:lib`) is used trimmed |
| image | the registry and repository, plus `@sha256:<hex>` when a digest is present; the tag is dropped. No registry means `docker.io`; a Docker Hub repository without a namespace gets `library/`. The registry is lowercase, the repository keeps its case |
| integers (lines, port, chain id) | decimal, no padding |
| transport | trim; lowercase |
| contract address | a `0x` (or bare) 40-digit hexadecimal address becomes `0x` and lowercase digits; any other value (not hexadecimal) is trimmed and keeps its case |
| snippet | every run of white space becomes one space, the ends are trimmed; the part is the lowercase hex SHA-256 of the result |

No recipe reads a message, title or description. Line numbers are a part of the line-based SAST recipe (`sast`) and of `generic` only.

## Recipes

Parts, in order, after the recipe name.

| Recipe | Parts | Notes |
|---|---|---|
| `sast` | file path, rule id, start line, end line | the identity changes when code above moves |
| `sast-content` | file path, rule id, logical location (enclosing function, may be empty), snippet hash | line independent; no fingerprint when the snippet is empty |
| `sca` | package, vulnerability id | versionless, so an upgrade of the same package that keeps the vulnerability keeps the key |
| `secret` | file path, rule id, secret digest | see below; no line number |
| `misconfig` | resource type, resource name, rule id, file path | |
| `dast` | rule or template id, origin, path, parameter name | parameter name, never its value |
| `container` | image identity, package, vulnerability id | package as for `sca` |
| `va` | host, port, transport, vulnerability or plugin id | network assessment; port `0` and an empty transport mean the host |
| `compliance` | framework, control id, resource | |
| `web3` | chain id, contract address, rule (SWC) id, function signature | |
| `generic` | rule id, file path, start line, end line | fallback; no message |

The recipe name is exactly the first column (`misconfig`, not `misconfiguration`). The type to use for input that names none is chosen in this order, first match wins: contract address, image and package, framework or control, secret digest, URL, VA asset value with a port or transport, package and vulnerability id, resource type or name, file and rule and snippet, file and rule and a start line, else `generic`.

## Secrets

The only form of a secret that enters a fingerprint is its digest: `HMAC-SHA256(producer_key, secret)`, 32 bytes, written as 64 lowercase hex characters in the part. There is no unsalted path in v2 and no hash prefix. A recipe call without a digest (or with the all-zero digest) produces no fingerprint.

Key handling:

- The producer holds the key. The key, the secret and any masked copy of the secret are never put in a report: only the fingerprint leaves the producer.
- Use at least 16 random bytes. One key per producer installation (or per tenant) stops two installations from confirming each other's secrets.
- Keep it as secret as the credentials it protects, and keep it stable: rotating it changes the fingerprint of every secret finding once.

`conformance/v2/fingerprint/secret-digest.json` pins the digest function.

## Correlation key

The correlation key says that two findings, possibly from different tools, describe the same issue at the same place on the same asset. It is `ctis-ck/1:` followed by the lowercase hex SHA-256 of the canonical input (the encoding above) of the recipe name `ctis-ck` and three parts:

1. the asset key, computed by the receiver (never taken from the producer);
2. the preferred vulnerability id (CVE first, the numerically smallest; then GHSA, OSV, vendor, in their listed order), or, when the finding has no vulnerability id, `rule:` + tool name + `/` + rule id, both trimmed;
3. `LocationKey`: the first of `pkg:<versionless purl>` (or `pkg:<type>/<name>` from the ecosystem and package name), `url:<origin><path>` from `web.url` and then from a URL-shaped `location.path`, `file:<repository path>`, `net:<port>/<protocol>` (`net:host` without a port), `resource:<type>/<name>`; empty when none applies. A key longer than 512 bytes is cut and ends in `#` and 32 hex characters of its SHA-256.

Receivers compute the key; a producer's value is never trusted.

The tool is the name of the tool that raised the finding. A finding that carries its own tool uses that, otherwise the report's tool is used: in Go, `CorrelationKeyForTool(assetKey, tool, finding)`.

## Vectors

- `conformance/v2/fingerprint/fingerprint.json`: per recipe, the input, the normalised `parts` (to compare each step), the expected value, and cases that must be refused (`error`). It includes colons and `0x1F` in parts, Maven `group:artifact` names, case-differing paths, Unicode and length-prefix look-alikes.
- `conformance/v2/fingerprint/secret-digest.json`: the HMAC function.
- `conformance/v2/correlation/correlation.json`: finding, tool, intermediate parts and expected key.

The values were cross-checked with an independent implementation of the encoding and hash.
