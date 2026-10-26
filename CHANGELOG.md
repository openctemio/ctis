# Changelog

All notable changes to CTIS. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Module versions follow [Semantic Versioning](https://semver.org/); module `v1.MINOR.x` implements CTIS spec `1.MINOR` (see [docs/spec.md](docs/spec.md#2-versioning-and-compatibility)).

## [Unreleased]

### Added: web content from crawlers and probes (forms, posture, aliases)

- `DiscoveredURLInput.Forms` (`WebFormInput`): each form becomes a `form` endpoint on the form's own origin with its field names (location `form`, never values). A field whose name says password, or that the producer marks `TypeHintPassword`, carries the type hint `password`: a receiver labels the endpoint as a login form from it. A form posting to another origin is not an endpoint of this one.
- `LiveHostInput.ResponseHeaders` and `LiveHostInput.CNAMEs`: the `http_service` asset gets a bounded `http_posture` property (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, the two CORS allow headers, and cookie names with their Secure, HttpOnly, SameSite and persistent flags) and a `cnames` property. The converter applies the allow-list itself: another header, or a cookie value, never reaches the report, and a value with a control character or over 4096 bytes is dropped.

## [1.6.3] - 2026-10-25

Additive release: the edge protection detector moves here so a platform and a sensor share one signature table without depending on each other. Nothing existing changed meaning.

### Added: `edgeprotect`, recognising a CDN or WAF in front of a service

- New package `edgeprotect`: `Classify(status, headers, title, body)` tells a challenge, a block, a rate limit or only fronting from the signs a vendor's own edge leaves (Cloudflare, AWS CloudFront and AWS WAF, Akamai, Fastly, Azure Front Door, Imperva, F5). A challenge or block needs a vendor marker next to the status: a bare 403 is the origin's own answer and stays `direct`. The rules are data (`Rule`, `DefaultRules`, `ClassifyWith`). Inputs are bounded (16 KiB of body, 512 bytes of title, 1 KiB per header value); it sends nothing, solves nothing and uses only the standard library.

## [1.6.2] - 2026-10-24

Additive release on CTIS 1.6: outcome revision 2 (why a target was not covered), CSV and XML declarative mappings with identity and field observation, and the bounty report importer. Nothing existing changed meaning.

### Added: outcome revision 2, classes that say why a target was not covered

- New `outcome` classes `name_gone`, `resolver_failed`, `sensor_network_fault`, `rate_limited`, `edge_challenged` and `edge_blocked` (edge classes valid under `failed` and `skipped`). They keep a target not covered, but tell a receiver whether the cause is the target, the sensor or the platform instead of reporting every unreached target as a scan failure.
- New optional `Target` members `cause`, `reason` and `vendor` (bounded lower-case tokens, omitted when empty), `Target.Side`, `Target.Fault`, `Target.Legacy` and `outcome.Revision` (2). Additive: revision 1 entries are unchanged on the wire. A sensor sends revision 2 entries only to a platform that advertised them (use `Legacy` otherwise); an unknown class is dropped by `Normalize` and the target stays unfinished, never done. A receiver must be upgraded before sensors send the new classes.

### Added: CSV and XML inputs, identity and field observation in declarative mappings

- `importer/mapping` reads `source: "csv"`. It reads a header row and detects the delimiter (`,` `;` tab `|`), or takes it from `csv.delimiter`. It skips preamble lines with `csv.skip_rows` and follows RFC 4180 quoting. Cells are capped (`Options.MaxCellBytes`, default 64 KiB), at most 1024 columns are read, and a UTF-16 input is refused (`ErrEncoding`). Cells are text and never evaluated.
- `importer/mapping` reads `source: "xml"` with `each` naming the record elements (`/a/b/c` or `//name`). The reader is the new `importer.SafeXMLTokenReader`, which refuses every document type declaration (no entities, no external resources) and bounds depth, elements, attributes, text and record size. Paths walk repeated and single elements alike.
- New mapping member `identity`: the finding members that identify a finding. A constant identity, and a constant `fingerprint`, are refused at load. A finding whose identity is empty is skipped. `Mapping.Identity()` and `Mapping.Rules()` let a receiver check its policy and compare versions.
- New `Options.Observe`: `Stats.Fields` lists the input's fields and `Stats.Unmapped` the ones no rule reads.
- One value set on a list member is now a one-item list. Before, the record was skipped.
- Three new samples, `generic-csv`, `generic-json` and `junit-xml`, which double as starter mappings.

### Added: bounty report importer format

- New importer format `bounty_report` (`importer.FormatBountyReport`) for bug-bounty and disclosure reports: JSON `{"bounty_reports": [...]}` or CSV with a header row. One report is one finding; `Detect` names the JSON shape by its top-level `bounty_reports` member, CSV is read only when the caller sets `Options.Format`.
- New option `Options.BountyIntake`: the intake of records that carry none (default `import`). The fingerprint is `bounty_report:v1:` + hex(sha256(intake + NUL + report_ref)).
- The report-specific members (intake, ref, researcher, submitted_at, reported_severity, state, weakness, endpoint_path, parameter, url, reward, disclosure) are in `findings[].properties.bounty_report`. Markup stays data; a `url` is kept only as an https URL in printable ASCII without credentials (an internationalised host only as `xn--`) and is never a reference; credentials in the asset URL are removed; bidirectional and control characters are removed; the importer opens no connection and resolves no name.
- `docs/importers/bounty_report.md` is generated.

## [1.6.1] - 2026-10-19

Additive release on CTIS 1.6: new contract packages (`addrscope`, `outcome`, `politeness`, `settings`, `source`, `tooloption`), the `transfer` module, the opengrep importer, and fixes. Nothing existing changed meaning.

### Added: `addrscope`, the one definition of an internal network address

- New package `addrscope` with `IsInternal(netip.Addr)`, `IsInternalPrefix(netip.Prefix)` and `EmbeddedIPv4`. The platform checks the targets of jobs for scanners that serve several organizations with it, and sensors check every address they connect to with the same function.
- Internal: private, loopback, link-local (cloud metadata), CGNAT, `0.0.0.0/8`, `192.0.0.0/24`, `198.18.0.0/15`, multicast, reserved and broadcast IPv4; unspecified, loopback, link-local, site-local, unique-local and multicast IPv6; and every IPv6 address that carries an internal IPv4 address (IPv4-mapped, IPv4-compatible, NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4 `2002::/16`, Teredo `2001::/32`). Invalid input is internal (fail closed). Documentation ranges are public.

### Added: host discovery in the capability taxonomy

- New `discover.hosts@1` (discover.active, T1, routed): in `ip`, `cidr`; out `ip`. Finds the live addresses of a range or an address list with light probes (ICMP echo or a TCP connection to a few common ports) before deeper scans. Each live address is reported as an `ip_address` asset with the probe that answered in `properties.live_by` (for example `tcp:443` or `icmp`). Params `ports` (TCP probe ports) and `rate`.
- `docs/capabilities.md` is regenerated.

### Added: a nuclei finding names the target it was run against

- The nuclei importer keeps the scan input (`host`, redacted) as `source_extra.target`. A receiver compares it with the matched URL to tell a path the template itself requested (one issue per origin, however many of its fixed paths matched) from a path that came from the target (one finding per endpoint).

### Added: opengrep JSON importer format

- New importer format `opengrep` (`importer.FormatOpengrep`) for `opengrep scan --json`. The output has the semgrep JSON shape and is read by the same parser; the report names the tool `opengrep` (vendor Opengrep) and tags findings `opengrep`. `Detect` cannot tell the two engines apart and still names the shape `semgrep`, so callers that ran opengrep choose the format with `Options.Format`.
- opengrep writes a real match-based id in `extra.fingerprint`. It is kept as the partial fingerprint `matchBasedId/v1`, and the finding's `fingerprint` is derived from path, rule and line, the value a semgrep run without a login produced. A finding first reported by semgrep therefore keeps its fingerprint when opengrep reports it.
- SARIF from opengrep (driver `Opengrep OSS`) is classified as SAST, as semgrep's is.
- `docs/importers/opengrep.md` is generated.

### Added: a failed target can say the sensor's egress refused it

- `outcome.EgressRefused` (`egress_refused`) is a new class of a `failed` target: the sensor's network confinement refused every connection the tool made toward that target. A receiver shows it as "not reached", never as "nothing found".

### Added: groups of one host for cutting a job's targets

- `politeness.Group(targets, network)` partitions targets into groups of one host: the targets whose keys conflict, directly or through other targets. Two parts built from whole groups never conflict, so the chunks of one step never wait on each other and the waves of a running job release whole hosts.
- `politeness.GroupKeys(keys)` is the same over keys a caller computed itself, for example a name with the keys of the addresses it is known to resolve to.
- One host is one group whatever form names it: `203.0.113.5`, `203.0.113.5:8443`, `203.0.113.5:443:tcp` and `https://203.0.113.5/` share the key `203.0.113.5` (a port never makes a separate host). Two addresses of one /24 bucket stay apart; a range joins the addresses of its buckets.

### Added: per-host politeness keys (`politeness/`)

- New package `github.com/openctemio/ctis/politeness` (standard library only): which hosts a scan job touches and when two jobs touch the same host. `Keys`, `TargetKeys`, `HostOf`, `Conflicts`, `Lock`, `AddrBucket`.
- A name, the host of a URL or a service, an address with the marker of its /24 (IPv6 /120) bucket, a range with one key per bucket, a repository clone URL or scp form (`host/owner`) and a local path each have a key; addresses are canonical (an IPv4-mapped address is the IPv4 address, `a.b.c.d/32` is the address).
- Network context: with a network id, the keys of private, shared, loopback and link-local addresses and of names end in `#<network>`; public addresses are never scoped; an unreadable id leaves the keys global.
- The platform and the sensor SDK both import it, so neither depends on the other for this contract. It replaces `github.com/openctemio/sdk-go/pkg/politeness` with the same API and keys.

### Added: release a running job's hosts target by target

- `politeness.Holding` (`NewHolding(held, targets, network)`, `Settle(target)`, `Held()`) tracks the keys a running job holds while its targets settle. A key is released once a settled target produced it and no pending target does. The holder (a sensor's local queue) frees it at once, so other work on that host starts before the job ends.
- A held key that no target produces is never released, and neither is a target the job never had. A bucket marker stays held while any pending address of its bucket does. Targets are keyed with and without the network, so keys computed either way are released alike.

### Added: repository source of a platform code scan

- New package `source`: `Repository` (SCM kind, HTTPS clone URL, branch, full commit id, depth, credential name, capabilities) with `Normalize`, `Validate`, `CheckCloneURL` and `ValidBranch`. The platform puts it in a code-scan job; the sensor fetches exactly that commit and refuses what `Validate` refuses.
- `Validate` refuses non-HTTPS URLs, address hosts, user information, queries, fragments, `..` or option-like path segments, branches git would read as an option or a revision expression, abbreviated commits, and capabilities that do not take a repository. A fuzz test pins these properties.

### Added: SARIF codeFlows become the finding's data flow

- `FromSARIF` (and the `sarif` importer format) maps a result's `codeFlows[].threadFlows[].locations[]` to `findings[].data_flow`: the first thread flow with a location, at most `MaxDataFlowSteps` (100) steps in order. A step's role comes from its `kinds` (`source`, `sink`, `sanitizer`), else its message (`Source:`, `Sink:`, `Propagator`, or a message that says the data is sanitized), else its position: the first unmarked step is the source and the last the sink. A step keeps its file, lines, columns, snippet, message (as `label`) and function. A malformed trace leaves the finding without a data flow and never fails the log. The mapping spec and `docs/importers/sarif.md` no longer list `codeFlows` as ignored.
- New `NormalizeDataFlow(df, roots...)`, applied by `FromSARIF` and by the semgrep and opengrep importers: bounds the steps and text (`MaxDataFlowContentLen`, `MaxDataFlowPathLen`, `MaxDataFlowLabelLen`), renumbers the step indexes, makes paths repository-relative (a file URI or absolute path is made relative to the run's `originalUriBaseIds` or to the root a relative path of the same flow reveals; otherwise, or when the path leaves the repository, the path is dropped and the step kept), and masks credentials in snippets, labels and notes.
- New `RedactCodeSecrets`: masks the credentials in a line of source code (a quoted value assigned to a credential name, a URL's password, tokens of a recognisable form, private key blocks) with `MaskSecretMatch`, and leaves the rest of the code as it is.

### Added: a line-independent SAST snippet hash a producer can send instead of the code

- `fingerprint.SnippetHash` hashes the code a SAST finding flags, independent of its line and indentation, and `fingerprint.PartialSnippetHash` (`snippetHash/v1`) is the `partial_fingerprints` key that carries it. A producer that has the scanned tree but no snippet from its scanner sends the hash, not the code; the receiver keys the finding on the flagged code, so a finding marked a false positive stays one when code above it moves.
- `fingerprint.MaxSnippetHashLines` (10) is where a producer reading the lines from the file cuts a long match, the same place the scanners cut it.

### Added: per-target outcomes (`outcome/`)

- New package `github.com/openctemio/ctis/outcome` (standard library only): how each target of a scan task ended. States `done`, `failed` (classes `unreachable`, `timeout`, `tool_error`), `skipped` (classes `refused`, `excluded`) and `unfinished`; a command result carries them under `target_outcomes`.
- `Normalize` reads a reported list against the task's own targets (unknown targets and invalid entries dropped, a missing target is unfinished, at most `MaxTargets` entries read); `Remaining` lists the targets to run again; `Count` counts the states.
- The platform and the sensor SDK both import it, so neither depends on the other for this contract.

### Added: common tool execution options (`tooloption/`)

- New package `github.com/openctemio/ctis/tooloption` (standard library only): the options almost every scan tool has, defined once: `timeout` (seconds per request, 1..300), `rate` (per second, 1..100000), `concurrency` (1..1000) and `retries` (0..10), with their unit, bounds, English title and description.
- `CheckProperty` checks that a tool manifest's property declared as a common option (`x-octm-common`) has the common type and only narrows the common bounds.
- `NarrowValue`: `rate`, `concurrency` and `retries` narrow down, so a layer closer to the job (a scan, a job decision) may only lower what an earlier layer (the sensor's configuration) set; `timeout` does not narrow.
- `Reserved`: `proxy`, `user_agent` and `headers` may not be tool options; the platform's egress and HTTP policy set them.
- The platform and the sensor SDK both import it, so neither depends on the other for what an option means.

### Added: tool settings contract (`settings/`)

- New package `github.com/openctemio/ctis/settings` (standard library and `tooloption` only): the closed JSON Schema 2020-12 subset a tool manifest declares its configuration in, its validator, defaults, digest and layered resolution. It is the validator the sensor SDK used (`sdk-go/pkg/core` settings), moved here so the platform validates administrators' values with the same code instead of a copy; the test vectors moved with it (`settings/testdata/vectors`).
- New annotations: `x-octm-common` names the common tool option a top-level key is (type and bounds checked against `tooloption`; an unbounded side takes the common bound; each common option at most once per tool), and `x-octm-flag` names the tool's native flag (one flag, no value) for display.
- Top-level keys named `proxy`, `user_agent` or `headers` are refused: the platform's egress and HTTP policy own them.
- Layers `tenant` (before the sensor's), `job` (the platform's decision for one job, after the scan's) and `local` (the sensor's local policy, last; it only lowers). Tenant, sensor and local layers may set keys of scope `sensor`; profile, scan and job layers only keys of scope `scan`.
- For a common option that narrows down (`rate`, `concurrency`, `retries`): a tenant or sensor layer may not raise what an earlier administrator layer set (the tool's default is not a cap for them); a profile, scan, job or local layer may only lower the value in force, the tool's default included. A raise is an error, never applied silently.

### Added: feed transfer module

- `github.com/openctemio/ctis/transfer` (own module, tag `transfer/vX.Y.Z`): fetch from ordered origins with retries, resume, blob cache and circuits; `transfer/bundle`: the signed chunked bundle format, writer and consumer.
- Moved unchanged from `github.com/openctemio/sdk-go/pkg/transfer` v0.1.0. A golden test pins every published byte (chunks, signed manifest, signed pointer) to that version, so publishers and consumers can switch in any order.

### Added: trivy findings say whether the package is direct and how it comes in

- With the package list of a language result (`trivy --list-all-pkgs`), each vulnerability gets `vulnerability.is_direct`, `vulnerability.dependency_path` (the shortest chain of package ids from the project or the direct dependency to the vulnerable package, at most 32 entries), the package's PURL when the record has none, and the lockfile with the package's first line as its location.
- Dependencies of a language result carry the lockfile as `path` and their lockfile lines as `locations`; `Indirect` sets the relationship when trivy gives no `Relationship`.
- OS-package results are unchanged: their target names an image, not a file.

### Fixed

- The recon converter no longer copies a live host's technologies into the asset's tags. They stay in `properties.technologies`; receivers keep them as detected technologies, and every fingerprint ("HSTS", a hosting platform) no longer becomes a user label.

### Upgrade notes

- Additive.
- Additive: no existing capability, param or rule changed.
- Additive: a new `source_extra` key.
- Additive. The semgrep format, its mapping and its fingerprints are unchanged.
- Additive. A receiver on an older version ignores the entry and treats the target as unfinished (handed out again), so update receivers (the platform) before senders (the sensor SDK) emit it.
- Additive: no existing function changed.
- Additive: no existing type, schema or rule changed.
- Additive: no existing function changed.
- Additive: a new package; nothing existing changed.
- `SARIFResult.CodeFlows` and `SARIFRun.OriginalURIBaseIDs` are new raw members. A SARIF log with code flows now yields findings with `data_flow`; the fingerprint is unchanged (the data flow never feeds it).
- A semgrep or opengrep trace step with an absolute path outside the repository, or one longer than 1024 characters, now has no path instead of a cut one.
- Additive: new functions and constants; nothing existing changed.
- Additive: no existing type, schema or rule changed.
- Additive: no existing type, schema or rule changed.
- Additive for this module. Schemas that declared a top-level `proxy`, `user_agent` or `headers` key no longer parse.
- Replace the import path `github.com/openctemio/sdk-go/pkg/transfer` with `github.com/openctemio/ctis/transfer`; nothing else changes. The ctis root module still has zero external dependencies.

## [1.6.0] - 2026-10-12

The first tagged release since v1.2.0. It implements CTIS 1.6 and includes everything listed under 1.3.0 below, which was never tagged, plus CTIS 1.4 and 1.5.

### Upgrade notes

- `SchemaVersion` is now `"1.4"` and `NewReport()` stamps it. Reports declaring 1.0 to 1.3 are still accepted, decode strictly and validate. Code that compared a version against the literal `"1.3"` should use `SupportedSchemaVersions()` / `IsSupportedVersion()` (versions this module knows every member of) or `IsCompatibleVersion()` (any minor of major 1).
- Receivers must run a 1.4 build before producers send the 1.4 members; a 1.3 receiver accepts the 1.4 stamp but refuses the new members.
- `SchemaVersion` is now `"1.5"` and `NewReport()`, the converters and the importers stamp it. Reports declaring 1.0 to 1.4 are unchanged and still validate. No converter emits the new members yet: receivers upgrade first (spec 2.2), producers send them afterwards.
- `SchemaVersion` is `"1.6"`. Reports of 1.0 to 1.5 are unchanged. Receivers upgrade first; producers send the 1.6 members afterwards.
- Additive: no existing capability, param or rule changed.
- The change is additive. The platform capability ids and the params it exposes are unchanged, and new params only follow the existing ones. No rule became stricter for a report without endpoints.

### Security

- `ConvertReconToCTIS` removes the user and password from probed and crawled URLs (`https://user:token@host/` put the credential into the asset value), and strips control characters from values the scanned host chooses: HTML titles, server headers and service names lose all of them, banners keep tab, newline and carriage return. ANSI escapes and forged newlines no longer reach a receiver's logs.
- `FromSARIF` no longer copies a secret scanner's raw match into the report. gitleaks and betterleaks write the matched secret into the SARIF region snippet unless run with `--redact`, and it went into `location.snippet` unchanged. For secret findings the snippet is now masked (first 4 characters of a value of 16 or more, else `REDACTED`), and the raw value is masked in the title, message and description too. `secret.masked_value` is left unset so receiver fingerprints do not change.
- The taxonomy is validated when the package loads: unknown phases, port types, CTIS asset or finding types, malformed ATT&CK/D3FEND/CAPEC ids, and required paths that do not name a CTIS member are refused, so a bad edit cannot ship.
- Ids are matched exactly (no case folding or trimming), so a look-alike capability name cannot resolve. `Check` is bounded (100 violations by default) on hostile reports and never modifies the report.
- `Validate` refuses malformed capability references (case, whitespace, missing major), ids that are not ATT&CK technique ids, unknown relationship types, relationships whose ends are not assets of the report or are the same asset, and every member above its limit. Hostile values quoted in errors are cut to 64 characters.
- A URL in `endpoints` and `finding.web` must carry no query value, user info or fragment, and `Validate` refuses one that does. A parameter value is refused by strict decoding and by the schema.
- No query value, user info or fragment reaches the output of the recon converter or the nuclei and ZAP importers. This covers the legacy `discovered_url` asset values, messages and ZAP evidence lines; names are kept as `name=`.
- No query value, user info or fragment reaches the output of the recon converter or the nuclei and ZAP importers. This covers the legacy `discovered_url` asset values, messages and ZAP evidence lines; names are kept as `name=`.
- `Validate` refuses:
  - hostile ids;
  - unknown enums;
  - control characters in paths, names, header values and labels;
  - dangling `origin_ref` and `endpoint_ref`;
  - every member over its limit.
- Spec 4.8: evidence MAY carry a sensitive value only inside a span it marks, and receivers MUST mask it before display or forwarding. `RedactSecretFinding` masks known raw secrets inside evidence too, except inside marked spans, and shifts a marked span when a masked value before it changes the length. Every other member stays secret-free.
- Producers mark sensitive values and never mask them; receivers mask them before display or forwarding (spec 4.8). The values marked are:
  - Authorization, Proxy-Authorization, Cookie, Set-Cookie and X-Api-Key headers;
  - headers named like a token, secret, session or auth;
  - query, form and JSON members named like a credential;
  - extracted values that look like credentials;
  - every repetition of these values in the other evidence items of the finding.
- Every item is capped:
  - bodies 64 KiB, headers 100 of 8 KiB and 32 KiB per message, extracted 20 of 1 KiB;
  - the item itself 256 KiB, after JSON escaping;
  - control characters are removed from headers, URLs and reasons;
  - a binary body is kept as base64.
- Tests check that no credential appears outside marked spans or outside evidence items, in the goldens and under hostile input.
- Endpoint user info (credentials in the URL), attached files, and the DefectDojo users who reported or mitigated a finding are never read.
- gitleaks: the raw secret never reaches the report. `Secret` is masked with the rule of the SARIF converter (first four characters of a value of at least 16 characters, else `REDACTED`) and every repeat in the description and fingerprint is replaced; `Match` and `Line` are not read; the commit author, e-mail and message are never read.
- grype: the scan configuration (registry settings and credentials), image manifest and config blobs and image labels are never read.
- ZAP: request and response headers and bodies (cookies, authorization headers, session tokens) are never read, and the user info of instance URIs is removed.
- The language has no loops, expressions, code, file or network access, so its cost is linear in the input.
- A mapping cannot set:
  - report-level members (`metadata`, `tool`, `$schema`);
  - record ids;
  - links between records (`asset_ref`, `related_assets`, `depends_on`, ...).
  
  Tool output therefore cannot forge references, and the report's tool comes only from the caller.
- Input limits:
  - 64 MiB per input;
  - 1 MiB per JSON Lines line;
  - 200 000 input and output records;
  - JSON nesting 64;
  - 4 KiB per string (64 KiB for free-text members).
- Strings lose control characters and invalid UTF-8.
- Issue messages that quote input are one bounded, clean line.
- Mapping-file limits: 256 KiB, 200 rules, 100 targets per rule, 256 `map` and `in` entries.
- Secret findings are masked with `ctis.RedactSecretFinding`.
- `RedactSecretFinding` no longer sizes an allocation from the number of masking candidates, which come from hostile text.
- Credential redaction in plugin output and compliance values also replaces an account label inside a line (`...; user: svc-scan`), not only at the start of a line.
- Imported files are hostile input: limits on size, nesting depth, elements, attributes, text and records; XML internal subsets, entity declarations and external resources are refused (an external DTD identifier is allowed and never read); only UTF-8, US-ASCII and ISO-8859-1; `OpenZip` refuses path traversal, absolute paths, links, encrypted entries, nested archives and decompression bombs.
- The Nessus scan policy (which holds scan credentials) is skipped whole; the accounts a scan logged in with are not read; plugin output and compliance values have account names, passwords, tokens and community strings replaced by `[redacted]`.
- Detection results are redacted of account names, passwords, tokens and community strings; host owner, comments and user-defined fields are never read; KnowledgeBase HTML is reduced to plain text and advisory links other than http(s) are dropped. The KnowledgeBase gets the same XML limits as the detection file.
- Raw secrets never reach a report: betterleaks and trivy matches are masked in the snippet, title and commit message, and only the masked value goes into fingerprints. Credentials in SARIF repository URIs and in nuclei URLs are removed; nuclei raw requests, responses, curl commands and extracted values, and trivy image configuration and code lines are never read.
- Each nuclei line is checked on its own: a broken, oversized or wrong-typed line is skipped with an issue at its line.
- Fuzzing found and this change fixes two invalid outputs: a trivy CVSS score above 10 in the legacy members, and a SARIF result with neither message nor rule.
- People's names and contacts (BOM authors, credits, supplier contacts, annotations, SPDX `Person:` suppliers and creators, e-mail addresses) are never read; CycloneDX proof-of-concept material is not copied. Package URLs with control characters or whitespace are dropped before they reach a match key.
- VEX documents are hostile input. A `not_affected` statement with neither a recognized justification nor an impact statement is left out with an issue, so a bare claim never suppresses a finding. Undefined, circular and over-limit product references are refused or left out, and links in the documents (SBOM URLs, references) are never fetched.
- **Nuclei results no longer carry the credentials of a matched URL.**
  - `importer.Parse` (nuclei) removes the credentials a matched URL carries before it reaches the finding message or location: the user info, and the values of query and fragment parameters named like a credential (`api_key`, `token`, `access_token`, `password`, `session`, `signature`, `code`, ...), which become `REDACTED`. A URL that does not parse is masked by pattern. The fingerprint is computed from the host without its user info; fingerprints of hosts without credentials are unchanged. Found while moving the sensor parsers onto the importer (sensor #175).
- **A secret scanner's raw match no longer survives in the title or other fields.**
  - A secret finding whose message, description, commit message, tags or properties repeated the raw secret kept it there; only the snippet was masked. This happened when the snippet held the whole code line (key = "...") rather than the bare secret, when a leak record reported only the match line, and when the secret was shorter than six characters.
  - New `RedactSecretFinding(f, known...)`: masks every known raw value, an unmasked snippet or `secret.masked_value` of a secret finding, and each secret-looking word of them, in every plain string field of the finding (title, description, message, evidence, remediation, tags, properties, fingerprints). Masking is `MaskSecretMatch` (at most the first 4 characters of a secret of 16 or more). Already masked values are kept; the call is idempotent. Receivers can call it before storage. New `ContainsSecret` for tests and receivers.
  - `FromSARIF` and every importer use it: SARIF from secret scanners (gitleaks, betterleaks, trufflehog, any `secret` tool), gitleaks and betterleaks JSON, trivy secrets, and any secret finding of another format. Nessus plugin output and compliance values and Qualys results: the passwords, tokens and community strings that credential redaction hides are also masked wherever another field repeats them.
  - The CTIS spec states it: the raw secret MUST NOT appear in any field of a finding; receivers SHOULD mask what they can recognise.
- A query value never leaves `Parse` or `RedactURL`. Only parameter names are kept, so tokens, keys and passwords in URLs cannot reach a report, a log or a database through this library.
- Hosts are matched in one ASCII form, so a look-alike Unicode spelling cannot become a second origin. Full UTS #46 mapping is not applied: only lowercasing and Punycode.

### Added

- **CTIS 1.4: interoperability members** (spec section 4.10), all optional, so every 1.3 report is a valid 1.4 report. Receivers must upgrade before producers send them.
  - `finding.native`: the source's own identity of the finding (`scheme`, `vuln_id`, `instance_id`, `family`, native `severity` and `status`, `detection_type` confirmed / potential / info, `credentialed`, `raw_ref`).
  - `finding.scores[]`: every score with `system` (cvss, epss, epss_percentile, ssvc, vpr, vendor), `version`, `vector`, `value`, `label`, `source` and `as_of`, so CVSS v3.1 and v4.0, vendor ratings, EPSS and SSVC travel together.
  - `finding.vex`: exploitability statement (`status`, `justification`, `native_justification`, `statement`, `source`, `as_of`) in the CSAF / OpenVEX vocabulary.
  - `finding.source_lifecycle`: `first_found`, `last_found`, `last_fixed`, `times_found`, `state` as the source tracks them.
  - `finding.source_extra`: unmapped source fields as bounded strings.
  - `vulnerability.ids[]`: typed vulnerability ids (cve, ghsa, osv, vendor).
  - `remediation.solution_type`, `remediation.patch_published_at`, `remediation.advisories[]`.
  - `asset.identity_hints`: FQDN, NetBIOS name, MACs, OS CPE, cloud resource id and agent id as a scanner observed them.
- `SupportedSchemaVersions()` and `IsSupportedVersion()`: the CTIS versions this module reads with full knowledge of their members (1.0 to `SchemaVersion`).
- Normalizers and mapping tables that keep the native value: `NormalizeNativeSeverity` (Nessus 0-4, Qualys 1-5, DefectDojo labels, SARIF levels), `NormalizeNativeStatus`, `NormalizeDetectionType`, `NormalizeVEXStatus`, `NormalizeVEXJustification` (CSAF, OpenVEX, CycloneDX), `NormalizeVulnerabilityID`, `VulnerabilityIDs`, `PreferredVulnerabilityID`, `LocationKey` (the derived location part of a deduplication key), `AllScores`, `CVSSVersionOfVector` and `SetSourceExtra`.
- `Validate` checks the new members: enums, score ranges per system, CVSS version and vector agreement, VEX consistency (`not_affected` needs a justification or statement; a justification only with `not_affected`), typed id shapes, and the size limits, which the schema states with `maxLength`, `maxItems` and `maxProperties`.
- Example `examples/network-vulnerability-interop.json` and four invalid examples for the new members. The test schema validator evaluates `maxItems` and `maxProperties`.
- `LiveHostInput` keeps what an HTTP probe learns about the server: `TLS` (the leaf certificate: subject, SANs, issuer, serial, validity, SHA-256 fingerprint, self-signed, wildcard, host mismatch), `FaviconMMH3`, `JARM`, `ASN` and `CDNType`. `ConvertReconToCTIS` emits one `certificate` asset per leaf, named by its SHA-256 fingerprint (64 lower-case hex) and linked from the `http_service` through `related_assets` and `properties.tls_fingerprint`; services that serve the same certificate share one asset. The service gets `favicon_mmh3`, `jarm`, `asn`/`asn_org`/`asn_country`, `cdn_type`, `waf` and `hosted_by`. Every value is bounded: names at 255 bytes, serial at 128, at most 100 SANs (the rest counted in `sans_truncated`), control characters removed; a leaf without a valid SHA-256 fingerprint, an invalid JARM or favicon hash, or an ASN number outside 1..2^32-1 is dropped.
- `MergeReconReports` keeps `related_assets` pointing at the right asset when merged IDs change.
- **The capability taxonomy (`capability` package).**
  - `capability` is the closed, versioned list of acts a scan tool performs: 29 entries (13 routed, 12 planned, 4 listed for later), each with an id and major (`scan.ports@1`), phase and CTEM stage, tier floor (0 passive, 1 active, 2 intrusive), typed input and output ports, standard params, required CTIS output paths, and MITRE ATT&CK, D3FEND and CAPEC references. The data is embedded JSON (`capability/taxonomy.json`), so every consumer reads one copy.
  - Port types name the CTIS asset types they carry; `Accepts` and `MayEmit` answer whether a capability takes or may emit a kind.
  - `Capability.Check` reports, for a CTIS report, the outputs the capability may not emit and the records that miss a required path. Rules may name alternative output shapes (`scan.ports`: one `open_port` asset per port, or ports on the IP asset).
  - New reference page `docs/capabilities.md`, generated from the data and kept current by a test.
- **CTIS 1.5 contract members.**
  - `metadata.capability`: the capability the report answers, as `id@major` (`scan.ports@1`). A producer claim; receivers bound to a command use the command capability.
  - `asset.technologies[]`: typed technologies (`name`, `version`, `cpe`, `categories`, `confidence`), replacing the untyped `properties.technologies` list.
  - `relationships[]`: typed edges between two assets of the report (`subdomain_of`, `resolves_to`, `cname_of`, `exposes`, `serves_certificate`, `hosted_by`).
  - `finding.attack[]`: the MITRE ATT&CK techniques a finding enables, at most 20.
  - `IsCapabilityRef`, `IsAttackTechniqueID`, `AllRelationshipTypes`; spec section 4.11 and the limits in section 7; example `examples/contract-members.json` and three invalid examples.
- **CTIS 1.6 web members and typed evidence.**
  - `endpoints[]` (top level): the methods and paths web origins serve, as a tool saw them.
    - Fields: normalised `origin`, `origin_ref`, `method`, concrete `path`, `template` hint, `kind`, `source`, redacted `parent`, `status_code`, `content_type`, `auth`, `technologies`.
    - `params[]` holds a `location`, a `name`, a `type_hint` and `required`. Parameters are named, never valued.
  - `finding.web`: the redacted `url`, `method`, `endpoint_ref`, `parameter` (`location`, `name`), `request_ref` and `status_code` of a web finding.
  - `finding.evidence_items[]` (at most 20): typed evidence. The envelope is `kind`, `version`, `label`, `captured_at`, `content_sha256` and `sensitive` spans.
    - Known kinds: `http_exchange` (request, response, match, extracted), `raw_text`, `curl`, `command_output`, `file_excerpt`, `screenshot`.
    - An unknown kind is validated by its envelope and carries its fields in `data`; it is never refused.
  - New schemas `schemas/v1/endpoint.json` and `schemas/v1/evidence-item.json`, spec sections 4.12 and 4.13, the section 7 limits, an example `examples/web-endpoints-evidence.json` and five invalid examples.
  - Go: `Endpoint`, `EndpointParam`, `WebLocation`, `WebParameter`, `EvidenceItem` and its parts, `SensitiveSpan`, the enums with their `All*` lists, `KnownEvidenceKinds` and `IsKnownEvidenceKind`.
  - Recon converter: a `url_crawl` emits `endpoints[]`. There is one endpoint per origin, method and path template, holding the query parameter names of every URL that fell into it, the kind, source, parent, status and content type. `DiscoveredURLInput` gains `ContentType` and `Params`. The legacy `discovered_url` assets stay for one release train, and `MergeReconReports` combines endpoints.
  - nuclei importer: the URL credential helper of the previous release is replaced by `weburl.RedactURL`, which drops every query value instead of only credential-named ones; the fingerprint of a host without credentials is unchanged. An http `matched-at` becomes `finding.web`, holding the URL, the method, and for DAST results the fuzzed parameter (`fuzzing_parameter` at `fuzzing_position`). A URL is no longer put in `location.path`.
  - ZAP importer: one finding per alert, method, URL template and parameter (at most 100 per alert), each with `finding.web`, its own instances as evidence (at most 20) and its own `occurrence_count`.
  - Recon converter: a `url_crawl` emits `endpoints[]`. There is one endpoint per origin, method and path template, holding the query parameter names of every URL that fell into it, the kind, source, parent, status and content type. `DiscoveredURLInput` gains `ContentType` and `Params`. The legacy `discovered_url` assets stay for one release train, and `MergeReconReports` combines endpoints.
  - nuclei importer: an http `matched-at` becomes `finding.web`, holding the URL, the method, and for DAST results the fuzzed parameter (`fuzzing_parameter` at `fuzzing_position`). A URL is no longer put in `location.path`.
  - ZAP importer: one finding per alert, method, URL template and parameter (at most 100 per alert), each with `finding.web`, its own instances as evidence (at most 20) and its own `occurrence_count`.
- **Typed evidence from nuclei, SARIF and ZAP.**
  - Builders in the root package that cap items and mark sensitive values, never masking them:
    - `HTTPExchangeFromRaw(request, response, baseURL)` for raw HTTP/1.x or HTTP/2 text;
    - `HTTPExchangeFromHAR(entry)` for a HAR 1.2 entry;
    - `CurlEvidence(command)`;
    - `MarkSensitive(items...)`;
    - `FitEvidenceItem(item)`;
    - `IsSensitiveHeader(name)` and `IsSensitiveParam(name)`.
  - nuclei:
    - `request` and `response` become one `http_exchange` item, with `extracted-results` (located in the response body when found there) and the matcher name;
    - `curl-command` becomes a `curl` item;
    - `timestamp` becomes `captured_at`.
  - SARIF: `webRequest` and `webResponse` become an `http_exchange` item (new `SARIFWebRequest`, `SARIFWebResponse` and `SARIFContent` types).
  - ZAP: the HTTP message of the first 3 instances of each finding becomes `http_exchange` items, with the instance evidence located in the response body.
  - `FuzzHTTPExchangeFromRaw` runs in the CI fuzz loop.
- **The DefectDojo Generic Findings JSON importer.**
  - `importer.Parse` reads DefectDojo Generic Findings Import JSON. One finding per record and endpoint host (domain or IP asset); a record without endpoints goes to `Options.DefaultAsset`, else to an unclassified asset named after the tool.
  - Kept: the severity label and the status flags as native values (normalized to the CTIS severity, status and source state), `vuln_id_from_tool` and `unique_id_from_tool`, CVE and typed vulnerability ids, CWE, CVSS v3 and v4 with vectors, EPSS, KEV, component and fix version, file and line, endpoint port, protocol and URL, tags, mitigation, effort, payload, and the other members in `source_extra`.
  - A record that cannot be decoded is skipped with an issue at its line; values written as numbers or strings are read either way.
  - New `Options.DefaultAsset` for records that name no asset.
- **Gitleaks, grype and ZAP importers.**
  - `importer.Parse` reads gitleaks JSON reports (`gitleaks`), grype JSON output (`grype`) and ZAP traditional reports in JSON and XML (`zap`); `importer.Detect` recognizes them.
  - gitleaks: one secret finding per leak on `Options.DefaultAsset` (the scanned repository), with rule id, location, commit, entropy and tags; the secret type is mapped to the CTIS vocabulary by keyword.
  - grype: the scanned image (container), directory (repository) or SBOM becomes the asset; one finding per match with every CVSS entry and its source, EPSS, KEV, typed ids of related vulnerabilities, fix versions and state, advisories; one dependency per artifact.
  - ZAP: one website asset per site origin; one finding per alert with riskcode severity, confidence, CWE, references, tags and up to 20 instances (method, URI, parameter, attack, evidence) as evidence.
  - Mapping specs `docs/importers/gitleaks.md`, `grype.md` and `zap.md`.
- **Declarative mappings for any JSON tool output (`importer/mapping`).**
  - `mapping.Load` reads a mapping file (`openctem.io/mapping/v1`, JSON). `(*Mapping).Apply` turns the JSON or JSON Lines output of a command-line tool into a CTIS report, so wrapping a tool needs no parser code. `(*Mapping).Digest` is the SHA-256 of the canonical mapping, for tool descriptors to record.
  - Rules:
    - closed predicates: `exists`, `equals`, `in`, and RE2 `matches` (at most 256 bytes);
    - kinds: `asset`, `finding`, `dependency`;
    - values: a source path, a constant or a named template;
    - transforms: `first`, `trim`, `lower`, `upper`, `split`, `map`, `join`, `as`, `max_bytes`, `default`.
  - Every target is checked against the CTIS Go types when the mapping loads.
  - Each emitted record is decoded strictly and validated. A record that fails is skipped and reported in `Stats.Issues` with its record number and rule.
  - Three samples with golden reports (a port scanner's JSON Lines, a JSON document with a result list, template-scanner findings). The golden reports are validated against the CTIS schema in CI.
  - Fuzz targets `FuzzApply` and `FuzzLoad` run in CI.
  - Spec: `docs/mapping.md`.
- **The importer package and the Nessus v2 importer.**
  - `importer.Detect` names the format of an exported file from its first bytes; `importer.Parse` converts it to a CTIS 1.4 report, with counts, problems with their line numbers, and the source fields the format's mapping spec does not list.
  - Nessus v2 XML (`.nessus`, from Nessus and Tenable.sc): one asset per host with its identity hints (FQDN, NetBIOS name, MACs, OS CPE, cloud instance id, agent id), one finding per plugin result or compliance check, with the native identity (plugin id, family, severity, credentialed scan), every CVSS version, VPR and EPSS in `scores`, typed vulnerability ids, CWEs, advisories, KEV and exploit flags, and the remaining plugin members in `source_extra`.
  - Every importer has a mapping spec rendered to `docs/importers/`, golden fixtures, and a field-coverage test that fails when a fixture holds a field the spec does not list or the spec maps a field no fixture holds.
  - `importer.OpenZip` lists the files of an uploaded ZIP archive without writing to disk.
- **The Qualys detection importer, joined with the KnowledgeBase.**
  - `importer.Parse` reads Qualys VM host list detection XML (`HOST_LIST_VM_DETECTION_OUTPUT`). Pass the KnowledgeBase export (`KNOWLEDGE_BASE_VULN_LIST_OUTPUT`) as `Options.QualysKnowledgeBase` to join it on QID; it is streamed and only the QIDs the detections name are decoded.
  - One asset per host with its identity hints (FQDN, NetBIOS, OS CPE, cloud resource id, Qualys agent host id) and tags; one finding per detection with the QID, unique detection id, native severity, status and detection type (Confirmed / Potential / Info), the detection score, the source lifecycle (first and last found, last fixed, times found, state), and from the KnowledgeBase the title, category, diagnosis, solution, CVEs, Bugtraq ids, vendor advisories, CVSS v2 and v3 with their source, threat intelligence, exploits and patch data.
  - Mapping specs `docs/importers/qualys.md` and `docs/importers/qualys_kb.md`.
- **SARIF tool type and default confidence in the importer.**
  - `importer.Options.ToolType` (`sast`, `sca`, `secret`, `iac`, `web3`) decides the type of every SARIF finding and the tool capabilities, as `ConvertOptions.ToolType` does for `FromSARIF`; a named tool (`Options.ToolName`) keeps the capabilities of its type. Other values are ignored.
  - `importer.Options.DefaultConfidence` (1 to 100) is the confidence of a SARIF result whose rule states no precision; zero or out of range keeps 90.
  - A scanner runtime can now convert its tools' SARIF through `importer.Parse` alone, with the importer's input limits, instead of calling `FromSARIF` directly.
- **SARIF 2.1.0 and the trivy, nuclei, semgrep, betterleaks and vuls formats in the importer.**
  - `importer.Parse` reads SARIF 2.1.0 (through `FromSARIF`, with the importer's input limits) and the native JSON of trivy, nuclei (JSON lines or an array), semgrep, betterleaks and vuls, with mapping specs, golden fixtures and the field-coverage gate like the other formats. `importer.Detect` recognizes each of them.
  - New `Options.Repository`, `Branch` and `CommitSHA`: the repository a code report is filed on. It wins over the repository or image a file names (a SARIF `versionControlProvenance`, a trivy artifact), so a receiver that sets it from a verified identity decides the asset, never the file.
  - `ctis.MaskSecretMatch`: the masking `FromSARIF` applies to a secret scanner's match, for other secret-scanner formats.
  - Parity with the SDK's tool adapters is tested on their fixtures; the differences are listed in the test with their reasons (SARIF titles and types from `FromSARIF`, schema secret types, no default criticality, semgrep's placeholder fingerprint).
- **CycloneDX, SPDX and OSV importers.**
  - CycloneDX 1.4-1.6 JSON (SBOM, VDR, VEX): the subject component is the asset (container, host or repository), every other component at any depth a dependency with licenses, hashes, purl and the dependency graph; one finding per vulnerability and affected component with typed ids, every rating as a score (CVSS 2.0-4.0, SSVC, vendor), CWEs, advisories, recommendation and workaround; `analysis` becomes the finding's VEX and a VEX statement whose products are the affected purls. Findings the analysis declares not_affected, resolved or false_positive are not made; a bare not_affected claim (no justification, no detail) is refused and the finding kept.
  - SPDX 2.2/2.3 JSON: the described package is the asset, every other package a dependency (purl, CPE, licenses, checksums, organization supplier and originator), DEPENDS_ON / CONTAINS relationships as the graph.
  - osv-scanner JSON results: one asset per scanned source, its packages as dependencies, one finding per package and vulnerability group with every id and alias, CVSS vectors as scores, the affected version range and fixed versions, and database-specific data in `source_extra`.
  - Mapping specs `docs/importers/cyclonedx.md`, `spdx.md`, `osv.md` with golden fixtures under the field-coverage gate.
- **CSAF 2.0 and OpenVEX importers.**
  - `importer.Parse` reads CSAF 2.0 documents (the `csaf_vex` and `csaf_security_advisory` profiles) and OpenVEX documents (v0.2.0, and the v0.0.1 string forms). A VEX document describes products, not findings: the report has no assets or findings, and `Result.VEX` holds the statements, each with the vulnerability's typed ids, the products (PURL, CPE, or name and version) and the CTIS VEX status, justification, statement, source and date.
  - CSAF: the product tree is resolved (branches at any depth, full product names, relationships, product groups); first/last affected, first fixed and recommended merge into the affected and fixed statements; a not_affected statement takes its justification from the flags and its text from the impact threats, an affected or fixed statement its text from the remediations.
  - `Product.Subcomponents`: a statement about components inside a product only (an OpenVEX subcomponent, a CSAF relationship). A receiver must match those components only on that product.
  - A mapping spec `**` segment matches any number of path segments, for formats that nest to any depth.
- **Passive registration and network ownership lookups in the capability taxonomy.**
  - New `lookup.rdap@1` (discover.passive, T0, routed): in `root_domain`, out `root_domain`. Registrar, registrant organization, name servers and registration dates of a root domain from the RDAP service of its registry, reported on the domain (`technical.domain`, required `technical.domain.whois`). Param `follow_registrar`.
  - New `lookup.asn@1` (discover.passive, T0, routed): in `ip`, `cidr`; out `ip`, `cidr`. Origin autonomous system, holder and announced range of an address or network from public routing data (required `technical.ip_address.asn` on addresses, `properties.asn` on networks). Params `include_announced`, `max_ranges`.
  - `intel.passive@1` (planned) no longer names RDAP and ASN data in its description.
  - `docs/capabilities.md` is regenerated.
- **Web endpoints in the capability taxonomy.**
  - Port type `endpoint`: a stream of web endpoints (CTIS 1.6 `report.endpoints`), which are sub-inventory of a `url` and not assets.
  - Output kind `endpoint`. A capability may report endpoints through an endpoint port (in or out) or the `endpoint` extra output, and a required-output rule may `select: "endpoints"` (no type filter). `Check` reports endpoints from a capability that may not emit them as `not_allowed` at `/endpoints`.
  - `crawl.web@1` gains the out port `endpoint` and an `endpoints` rule (`origin`, `path`). Legacy `discovered_url` reports still conform.
  - `dast.web@1` and `vuln.templates@1` gain the in port `endpoint`, and `web.url` joins their findings `any_of`.
  - `verify.finding@1` retests a web finding at its `finding.web` location.
  - `probe.http@1` gains the boolean param `api_schema` (fetch OpenAPI or GraphQL schema documents at well-known paths), and may report endpoints.
  - New `import.api_spec@1`: collect, T0, planned, cross-cutting, no input, out `endpoint`.
  - `docs/capabilities.md` is regenerated.
- **Weburl, one library to parse, normalise and template web URLs.**
  - New package `weburl`. The sensor, the SDK and the platform use it to turn a web URL into the same endpoint identity.
  - `Parse` is strict and returns the normalised URL. It refuses:
    - any scheme other than `http` and `https`;
    - user info;
    - a URL over 2,048 bytes;
    - invalid UTF-8;
    - control, white-space and bidi characters, including percent-encoded control characters;
    - a malformed escape;
    - an invalid port;
    - an ambiguous numeric host (`2130706433`, `0x7f.0.0.1`).
  - `Parse` normalises:
    - the origin: lowercase scheme and ASCII host, internationalized labels in Punycode, no trailing dot, IPv6 in canonical form, default port dropped;
    - the path: unreserved escapes decoded and the others upper-cased, dot segments resolved, empty segments collapsed, no trailing slash, `;jsessionid=` removed. Case is kept;
    - the query: reduced to its sorted parameter names, at most 100, each at most 128 bytes.
  - `Template` / `TemplatePath` replace identifier segments with typed variables:
    - `{int}`, `{uuid}`, `{date}`, `{email}`, `{hex}`;
    - `{token}`: JWT-like, or a mixed-case base64url value of 20 characters or more;
    - `{id}`: 12 or more letters and digits.

    The rules are deterministic and use RE2 only.
  - `RedactURL` removes the user info, every query value and the fragment, and never fails.
  - `PathHash(method, template)` is the dedup key of an endpoint. `NormalizeMethod` checks the closed method set (`ANY` when unknown).
  - A 223-URL golden corpus, including hostile inputs, and the `FuzzWebURL` fuzz target, which runs in CI.

### Changed

- `DefaultReconConverterOptions` no longer sets `DefaultCriticality` (it was `medium`). Criticality is business context that a scanner does not know (spec section 4.1); `FromSARIF` stopped setting it in 1.3.0. OpenCTEM files an asset without criticality as medium, so its behaviour is unchanged.
- `ConvertReconToCTIS` writes each resolved IP of a subdomain once, in canonical form (`::ffff:192.0.2.1` is `192.0.2.1`).
- `FromSARIF` carries SARIF `suppressions` (a `nosemgrep` comment, a CodeQL alert suppression) as `finding.suppression`, and sets `status: suppressed` when SARIF calls the result suppressed (at least one accepted suppression, none under review or rejected). They were dropped, so a suppressed result looked open. `SARIFResult` gains `Suppressions`.
- `FromSARIF` ignores the placeholder fingerprint `requires login` that Semgrep OSS writes for every result (all results got the same `fingerprint`).
- `FromSARIF` carries `properties.tags` from the result and its rule into `finding.tags` (they were dropped). Tags are deduplicated ignoring case in first-seen order; non-string, empty and over-long (more than 128 bytes) entries are skipped; at most 50 are kept per finding.
- betterleaks (a gitleaks fork) is recognised as a secret scanner: its SARIF findings get type `secret` and the tool gets the `secret` capability (they were typed `vulnerability`).
- **One parser for gitleaks and betterleaks reports.**
  - gitleaks and betterleaks write the same JSON shape and are now read by one parser. `importer.Detect` names the shape `gitleaks`; `betterleaks` is the same mapping under its tool name, chosen with `Options.Format`. The record is filed on `Options.Repository` (else `Options.DefaultAsset`); the secret is masked with `ctis.MaskSecretMatch` in the masked value, snippet, title and commit message; the commit author and e-mail are kept (the person who must rotate the secret), replacing the gitleaks behaviour of the previous unreleased entry that dropped them.
  - `importer.Detect` also recognizes a nuclei `-json-export` array.

### Fixed

- **Nessus host-level results carry their host.**
  - Every Nessus finding now has `network.host`, `network.port` and `network.protocol`. A host-level result (port 0, Nessus pseudo-service `general`) used to have no network location, so a receiver keyed it by its title instead of by host and plugin; it is now keyed like any other network result. A port outside 1-65535 is reported as host-level.
- **The importer never returns an invalid CTIS report.**
  - Every asset, finding, component and VEX statement a parser builds is validated on its own before `importer.Parse` returns. One that is not valid CTIS (a required name or title missing, a duplicate id, a bare not_affected claim) is left out with a counted issue, and a finding whose asset was left out goes with it. If the report would still fail `Report.Validate`, `Parse` fails instead of returning it.
  - `FuzzParseFormat` fuzzes each parser directly (`IMPORTER_FUZZ_FORMAT` names one), without format detection.
- **A secret whose text is part of the mask word is masked once.**
  - `RedactSecretFinding` (and `FromSARIF` for secret findings) set the snippet and `secret.masked_value` to their mask before masking every other field, so a raw value such as `CTED` was masked again inside `REDACTED` and the snippet read `REDAREDACTED`. The mask is now set after the other fields. No raw value was exposed: the result was over-masked, not under-masked. Found by `FuzzFromSARIF`.

### Documentation

- Spec: new sections 4.8 (secrets: no member may hold a usable secret; bounds on `masked_value`) and 4.9 (`metadata.source_type` is the channel and a producer claim; results are bound to commands by the request, not the body).
- Spec 4.5: an absent `coverage_type` is not `full`, and receivers MUST NOT auto-resolve from it.
- Spec 4.2: `network.protocol` is the transport; send it whenever `port` is sent.
- Spec 2.2: new enum values are refused by older receivers, the same as new members.
- Spec 7: OpenCTEM's per-field text caps and the v1 body limit.
- README lists all eight schemas and every importer format; the spec lists `relationships` and `endpoints` among the report members and drops the protocol v1 body limit; `docs/proposals-1.4.md` records the status of each proposal.
- `SECURITY.md`: how to report a vulnerability privately.

## [1.3.0] - 2026-10-02

Receivers (OpenCTEM API) must upgrade before producers send `suppression.reason`, `suppression.expires_at` or `dependencies[].properties`.

### Changed

- **License: GPL-3.0 to Apache-2.0.** The schemas and Go types can now be used by any producer without copyleft obligations.
- **Schema and Go types agree, field by field and enum by enum.** A test walks both recursively in both directions (members, JSON types, required members, enums, `additionalProperties`) and fails the build on any difference. There is no exception list.
- Every schema object sets `additionalProperties: false`, except the free-form `properties` bags and typed maps. A typo now fails schema validation the way it already failed strict ingest.
- `version` accepts any `1.<minor>` (it was `const "1.0"`); the schema's `default` is the version it describes. `NewReport()` stamps `1.3` and `$schema`. Receivers accept any 1.x (spec section 2).
- Schema `$id`s moved from the unresolvable `schemas.openctem.io` to `https://raw.githubusercontent.com/openctemio/ctis/main/schemas/v1/`.
- `epss_percentile` is a 0-1 fraction, as FIRST publishes it (the schema said 0-100, which no producer sent).
- `dependencies[].version` is no longer required (the Go type always allowed it to be empty).
- `services[]` require `port` (the Go type always sends it).
- `finding.asset_type` uses the asset type enum.
- `FromSARIF`:
  - converts every run, not just the first;
  - picks the fingerprint deterministically (lowest key) instead of by map order;
  - reads GitHub `security-severity` (CodeQL, Trivy) before the SARIF level;
  - types findings from rule tags and CVE/GHSA rule IDs, so Trivy CVEs are vulnerabilities, not misconfigurations;
  - reads CWE arrays and `external/cwe/cwe-NNN` tags, and OWASP tags;
  - finds the rule by `rule.id`, `ruleIndex` or `rule.index` too;
  - carries `partialFingerprints`, `correlationGuid` and `baselineState` (matched case-insensitively);
  - reads `result.kind` into `finding.kind`, mapping SARIF's `notApplicable` to `not_applicable` (it was dropped, so a passed or inapplicable check looked like any other finding); values outside SARIF's set are left unset, and `SARIFResult` gains `Kind`;
  - no longer sets the asset's criticality to `high`;
  - capabilities: known SAST tools report `sast`, `ToolType: sca` reports `sca`, and an unknown tool reports `vulnerability` (it reported `vulnerability, secret`, which OpenCTEM read as a secret scan).
- `SARIFResult.RuleIndex` is now `*int` (absent is not index 0).
- `ConvertReconToCTIS`:
  - output validates against the schema: scope type `domain`/`network` (was `web`), capabilities `subdomain`/`dns`/`portscan`/`http_probe`/`crawler` (was the raw recon type), DNS types upper-cased and one record per value (values were joined with ", "), unknown DNS types kept in `properties.other_dns_records`;
  - a port-scan target without an IP is a `host`, not an `ip_address` with `version: 4`;
  - every HTTP probe result is an `http_service`; the type no longer flips to `service` on a 2xx/3xx status;
  - `$schema` is the real schema URL; the vendor is `projectdiscovery` only for ProjectDiscovery tools;
  - asset IDs are unique within the report; assets keep input order;
  - the caller's options are no longer modified.
- `MergeReconReports`: deterministic first-seen order, capabilities are the union of the inputs' capabilities (were tool names), inputs are never modified, and a single report is copied, not returned as is.
- `Report.Validate` also rejects: a zero timestamp, a version that is not `1.<minor>`, a `tool` without a name, duplicate asset/finding/dependency IDs, an `asset_ref` that names no asset, and confidence, rank, CVSS, EPSS and VPR outside their ranges (or NaN/infinite). It lists at most 100 problems.

### Added

- Schema entries for every field the Go types already had: `secret.verified_at`, `revoked_at`, `age_in_days`, `commit_count`; `vulnerability.fixed_versions`, `affected_version_range`, `advisories`, `is_direct`; `suppression.kind`, `status`; `location.context_start_line`; `logical_location.parent_index`; `attachments[].artifact_location.index`; the full `FindingLocation` for `dependencies[].location`.
- Go fields for schema members that had none: `Suppression.Reason`, `Suppression.ExpiresAt`, `Dependency.Properties`.
- Asset type `server` in the schema (the Go enum had it).
- DNS record type `CAA`.
- Capability values OpenCTEM already reads: `dast`, `va`, `easm`, `cspm`, `external`, `import`, `subdomain`, `dns`, `portscan`, `http_probe`, `crawler`, `tech-detect`.
- `ctis.SchemaVersion`, `SchemaMajor`, `SchemaBaseURL`, `SchemaURL`, `ParseVersion`, `IsCompatibleVersion`, `AllDataFlowLocationTypes`.
- `fingerprint.GenerateSASTStable` and `fingerprint.TypeSASTContent`: a line-independent SAST fingerprint (file, rule, enclosing function, normalised snippet).
- `docs/spec.md`: the normative specification, with a field reference generated from the schema (CI fails when it is stale), versioning rules, fingerprint recipes per finding type, receiver limits, and what OpenCTEM stores.
- `docs/proposals-1.4.md`: technique field, web/DAST block, typed relationships, VEX, aliases, KEV detail, scan outcome.
- `examples/`: one report per finding type plus an attack-surface asset report, and `examples/invalid/` with mistakes the schema must reject.
- Fuzz targets: `FuzzValidate`, `FuzzFromSARIF`, `FuzzConvertRecon`, `FuzzParseVersion`.
- Golden tests for `FromSARIF` with Semgrep, CodeQL and Trivy logs.

### Removed

- Schema members no receiver ever accepted (the Go types lacked them, so strict ingest rejected any report using them): `suppression.state` (use `status`), `dependencies[].target_index` (pointed at a `targets` array that does not exist), `dependencies[].location.line`/`column` (use `start_line`/`start_column`), `attachments[].rectangles`.
- Asset type `other` from the schema. The Go types never accepted it; use `unclassified`. OpenCTEM still files `other` as unclassified.

### Fixed

- golangci-lint finding in `fingerprint` tests (QF1001).

### CI

- golangci-lint is blocking and pinned (v2.14.0, `.golangci.yml`).
- Coverage gate enforced at 85% (was a warning at 50%; total is about 95%).
- Schema job: draft-07 meta-validation, `$ref` resolution through the `$id` registry, examples and converter golden files validated with format checks, invalid examples must be rejected.
- Fuzz smoke job.
- Release: the tag must be `vMAJOR.MINOR.PATCH`, match the module path, match `ctis.SchemaVersion` and have a CHANGELOG section; release notes come from that section.
- Third-party actions pinned by commit SHA.

## [1.2.0] - 2026-10-01

### Added

- `asset.identifiers`: stable identifiers (`machine_id`, `cloud_resource_id`, `bios_uuid`, `serial_number`, `mac_addresses`, `scm_repo_id`) so a renamed or readdressed asset keeps its history.

### CI

- Release notes escape stray `@mentions` and drop email addresses.

## [1.1.0] - 2026-06-05

### Added

- Nessus/Tenable fields: `vulnerability.cve_ids`, `vulnerability.vpr_score`, `finding.network` (host, port, protocol, service), `finding.evidence`.
- `Report.Validate()`: required fields and enum membership, zero dependencies.
- `severity.FromCVSSWithVersion`: CVSS v2 has no critical band.

### Fixed

- `FindingStatus` gained `suppressed`, matching the schema.
- `FromSARIF` falls back to the rule's `defaultConfiguration.level` when a result has no level.
- `truncateString` no longer panics on small limits; `itoa` handles `math.MinInt`.

### Changed

- `Severity.Score` documents its fail-safe: an unknown severity scores as medium.

## [1.0.0] - 2026-04-15

### Added

- Initial module: CTIS report, asset, finding and dependency types; Web3 assets and findings; JSON Schemas in `schemas/v1`; `severity` and `fingerprint` packages; SARIF and recon converters; CI, release and security workflows.

[1.3.0]: https://github.com/openctemio/ctis/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/openctemio/ctis/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/openctemio/ctis/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/openctemio/ctis/releases/tag/v1.0.0
