# semgrep JSON output mapping

Generated from `importer/spec_semgrep.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `semgrep`
- Source versions: semgrep 1.x --json
- Fields: 52 mapped, 23 ignored on purpose (69% mapped)

## Rules

- One finding per result, filed on Options.Repository, else Options.DefaultAsset, else an unclassified asset named after the tool (with an issue).
- Severity: ERROR high, WARNING medium, INFO low, INVENTORY and EXPERIMENT info; native.severity keeps the word. Confidence from metadata.confidence (HIGH 90, MEDIUM 70, LOW 50).
- The placeholder "requires login" that semgrep writes in fingerprint and lines without a login is no value and is dropped; the fingerprint is then derived from path, rule and line.
- A taint trace is read in both forms semgrep writes (objects, or the tagged ["CliLoc", [location, content]]); call steps are skipped.
- An ignored result (nosemgrep) gets an in-source suppression. Errors become issues.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/version` | `tool.version` |  |
| `/results` | (container) |  |
| `/results[]` | `findings[]` |  |
| `/results[]/check_id` | `findings[].rule_id, rule_name, native.vuln_id` |  |
| `/results[]/path` | `findings[].location.path` |  |
| `/results[]/start` | (container) |  |
| `/results[]/start/line` | `findings[].location.start_line` |  |
| `/results[]/start/col` | `findings[].location.start_column` |  |
| `/results[]/start/offset` |  | byte offset; line and column are kept |
| `/results[]/end` | (container) |  |
| `/results[]/end/line` | `findings[].location.end_line` |  |
| `/results[]/end/col` | `findings[].location.end_column` |  |
| `/results[]/end/offset` |  | byte offset; line and column are kept |
| `/results[]/extra` | (container) |  |
| `/results[]/extra/message` | `findings[].title, message` |  |
| `/results[]/extra/severity` | `findings[].severity, native.severity` |  |
| `/results[]/extra/lines` | `findings[].location.snippet` |  |
| `/results[]/extra/fingerprint` | `findings[].fingerprint` |  |
| `/results[]/extra/is_ignored` | `findings[].suppression` |  |
| `/results[]/extra/fix` | `findings[].remediation.fix_code` |  |
| `/results[]/extra/fix_regex` | (container) |  |
| `/results[]/extra/fix_regex/regex` | `findings[].remediation.fix_regex.regex` |  |
| `/results[]/extra/fix_regex/replacement` | `findings[].remediation.fix_regex.replacement` |  |
| `/results[]/extra/fix_regex/count` | `findings[].remediation.fix_regex.count` |  |
| `/results[]/extra/validation_state` | `findings[].source_extra.validation_state` |  |
| `/results[]/extra/engine_kind` | `findings[].source_extra.engine_kind` |  |
| `/results[]/extra/metavars` |  | matched metavariables: fragments of source code, the snippet is kept |
| `/results[]/extra/metavars/**` |  | matched metavariables: fragments of source code, the snippet is kept |
| `/results[]/extra/dataflow_trace` | `findings[].data_flow` |  |
| `/results[]/extra/dataflow_trace/taint_source` | `findings[].data_flow.sources` |  |
| `/results[]/extra/dataflow_trace/taint_source[]/**` | `findings[].data_flow.sources (location path, start line and column, content)` |  |
| `/results[]/extra/dataflow_trace/taint_source[][]/**` | `findings[].data_flow.sources (tagged form: location path, start line and column)` |  |
| `/results[]/extra/dataflow_trace/taint_sink[][]/**` | `findings[].data_flow.sinks (tagged form: location path, start line and column)` |  |
| `/results[]/extra/dataflow_trace/intermediate_vars` | `findings[].data_flow.intermediates` |  |
| `/results[]/extra/dataflow_trace/intermediate_vars[]/**` | `findings[].data_flow.intermediates (location path, start line and column, content)` |  |
| `/results[]/extra/dataflow_trace/taint_sink` | `findings[].data_flow.sinks` |  |
| `/results[]/extra/dataflow_trace/taint_sink[]/**` | `findings[].data_flow.sinks (location path, start line and column, content)` |  |
| `/results[]/extra/metadata` | (container) |  |
| `/results[]/extra/metadata/cwe` | `findings[].vulnerability.cwe_ids` |  |
| `/results[]/extra/metadata/cwe[]` | `findings[].vulnerability.cwe_ids` |  |
| `/results[]/extra/metadata/owasp` | `findings[].vulnerability.owasp_ids` |  |
| `/results[]/extra/metadata/owasp[]` | `findings[].vulnerability.owasp_ids` |  |
| `/results[]/extra/metadata/confidence` | `findings[].confidence` |  |
| `/results[]/extra/metadata/impact` | `findings[].impact` |  |
| `/results[]/extra/metadata/likelihood` | `findings[].likelihood` |  |
| `/results[]/extra/metadata/category` | `findings[].category` |  |
| `/results[]/extra/metadata/subcategory` | `findings[].subcategory` |  |
| `/results[]/extra/metadata/subcategory[]` | `findings[].subcategory` |  |
| `/results[]/extra/metadata/technology` | `findings[].tags` |  |
| `/results[]/extra/metadata/technology[]` | `findings[].tags` |  |
| `/results[]/extra/metadata/references` | `findings[].references` |  |
| `/results[]/extra/metadata/references[]` | `findings[].references` |  |
| `/results[]/extra/metadata/vulnerability_class` | `findings[].vulnerability_class` |  |
| `/results[]/extra/metadata/vulnerability_class[]` | `findings[].vulnerability_class` |  |
| `/results[]/extra/metadata/source` | `findings[].source_extra.rule_source` |  |
| `/results[]/extra/metadata/source-rule-url` | `findings[].references` |  |
| `/results[]/extra/metadata/shortlink` | `findings[].references` |  |
| `/results[]/extra/metadata/license` | `findings[].source_extra.rule_license` |  |
| `/results[]/extra/metadata/*` |  | other rule metadata (rule authoring details) |
| `/results[]/extra/metadata/*/**` |  | other rule metadata (rule authoring details) |
| `/errors` | (container) |  |
| `/errors[]` | `issues` |  |
| `/errors[]/message` | `issues (message)` |  |
| `/errors[]/type` | `issues (kind)` |  |
| `/errors[]/path` | `issues (path)` |  |
| `/errors[]/type[][]/**` |  | spans of the error kind; the path is kept |
| `/errors[]/type[]` |  | spans of the error kind; the path is kept |
| `/errors[]/code` |  | exit-code class of the error |
| `/errors[]/level` |  | error level; every error becomes an issue |
| `/errors[]/spans` |  | source spans of a parse error; the path is kept |
| `/errors[]/spans[]/**` |  | source spans of a parse error; the path is kept |
| `/paths` |  | the files semgrep scanned (scan operation details) |
| `/paths/**` |  | the files semgrep scanned (scan operation details) |
| `/time` |  | timing statistics |
| `/time/**` |  | timing statistics |
| `/profiling_results` |  | timing statistics |
| `/profiling_results/**` |  | timing statistics |
| `/skipped_rules` |  | rules semgrep did not run |
| `/skipped_rules/**` |  | rules semgrep did not run |
| `/engine_requested` |  | engine kind of the run |
| `/interfile_languages_used` |  | engine detail of the run |
| `/interfile_languages_used/**` |  | engine detail of the run |
