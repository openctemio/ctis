### Added: opengrep JSON importer format

- New importer format `opengrep` (`importer.FormatOpengrep`) for `opengrep scan --json`. The output has the semgrep JSON shape and is read by the same parser; the report names the tool `opengrep` (vendor Opengrep) and tags findings `opengrep`. `Detect` cannot tell the two engines apart and still names the shape `semgrep`, so callers that ran opengrep choose the format with `Options.Format`.
- opengrep writes a real match-based id in `extra.fingerprint`. It is kept as the partial fingerprint `matchBasedId/v1`, and the finding's `fingerprint` is derived from path, rule and line, the value a semgrep run without a login produced. A finding first reported by semgrep therefore keeps its fingerprint when opengrep reports it.
- SARIF from opengrep (driver `Opengrep OSS`) is classified as SAST, as semgrep's is.
- `docs/importers/opengrep.md` is generated.

### Upgrade notes

- Additive. The semgrep format, its mapping and its fingerprints are unchanged.
