### Added: a nuclei finding names the target it was run against

- The nuclei importer keeps the scan input (`host`, redacted) as `source_extra.target`. A receiver compares it with the matched URL to tell a path the template itself requested (one issue per origin, however many of its fixed paths matched) from a path that came from the target (one finding per endpoint).

### Upgrade notes

- Additive: a new `source_extra` key.
