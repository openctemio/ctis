### Added: repository source of a platform code scan

- New package `source`: `Repository` (SCM kind, HTTPS clone URL, branch, full commit id, depth, credential name, capabilities) with `Normalize`, `Validate`, `CheckCloneURL` and `ValidBranch`. The platform puts it in a code-scan job; the sensor fetches exactly that commit and refuses what `Validate` refuses.
- `Validate` refuses non-HTTPS URLs, address hosts, user information, queries, fragments, `..` or option-like path segments, branches git would read as an option or a revision expression, abbreviated commits, and capabilities that do not take a repository. A fuzz test pins these properties.

### Upgrade notes

- Additive: a new package; nothing existing changed.
