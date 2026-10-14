### Added: SARIF codeFlows become the finding's data flow

- `FromSARIF` (and the `sarif` importer format) maps a result's `codeFlows[].threadFlows[].locations[]` to `findings[].data_flow`: the first thread flow with a location, at most `MaxDataFlowSteps` (100) steps in order. A step's role comes from its `kinds` (`source`, `sink`, `sanitizer`), else its message (`Source:`, `Sink:`, `Propagator`, or a message that says the data is sanitized), else its position: the first unmarked step is the source and the last the sink. A step keeps its file, lines, columns, snippet, message (as `label`) and function. A malformed trace leaves the finding without a data flow and never fails the log. The mapping spec and `docs/importers/sarif.md` no longer list `codeFlows` as ignored.
- New `NormalizeDataFlow(df, roots...)`, applied by `FromSARIF` and by the semgrep and opengrep importers: bounds the steps and text (`MaxDataFlowContentLen`, `MaxDataFlowPathLen`, `MaxDataFlowLabelLen`), renumbers the step indexes, makes paths repository-relative (a file URI or absolute path is made relative to the run's `originalUriBaseIds` or to the root a relative path of the same flow reveals; otherwise, or when the path leaves the repository, the path is dropped and the step kept), and masks credentials in snippets, labels and notes.
- New `RedactCodeSecrets`: masks the credentials in a line of source code (a quoted value assigned to a credential name, a URL's password, tokens of a recognisable form, private key blocks) with `MaskSecretMatch`, and leaves the rest of the code as it is.

### Upgrade notes

- `SARIFResult.CodeFlows` and `SARIFRun.OriginalURIBaseIDs` are new raw members. A SARIF log with code flows now yields findings with `data_flow`; the fingerprint is unchanged (the data flow never feeds it).
- A semgrep or opengrep trace step with an absolute path outside the repository, or one longer than 1024 characters, now has no path instead of a cut one.
