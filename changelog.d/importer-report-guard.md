### Fixed: the importer never returns an invalid CTIS report

- Every asset, finding, component and VEX statement a parser builds is validated on its own before `importer.Parse` returns. One that is not valid CTIS (a required name or title missing, a duplicate id, a bare not_affected claim) is left out with a counted issue, and a finding whose asset was left out goes with it. If the report would still fail `Report.Validate`, `Parse` fails instead of returning it.
- `FuzzParseFormat` fuzzes each parser directly (`IMPORTER_FUZZ_FORMAT` names one), without format detection.
