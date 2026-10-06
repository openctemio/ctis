### Added: SARIF tool type and default confidence in the importer

- `importer.Options.ToolType` (`sast`, `sca`, `secret`, `iac`, `web3`) decides the type of every SARIF finding and the tool capabilities, as `ConvertOptions.ToolType` does for `FromSARIF`; a named tool (`Options.ToolName`) keeps the capabilities of its type. Other values are ignored.
- `importer.Options.DefaultConfidence` (1 to 100) is the confidence of a SARIF result whose rule states no precision; zero or out of range keeps 90.
- A scanner runtime can now convert its tools' SARIF through `importer.Parse` alone, with the importer's input limits, instead of calling `FromSARIF` directly.
