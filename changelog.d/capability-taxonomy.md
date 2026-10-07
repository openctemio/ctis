### Added: the capability taxonomy (`capability` package)

- `capability` is the closed, versioned list of acts a scan tool performs: 29 entries (13 routed, 12 planned, 4 listed for later), each with an id and major (`scan.ports@1`), phase and CTEM stage, tier floor (0 passive, 1 active, 2 intrusive), typed input and output ports, standard params, required CTIS output paths, and MITRE ATT&CK, D3FEND and CAPEC references. The data is embedded JSON (`capability/taxonomy.json`), so every consumer reads one copy.
- Port types name the CTIS asset types they carry; `Accepts` and `MayEmit` answer whether a capability takes or may emit a kind.
- `Capability.Check` reports, for a CTIS report, the outputs the capability may not emit and the records that miss a required path. Rules may name alternative output shapes (`scan.ports`: one `open_port` asset per port, or ports on the IP asset).
- New reference page `docs/capabilities.md`, generated from the data and kept current by a test.

### Security

- The taxonomy is validated when the package loads: unknown phases, port types, CTIS asset or finding types, malformed ATT&CK/D3FEND/CAPEC ids, and required paths that do not name a CTIS member are refused, so a bad edit cannot ship.
- Ids are matched exactly (no case folding or trimming), so a look-alike capability name cannot resolve. `Check` is bounded (100 violations by default) on hostile reports and never modifies the report.
