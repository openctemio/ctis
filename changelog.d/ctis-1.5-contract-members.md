### Added: CTIS 1.5 contract members

- `metadata.capability`: the capability the report answers, as `id@major` (`scan.ports@1`). A producer claim; receivers bound to a command use the command capability.
- `asset.technologies[]`: typed technologies (`name`, `version`, `cpe`, `categories`, `confidence`), replacing the untyped `properties.technologies` list.
- `relationships[]`: typed edges between two assets of the report (`subdomain_of`, `resolves_to`, `cname_of`, `exposes`, `serves_certificate`, `hosted_by`).
- `finding.attack[]`: the MITRE ATT&CK techniques a finding enables, at most 20.
- `IsCapabilityRef`, `IsAttackTechniqueID`, `AllRelationshipTypes`; spec section 4.11 and the limits in section 7; example `examples/contract-members.json` and three invalid examples.

### Upgrade notes

- `SchemaVersion` is now `"1.5"` and `NewReport()`, the converters and the importers stamp it. Reports declaring 1.0 to 1.4 are unchanged and still validate. No converter emits the new members yet: receivers upgrade first (spec 2.2), producers send them afterwards.

### Security

- `Validate` refuses malformed capability references (case, whitespace, missing major), ids that are not ATT&CK technique ids, unknown relationship types, relationships whose ends are not assets of the report or are the same asset, and every member above its limit. Hostile values quoted in errors are cut to 64 characters.
