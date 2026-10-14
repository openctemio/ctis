### Added: per-target outcomes (`outcome/`)

- New package `github.com/openctemio/ctis/outcome` (standard library only): how each target of a scan task ended. States `done`, `failed` (classes `unreachable`, `timeout`, `tool_error`), `skipped` (classes `refused`, `excluded`) and `unfinished`; a command result carries them under `target_outcomes`.
- `Normalize` reads a reported list against the task's own targets (unknown targets and invalid entries dropped, a missing target is unfinished, at most `MaxTargets` entries read); `Remaining` lists the targets to run again; `Count` counts the states.
- The platform and the sensor SDK both import it, so neither depends on the other for this contract.

### Upgrade notes

- Additive: no existing type, schema or rule changed.
