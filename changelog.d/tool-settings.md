### Added: tool settings contract (`settings/`)

- New package `github.com/openctemio/ctis/settings` (standard library and `tooloption` only): the closed JSON Schema 2020-12 subset a tool manifest declares its configuration in, its validator, defaults, digest and layered resolution. It is the validator the sensor SDK used (`sdk-go/pkg/core` settings), moved here so the platform validates administrators' values with the same code instead of a copy; the test vectors moved with it (`settings/testdata/vectors`).
- New annotations: `x-octm-common` names the common tool option a top-level key is (type and bounds checked against `tooloption`; an unbounded side takes the common bound; each common option at most once per tool), and `x-octm-flag` names the tool's native flag (one flag, no value) for display.
- Top-level keys named `proxy`, `user_agent` or `headers` are refused: the platform's egress and HTTP policy own them.
- Layers `tenant` (before the sensor's) and `job` (the platform's decision for one job, after the scan's). Tenant and sensor layers may set keys of scope `sensor`; profile, scan and job layers only keys of scope `scan`.
- For a common option that narrows down (`rate`, `concurrency`, `retries`), a later layer that raises the value an earlier layer set is an error, never applied silently.

### Upgrade notes

- Additive for this module. Schemas that declared a top-level `proxy`, `user_agent` or `headers` key no longer parse.
