### Added: common tool execution options (`tooloption/`)

- New package `github.com/openctemio/ctis/tooloption` (standard library only): the options almost every scan tool has, defined once: `timeout` (seconds per request, 1..300), `rate` (per second, 1..100000), `concurrency` (1..1000) and `retries` (0..10), with their unit, bounds, English title and description.
- `CheckProperty` checks that a tool manifest's property declared as a common option (`x-octm-common`) has the common type and only narrows the common bounds.
- `NarrowValue`: `rate`, `concurrency` and `retries` narrow down, so a layer closer to the job (a scan, a job decision) may only lower what an earlier layer (the sensor's configuration) set; `timeout` does not narrow.
- `Reserved`: `proxy`, `user_agent` and `headers` may not be tool options; the platform's egress and HTTP policy set them.
- The platform and the sensor SDK both import it, so neither depends on the other for what an option means.

### Upgrade notes

- Additive: no existing type, schema or rule changed.
