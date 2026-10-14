### Added: a failed target can say the sensor's egress refused it

- `outcome.EgressRefused` (`egress_refused`) is a new class of a `failed` target: the sensor's network confinement refused every connection the tool made toward that target. A receiver shows it as "not reached", never as "nothing found".

### Upgrade notes

- Additive. A receiver on an older version ignores the entry and treats the target as unfinished (handed out again), so update receivers (the platform) before senders (the sensor SDK) emit it.
