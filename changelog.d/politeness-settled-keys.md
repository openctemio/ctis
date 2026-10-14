### Added: release a running job's hosts target by target

- `politeness.Holding` (`NewHolding(held, targets, network)`, `Settle(target)`, `Held()`) tracks the keys a running job holds while its targets settle. A key is released once a settled target produced it and no pending target does. The holder (a sensor's local queue) frees it at once, so other work on that host starts before the job ends.
- A held key that no target produces is never released, and neither is a target the job never had. A bucket marker stays held while any pending address of its bucket does. Targets are keyed with and without the network, so keys computed either way are released alike.

### Upgrade notes

- Additive: no existing function changed.
