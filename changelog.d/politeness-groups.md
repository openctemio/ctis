### Added: groups of one host for cutting a job's targets

- `politeness.Group(targets, network)` partitions targets into groups of one host: the targets whose keys conflict, directly or through other targets. Two parts built from whole groups never conflict, so the chunks of one step never wait on each other and the waves of a running job release whole hosts.
- `politeness.GroupKeys(keys)` is the same over keys a caller computed itself, for example a name with the keys of the addresses it is known to resolve to.
- One host is one group whatever form names it: `203.0.113.5`, `203.0.113.5:8443`, `203.0.113.5:443:tcp` and `https://203.0.113.5/` share the key `203.0.113.5` (a port never makes a separate host). Two addresses of one /24 bucket stay apart; a range joins the addresses of its buckets.

### Upgrade notes

- Additive: no existing function changed.
