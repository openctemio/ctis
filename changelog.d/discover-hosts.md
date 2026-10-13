### Added: host discovery in the capability taxonomy

- New `discover.hosts@1` (discover.active, T1, routed): in `ip`, `cidr`; out `ip`. Finds the live addresses of a range or an address list with light probes (ICMP echo or a TCP connection to a few common ports) before deeper scans. Each live address is reported as an `ip_address` asset with the probe that answered in `properties.live_by` (for example `tcp:443` or `icmp`). Params `ports` (TCP probe ports) and `rate`.
- `docs/capabilities.md` is regenerated.

### Upgrade notes

- Additive: no existing capability, param or rule changed.
