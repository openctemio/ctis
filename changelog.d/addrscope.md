### Added: `addrscope`, the one definition of an internal network address

- New package `addrscope` with `IsInternal(netip.Addr)`, `IsInternalPrefix(netip.Prefix)` and `EmbeddedIPv4`. The platform checks the targets of jobs for scanners that serve several organizations with it, and sensors check every address they connect to with the same function.
- Internal: private, loopback, link-local (cloud metadata), CGNAT, `0.0.0.0/8`, `192.0.0.0/24`, `198.18.0.0/15`, multicast, reserved and broadcast IPv4; unspecified, loopback, link-local, site-local, unique-local and multicast IPv6; and every IPv6 address that carries an internal IPv4 address (IPv4-mapped, IPv4-compatible, NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4 `2002::/16`, Teredo `2001::/32`). Invalid input is internal (fail closed). Documentation ranges are public.

### Upgrade notes

- Additive.
