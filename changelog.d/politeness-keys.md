### Added: per-host politeness keys (`politeness/`)

- New package `github.com/openctemio/ctis/politeness` (standard library only): which hosts a scan job touches and when two jobs touch the same host. `Keys`, `TargetKeys`, `HostOf`, `Conflicts`, `Lock`, `AddrBucket`.
- A name, the host of a URL or a service, an address with the marker of its /24 (IPv6 /120) bucket, a range with one key per bucket, a repository clone URL or scp form (`host/owner`) and a local path each have a key; addresses are canonical (an IPv4-mapped address is the IPv4 address, `a.b.c.d/32` is the address).
- Network context: with a network id, the keys of private, shared, loopback and link-local addresses and of names end in `#<network>`; public addresses are never scoped; an unreadable id leaves the keys global.
- The platform and the sensor SDK both import it, so neither depends on the other for this contract. It replaces `github.com/openctemio/sdk-go/pkg/politeness` with the same API and keys.

### Upgrade notes

- Additive: no existing type, schema or rule changed.
