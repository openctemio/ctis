### Added: passive registration and network ownership lookups in the capability taxonomy

- New `lookup.rdap@1` (discover.passive, T0, routed): in `root_domain`, out `root_domain`. Registrar, registrant organization, name servers and registration dates of a root domain from the RDAP service of its registry, reported on the domain (`technical.domain`, required `technical.domain.whois`). Param `follow_registrar`.
- New `lookup.asn@1` (discover.passive, T0, routed): in `ip`, `cidr`; out `ip`, `cidr`. Origin autonomous system, holder and announced range of an address or network from public routing data (required `technical.ip_address.asn` on addresses, `properties.asn` on networks). Params `include_announced`, `max_ranges`.
- `intel.passive@1` (planned) no longer names RDAP and ASN data in its description.
- `docs/capabilities.md` is regenerated.

### Upgrade notes

- Additive: no existing capability, param or rule changed.
