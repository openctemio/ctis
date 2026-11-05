# nmap XML mapping

Generated from `importer/spec_nmap.go`; do not edit. Regenerate with `go test ./importer -run TestMappingDocs -update`.

- Format: `nmap`
- Source versions: nmap 7.x -oX (xmloutputversion 1.05); the same document from nmap-compatible scanners (masscan -oX)
- Fields: 26 mapped, 60 ignored on purpose (30% mapped)

## Rules

- An inventory format: hosts, names and services, never findings. Matching service versions to vulnerabilities is the receiver's job (it reads the CPE and the product version).
- Every host whose status is up is an ip_address asset (its first IPv4 or IPv6 address); a host that is down, or has no address, is counted as skipped.
- A name of type user (the name the person asked nmap to scan) is a domain_name asset that resolves_to the address. A PTR name is the address owner's choice, often a provider's, so it stays the property ptr_names (at most 8) and is never an asset.
- Every open port is a service asset host:port/transport exposed by the address, with nmap's service name (http over an ssl tunnel is https), product, version, extra info, the first application CPE (made CPE 2.3), TLS when the tunnel is ssl, and a technology entry whose confidence is nmap's 0-10 conf times 10. Closed, filtered and open|filtered ports are not kept.
- The best OS match (highest accuracy) is an operating-system technology of the address.
- NSE script output is free text a script author chose, often holding banners and keys: it is not read. The command line (args) is not kept: it can hold script arguments with credentials.
- Every host-bearing asset carries extensions[io.openctem].import_scope relative to Options.ScopeDomains (unknown for an address); the receiver judges scope.

## Fields

| Source field | CTIS | Ignored because |
|---|---|---|
| `/nmaprun` | (container) |  |
| `/nmaprun/@scanner` | `tool.name (unless Options.ToolName)` |  |
| `/nmaprun/@version` | `tool.version` |  |
| `/nmaprun/@args` |  | the command line can hold script arguments with credentials |
| `/nmaprun/@start` |  | run start; each host has its own times |
| `/nmaprun/@startstr` |  | run start as text |
| `/nmaprun/@xmloutputversion` |  | output format version |
| `/nmaprun/scaninfo/**` |  | scan type and port list |
| `/nmaprun/scaninfo` |  | scan type and port list |
| `/nmaprun/verbose/**` |  | verbosity |
| `/nmaprun/verbose` |  | verbosity |
| `/nmaprun/debugging/**` |  | debug level |
| `/nmaprun/debugging` |  | debug level |
| `/nmaprun/hosthint` |  | a host announced before its scan finished; the host element follows |
| `/nmaprun/hosthint/**` |  | a host announced before its scan finished; the host element follows |
| `/nmaprun/runstats` |  | run statistics |
| `/nmaprun/runstats/**` |  | run statistics |
| `/nmaprun/taskbegin/**` |  | progress |
| `/nmaprun/taskend/**` |  | progress |
| `/nmaprun/taskprogress/**` |  | progress |
| `/nmaprun/output/**` |  | interactive output text |
| `/nmaprun/prescript/**` |  | NSE output (free text) |
| `/nmaprun/postscript/**` |  | NSE output (free text) |
| `/nmaprun/target/**` |  | targets nmap could not resolve |
| `/nmaprun/host` | `assets[] (ip_address)` |  |
| `/nmaprun/host/@starttime` | `assets[].first_seen_at` |  |
| `/nmaprun/host/@endtime` | `assets[].last_seen_at` |  |
| `/nmaprun/host/status` | (container) |  |
| `/nmaprun/host/status/@state` | `hosts that are not up are skipped` |  |
| `/nmaprun/host/status/@reason` |  | why nmap thinks the host is up |
| `/nmaprun/host/status/@reason_ttl` |  | TTL of that reply |
| `/nmaprun/host/address` | (container) |  |
| `/nmaprun/host/address/@addr` | `assets[].value (ipv4, ipv6), identifiers.mac_addresses (mac)` |  |
| `/nmaprun/host/address/@addrtype` | `which of the two` |  |
| `/nmaprun/host/address/@vendor` | `assets[].properties.mac_vendor` |  |
| `/nmaprun/host/hostnames` | (container) |  |
| `/nmaprun/host/hostnames/hostname` | (container) |  |
| `/nmaprun/host/hostnames/hostname/@name` | `assets[] (domain_name) resolves_to the address (type user); properties.ptr_names (type PTR)` |  |
| `/nmaprun/host/hostnames/hostname/@type` | `which of the two` |  |
| `/nmaprun/host/ports` | (container) |  |
| `/nmaprun/host/ports/extraports` |  | counts of closed or filtered ports |
| `/nmaprun/host/ports/extraports/**` |  | counts of closed or filtered ports |
| `/nmaprun/host/ports/port` | `assets[] (service) exposed by the address, open ports only` |  |
| `/nmaprun/host/ports/port/@protocol` | `service transport` |  |
| `/nmaprun/host/ports/port/@portid` | `service port` |  |
| `/nmaprun/host/ports/port/state` | (container) |  |
| `/nmaprun/host/ports/port/state/@state` | `technical.service.state (open only)` |  |
| `/nmaprun/host/ports/port/state/@reason` |  | why nmap thinks the port is open |
| `/nmaprun/host/ports/port/state/@reason_ttl` |  | TTL of that reply |
| `/nmaprun/host/ports/port/service` | (container) |  |
| `/nmaprun/host/ports/port/service/@name` | `technical.service.app_protocol` |  |
| `/nmaprun/host/ports/port/service/@product` | `technical.service.product, technologies[].name` |  |
| `/nmaprun/host/ports/port/service/@version` | `technical.service.version, technologies[].version` |  |
| `/nmaprun/host/ports/port/service/@extrainfo` | `technical.service.extra_info` |  |
| `/nmaprun/host/ports/port/service/@tunnel` | `technical.service.is_tls (ssl)` |  |
| `/nmaprun/host/ports/port/service/@method` | `technical.service.details.detection_method` |  |
| `/nmaprun/host/ports/port/service/@conf` | `technologies[].confidence (times 10)` |  |
| `/nmaprun/host/ports/port/service/@ostype` |  | the OS the service banner names; the host OS match is kept |
| `/nmaprun/host/ports/port/service/@hostname` |  | a name the banner announced: the server's claim, not a resolution |
| `/nmaprun/host/ports/port/service/@devicetype` |  | device class guess |
| `/nmaprun/host/ports/port/service/@servicefp` |  | an unmatched service fingerprint |
| `/nmaprun/host/ports/port/service/@rpcnum` |  | RPC program number |
| `/nmaprun/host/ports/port/service/@lowver` |  | RPC version range |
| `/nmaprun/host/ports/port/service/@highver` |  | RPC version range |
| `/nmaprun/host/ports/port/service/@proto` |  | rpc when an RPC service |
| `/nmaprun/host/ports/port/service/cpe` | `technical.service.cpe, technologies[].cpe (the first application CPE)` |  |
| `/nmaprun/host/ports/port/script` |  | NSE output (free text chosen by the script) |
| `/nmaprun/host/ports/port/script/**` |  | NSE output (free text chosen by the script) |
| `/nmaprun/host/ports/port/owner/**` |  | ident owner of the port |
| `/nmaprun/host/os` | (container) |  |
| `/nmaprun/host/os/osmatch` | `technologies[] (operating-system, the best match)` |  |
| `/nmaprun/host/os/osmatch/@name` | `technologies[].name` |  |
| `/nmaprun/host/os/osmatch/@accuracy` | `technologies[].confidence` |  |
| `/nmaprun/host/os/osmatch/@line` |  | line in nmap's fingerprint database |
| `/nmaprun/host/os/osmatch/osclass` |  | the class of the match; the match name is kept |
| `/nmaprun/host/os/osmatch/osclass/**` |  | the class of the match; the match name is kept |
| `/nmaprun/host/os/portused` |  | ports the OS detection used |
| `/nmaprun/host/os/portused/**` |  | ports the OS detection used |
| `/nmaprun/host/os/osfingerprint/**` |  | the raw OS fingerprint |
| `/nmaprun/host/hostscript/**` |  | NSE output (free text chosen by the script) |
| `/nmaprun/host/uptime` |  | uptime guess |
| `/nmaprun/host/uptime/**` |  | uptime guess |
| `/nmaprun/host/distance` |  | network distance |
| `/nmaprun/host/distance/**` |  | network distance |
| `/nmaprun/host/tcpsequence` |  | TCP sequence analysis |
| `/nmaprun/host/tcpsequence/**` |  | TCP sequence analysis |
| `/nmaprun/host/ipidsequence` |  | IP ID analysis |
| `/nmaprun/host/ipidsequence/**` |  | IP ID analysis |
| `/nmaprun/host/tcptssequence` |  | TCP timestamp analysis |
| `/nmaprun/host/tcptssequence/**` |  | TCP timestamp analysis |
| `/nmaprun/host/trace` |  | route to the host: the hops are other parties' routers |
| `/nmaprun/host/trace/**` |  | route to the host: the hops are other parties' routers |
| `/nmaprun/host/times` |  | round-trip timing |
| `/nmaprun/host/times/**` |  | round-trip timing |
| `/nmaprun/host/smurf/**` |  | smurf responses |
