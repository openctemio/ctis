### Fixed: Nessus host-level results carry their host

- Every Nessus finding now has `network.host`, `network.port` and `network.protocol`. A host-level result (port 0, Nessus pseudo-service `general`) used to have no network location, so a receiver keyed it by its title instead of by host and plugin; it is now keyed like any other network result. A port outside 1-65535 is reported as host-level.

### Security

- Credential redaction in plugin output and compliance values also replaces an account label inside a line (`...; user: svc-scan`), not only at the start of a line.
