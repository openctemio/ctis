# Bindings

This directory is reserved for CTIS implementations in languages other than Go, one directory per language (`bindings/python/`, `bindings/rust/`, ...). None exists yet. The Go reference implementation stays at the repository root (`github.com/openctemio/ctis/v2`); `schemas/`, `conformance/` and `docs/` are language-neutral and shared by every binding.

A binding provides:

1. **Types generated from [`schemas/v2`](../schemas/v2)** with the language's JSON Schema tooling, committed with the generator version, and checked against the schema (strict members, closed enums, tri-state booleans). The schemas are the source of truth; a binding never edits generated types by hand to differ from them.
2. **The core behaviour**: decoding (strict and version-gated), validation beyond the schema, canonical forms and asset keys, vulnerability ids, location keys, web URLs, fingerprints, the secret digest and the correlation key, as specified in [`docs/`](../docs) (start with [docs/porting.md](../docs/porting.md)).
3. **A conformance protocol server**: a program that answers the requests of [conformance/PROTOCOL.md](../conformance/PROTOCOL.md) on standard input and output.
4. **A CI job that runs the harness** against that server and passes for every required operation:

   ```sh
   python3 scripts/conformance_harness.py -- <command that starts the binding's server>
   ```

Optional parts (the declarative mapping language, the interop engine and adapters, tool importers) may follow; the harness skips the optional operations a binding does not list in `info`.

A binding has its own package version and changelog, and states which CTIS specification version (`2.0`) and which conformance vectors (the CTIS release whose `conformance/` it runs) it implements.
