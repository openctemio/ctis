# Changelog: the OCSF adapter

Module `github.com/openctemio/ctis/v2/interop/ocsf`, released with tags `v2/interop/ocsf/vX.Y.Z`. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/). An upstream OCSF release changes this adapter only ([docs/interop.md](../../../docs/interop.md)).

## [Unreleased]

## [0.1.0] - 2026-11-03

First release: the OCSF code moved out of the CTIS core module (CTIS 2.0).

- Upstream OCSF 1.3.0: export (Vulnerability Finding and Compliance Finding events).
- One mapping directory per upstream version, run by `interop/engine`; vendored upstream schema under `schemas/` (sha256 in `interop/upstreams.json`); vectors in `conformance/interop/ocsf/`.
- Lossless passthrough under `extensions["org.ctis.interop.ocsf"]` where the format has an importer.
