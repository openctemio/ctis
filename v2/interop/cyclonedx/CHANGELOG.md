# Changelog: the CycloneDX adapter

Module `github.com/openctemio/ctis/v2/interop/cyclonedx`, released with tags `v2/interop/cyclonedx/vX.Y.Z`. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/). An upstream CycloneDX release changes this adapter only ([docs/interop.md](../../../docs/interop.md)).

## [Unreleased]

## [0.1.1] - 2026-11-03

### Changed: CTIS 2.1

- Requires core `github.com/openctemio/ctis/v2` v2.1.0; imported documents declare CTIS 2.1. No mapping change.

## [0.1.0] - 2026-11-03

First release: the CycloneDX code moved out of the CTIS core module (CTIS 2.0).

- Upstream CycloneDX 1.5 (with 1.2-1.4) and 1.6 (with later 1.x): import, and export as 1.6.
- One mapping directory per upstream version, run by `interop/engine`; vendored upstream schema under `schemas/` (sha256 in `interop/upstreams.json`); vectors in `conformance/interop/cyclonedx/`.
- Lossless passthrough under `extensions["org.ctis.interop.cyclonedx"]` where the format has an importer.
