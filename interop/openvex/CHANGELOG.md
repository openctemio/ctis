# Changelog: the OpenVEX adapter

Module `github.com/openctemio/ctis/v2/interop/openvex`, released with tags `interop/openvex/vX.Y.Z`. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/). An upstream OpenVEX release changes this adapter only ([docs/interop.md](../../docs/interop.md)).

## [Unreleased]

## [0.1.0] (draft)

First release: the OpenVEX code moved out of the CTIS core module (CTIS 2.0).

- Upstream OpenVEX 0.2.0 (with 0.0.1): import.
- One mapping directory per upstream version, run by `interop/engine`; vendored upstream schema under `schemas/` (sha256 in `interop/upstreams.json`); vectors in `conformance/interop/openvex/`.
- Lossless passthrough under `extensions["org.ctis.interop.openvex"]` where the format has an importer.
