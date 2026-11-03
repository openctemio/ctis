# Changelog: the CSAF adapter

Module `github.com/openctemio/ctis/v2/interop/csaf`, released with tags `interop/csaf/vX.Y.Z`. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/). An upstream CSAF release changes this adapter only ([docs/interop.md](../../docs/interop.md)).

## [Unreleased]

## [0.1.0] (draft)

First release: the CSAF code moved out of the CTIS core module (CTIS 2.0).

- Upstream CSAF 2.0: import (VEX and security advisory profiles).
- One mapping directory per upstream version, run by `interop/engine`; vendored upstream schema under `schemas/` (sha256 in `interop/upstreams.json`); vectors in `conformance/interop/csaf/`.
- Lossless passthrough under `extensions["org.ctis.interop.csaf"]` where the format has an importer.
