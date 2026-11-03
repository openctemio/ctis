# Changelog: the SARIF adapter

Module `github.com/openctemio/ctis/v2/interop/sarif`, released with tags `v2/interop/sarif/vX.Y.Z`. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/). An upstream SARIF release changes this adapter only ([docs/interop.md](../../../docs/interop.md)).

## [Unreleased]

## [0.1.0] (draft)

First release: the SARIF code moved out of the CTIS core module (CTIS 2.0).

- Upstream SARIF 2.1.0: import and export; the rule catalog (rules[] and rule_ref).
- One mapping directory per upstream version, run by `interop/engine`; vendored upstream schema under `schemas/` (sha256 in `interop/upstreams.json`); vectors in `conformance/interop/sarif/`.
- Lossless passthrough under `extensions["org.ctis.interop.sarif"]` where the format has an importer.
