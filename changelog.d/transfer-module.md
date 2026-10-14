### Added: feed transfer module

- `github.com/openctemio/ctis/transfer` (own module, tag `transfer/vX.Y.Z`): fetch from ordered origins with retries, resume, blob cache and circuits; `transfer/bundle`: the signed chunked bundle format, writer and consumer.
- Moved unchanged from `github.com/openctemio/sdk-go/pkg/transfer` v0.1.0. A golden test pins every published byte (chunks, signed manifest, signed pointer) to that version, so publishers and consumers can switch in any order.

### Upgrade notes

- Replace the import path `github.com/openctemio/sdk-go/pkg/transfer` with `github.com/openctemio/ctis/transfer`; nothing else changes. The ctis root module still has zero external dependencies.
