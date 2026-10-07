### Added: weburl, one library to parse, normalise and template web URLs

- New package `weburl`. The sensor, the SDK and the platform use it to turn a web URL into the same endpoint identity.
- `Parse` is strict and returns the normalised URL. It refuses:
  - any scheme other than `http` and `https`;
  - user info;
  - a URL over 2,048 bytes;
  - invalid UTF-8;
  - control, white-space and bidi characters, including percent-encoded control characters;
  - a malformed escape;
  - an invalid port;
  - an ambiguous numeric host (`2130706433`, `0x7f.0.0.1`).
- `Parse` normalises:
  - the origin: lowercase scheme and ASCII host, internationalized labels in Punycode, no trailing dot, IPv6 in canonical form, default port dropped;
  - the path: unreserved escapes decoded and the others upper-cased, dot segments resolved, empty segments collapsed, no trailing slash, `;jsessionid=` removed. Case is kept;
  - the query: reduced to its sorted parameter names, at most 100, each at most 128 bytes.
- `Template` / `TemplatePath` replace identifier segments with typed variables:
  - `{int}`, `{uuid}`, `{date}`, `{email}`, `{hex}`;
  - `{token}`: JWT-like, or a mixed-case base64url value of 20 characters or more;
  - `{id}`: 12 or more letters and digits.

  The rules are deterministic and use RE2 only.
- `RedactURL` removes the user info, every query value and the fragment, and never fails.
- `PathHash(method, template)` is the dedup key of an endpoint. `NormalizeMethod` checks the closed method set (`ANY` when unknown).
- A 223-URL golden corpus, including hostile inputs, and the `FuzzWebURL` fuzz target, which runs in CI.

### Security

- A query value never leaves `Parse` or `RedactURL`. Only parameter names are kept, so tokens, keys and passwords in URLs cannot reach a report, a log or a database through this library.
- Hosts are matched in one ASCII form, so a look-alike Unicode spelling cannot become a second origin. Full UTS #46 mapping is not applied: only lowercasing and Punycode.
