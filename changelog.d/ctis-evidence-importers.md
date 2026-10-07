### Added: typed evidence from nuclei, SARIF and ZAP

- Builders in the root package that cap items and mark sensitive values, never masking them:
  - `HTTPExchangeFromRaw(request, response, baseURL)` for raw HTTP/1.x or HTTP/2 text;
  - `HTTPExchangeFromHAR(entry)` for a HAR 1.2 entry;
  - `CurlEvidence(command)`;
  - `MarkSensitive(items...)`;
  - `FitEvidenceItem(item)`;
  - `IsSensitiveHeader(name)` and `IsSensitiveParam(name)`.
- nuclei:
  - `request` and `response` become one `http_exchange` item, with `extracted-results` (located in the response body when found there) and the matcher name;
  - `curl-command` becomes a `curl` item;
  - `timestamp` becomes `captured_at`.
- SARIF: `webRequest` and `webResponse` become an `http_exchange` item (new `SARIFWebRequest`, `SARIFWebResponse` and `SARIFContent` types).
- ZAP: the HTTP message of the first 3 instances of each finding becomes `http_exchange` items, with the instance evidence located in the response body.
- `FuzzHTTPExchangeFromRaw` runs in the CI fuzz loop.

### Security

- Producers mark sensitive values and never mask them; receivers mask them before display or forwarding (spec 4.8). The values marked are:
  - Authorization, Proxy-Authorization, Cookie, Set-Cookie and X-Api-Key headers;
  - headers named like a token, secret, session or auth;
  - query, form and JSON members named like a credential;
  - extracted values that look like credentials;
  - every repetition of these values in the other evidence items of the finding.
- Every item is capped:
  - bodies 64 KiB, headers 100 of 8 KiB and 32 KiB per message, extracted 20 of 1 KiB;
  - the item itself 256 KiB, after JSON escaping;
  - control characters are removed from headers, URLs and reasons;
  - a binary body is kept as base64.
- Tests check that no credential appears outside marked spans or outside evidence items, in the goldens and under hostile input.
