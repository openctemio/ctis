# Canonical forms and derived keys

This document is normative. It gives, step by step, the algorithms behind [spec.md](spec.md) section 5.2 (canonical asset values), section 5.3 (asset key), section 6.2 (location key) and section 6.3 (vulnerability ids), and the web URL rules that recipe `ctis-fp/2` uses ([fingerprints.md](fingerprints.md)). Every algorithm has vectors under [`conformance/v2`](../conformance/v2) (listed per section); an implementation that follows the steps reproduces them byte for byte. The Go reference names are given for orientation only.

When an algorithm says "refuse", the value has no canonical form: `CanonicalAssetValue` fails, and `Report.Validate` refuses an asset whose value it is (V-CANON-001 in [validation-rules.md](validation-rules.md)). An asset value that is accepted but differs from its canonical form is refused too: the canonical form is the only spelling a document may carry.

## 1. Definitions

- **Trim**: remove the leading and trailing code points that have the Unicode `White_Space` property (TAB, LF, VT, FF, CR, SPACE, U+0085, U+00A0, U+1680, U+2000 to U+200A, U+2028, U+2029, U+202F, U+205F, U+3000). U+001C to U+001F are not white space. (Some standard libraries strip them too: do not use such a function.)
- **Lowercase**: map every code point with its Unicode *simple* lowercase mapping (`UnicodeData.txt`, field 13), one code point to one code point, with no context and no locale. U+0130 becomes U+0069, U+212A (Kelvin sign) becomes `k`, every capital sigma becomes U+03C3 (never the final form). A *full* case mapping (which turns U+0130 into two code points, or picks a final sigma) gives different results and MUST NOT be used.
- **Upper-case** (ASCII): `a`-`z` to `A`-`Z`; used only on values that are ASCII by the time it applies.
- **Unreserved**: the ASCII bytes `A`-`Z`, `a`-`z`, `0`-`9`, `-`, `.`, `_`, `~` (RFC 3986).
- **Normalise escapes**: in a string, every `%` followed by two hexadecimal digits is replaced by the byte it encodes when that byte is unreserved, and otherwise kept with its two digits upper-cased. A `%` not followed by two hexadecimal digits is kept as it is.
- **Control character** (free-form values): U+0000 to U+001F, U+007F, U+0080 to U+009F, U+202E, U+2028, U+2029.
- **Decimal port**: the text of a port is parsed as an optional `+` or `-` sign followed by ASCII digits (leading zeros allowed); the value must be 1 to 65535. Where a URL parser has already split the port off, it holds digits only.

## 2. Asset values (`CanonicalAssetValue`)

`CanonicalAssetValue(type, value)` trims the value and refuses an empty result. It then applies the algorithm of the type:

| Type | Algorithm |
|---|---|
| `domain_name` | 3.1 Domain name |
| `ip_address` | 3.2 IP address |
| `ip_range` | 3.3 IP range |
| `host` | 3.4 Host |
| `service` | 3.5 Service (value form) |
| `web_origin` | 4.1 Web origin |
| `repository` | 5.1 Repository |
| `package` | 5.2 Package URL; the asset value is the identity |
| `container_image` | 5.4 Container image |
| `certificate` | 5.5 Certificate fingerprint |
| `autonomous_system` | 5.6 Autonomous system |
| `cloud_resource`, `cloud_account`, `storage`, `database`, `serverless` | 6.4 Cloud id |
| every other type (`web_application`, `api`, `mobile_app`, `saas_application`, `ai_model`, `container_registry`, `container`, the Kubernetes, device and network types, `identity`, the web3 types, `unclassified`) | free-form: refuse a value that contains a control character; otherwise the trimmed value. Case and inner white space are kept. |

Vectors: `canonical/asset-value.json` (every type of `AllAssetTypes`).

## 3. Names and addresses

### 3.1 Domain name (`CanonicalDomain`)

1. Trim.
2. Replace every U+3002, U+FF0E and U+FF61 with `.`.
3. Remove one trailing `.`. Refuse an empty result.
4. Lowercase the whole name (section 1) and split it at `.` into labels.
5. For each label, in order:
   1. refuse an empty label, and a label that is exactly `*` (a wildcard is a certificate attribute, not an asset);
   2. if the label has a code point above U+007F, replace it with `xn--` followed by the Punycode encoding (RFC 3492) of its code points; refuse a surrogate code point;
   3. refuse a label longer than 63 bytes;
   4. refuse a label with a byte other than `a`-`z`, `0`-`9`, `-` and `_`. The position of `-` is not checked, and an existing `xn--` label is only lowercased.
6. Refuse the name when its last label consists of digits only (it is an IPv4 address in some notation).
7. Join the labels with `.` and refuse a result longer than 253 bytes.

There is no other IDNA processing: no UTS 46 mapping (fullwidth letters, ligatures and `ß` are encoded as they are, after lowercasing), no NFC normalisation (a precomposed and a decomposed letter give different A-labels), no bidi or joiner rules, no check of the Punycode of an `xn--` label. Producers that hold a name in Unicode SHOULD send it NFC-normalised.

Vectors: `canonical/domain.json`.

### 3.2 IP address (`CanonicalIP`)

1. Trim.
2. Parse one of:
   - IPv4: exactly four decimal parts, each 0 to 255, no leading zero in a part (`0` alone is fine), no other notation (no hexadecimal, octal or integer forms, no fewer parts);
   - IPv6 in the text forms of RFC 4291 section 2.2 (hexadecimal groups, `::`, an embedded dotted IPv4 address in the last 32 bits), optionally followed by `%` and a non-empty zone. No brackets, no prefix length.
   Refuse anything else.
3. Drop the zone.
4. An IPv4-mapped IPv6 address (`::ffff:0:0/96`) becomes its IPv4 address.
5. Write IPv4 in dotted decimal without leading zeros. Write IPv6 as RFC 5952 says: lowercase hexadecimal, leading zeros of each group removed, the longest run of two or more zero groups replaced by `::` (the first such run when two are equally long), a single zero group written `0`, and no embedded dotted quad (an IPv4-compatible or NAT64 address is written in hexadecimal groups).

Vectors: `canonical/ip.json`.

### 3.3 IP range (`CanonicalCIDR`)

1. Trim.
2. Parse `<address>/<length>`: the address as in 3.2 step 2 but without a zone, the length decimal without a leading zero, 0 to 32 for IPv4 and 0 to 128 for IPv6. Refuse anything else.
3. When the address is IPv4-mapped and the length is 96 or more, use the IPv4 address and the length minus 96.
4. Set every bit after the length to zero.
5. Write the address as in 3.2 step 5, then `/` and the length.

Vectors: `canonical/cidr.json`.

### 3.4 Host

1. Remove every leading `[` and trailing `]`; if the result is an IP address (3.2), the host is its canonical form, and it is an IPv6 host when that form contains `:`.
2. Otherwise the host is the canonical domain name (3.1) of the value as it was before step 1.

### 3.5 Service

`CanonicalService(host, port, transport)`:

1. The host is canonical (3.4).
2. Refuse a port outside 1 to 65535.
3. Trim the transport and lowercase it; refuse anything but `tcp`, `udp` and `sctp`.
4. The value is `<host>:<port>/<transport>`, the port in decimal without leading zeros and an IPv6 host in brackets.

The asset value form `host:port/transport` is split first: the transport is everything after the first `/` (refuse a value without `/`); in the part before it, the port is the text after the last `:` (refuse when there is no `:` or it is the first character), read as a decimal port (section 1), and the host is the text before that `:`. An IPv6 host SHOULD be bracketed; an unbracketed one still works because the last `:` separates the port.

Vectors: `canonical/service.json`, the `service` entries of `canonical/asset-value.json`.

## 4. Web origins and URLs

URL values are parsed with the generic syntax of RFC 3986 (`scheme ":" "//" authority path ["?" query] ["#" fragment]`). A value is refused when it is not a URI reference: an invalid percent-escape anywhere, an ASCII control character, a space or other character not allowed in the authority, a `%` in a host other than the zone of a bracketed IPv6 address (`%25<zone>`), an unclosed bracket. Characters outside RFC 3986 are tolerated in the path, query and fragment (see 4.2 for how the path is written).

### 4.1 Web origin (`CanonicalOrigin`)

1. Trim and parse. Lowercase the scheme; refuse anything but `http` and `https`.
2. The host is the authority's host without user info, port and brackets, with a zone `%25<zone>` decoded. Make it canonical (3.4); refuse an empty host.
3. The port, when the authority has a non-empty one: digits, value 1 to 65535 (refuse otherwise). Drop it when it is the scheme's default (80 for `http`, 443 for `https`).
4. The origin is `<scheme>://<host>[:<port>]`, an IPv6 host in brackets, the port in decimal without leading zeros. User info, path, query and fragment are dropped.

Vectors: `canonical/origin.json`.

### 4.2 URL in a member (`CanonicalURL`)

Used for URLs inside members, not for asset values.

1. Take the origin as in 4.1.
2. The path is written as follows. Let *raw* be the path as it appears in the value.
   - If every character of *raw* is unreserved, one of `!$&'()*+,;=:@/[]`, or part of a `%XX` escape, the path is *raw*.
   - Otherwise the path is *raw* percent-decoded and encoded again: the unreserved bytes and `$&+,/:;=@` are kept, every other byte (as UTF-8) becomes `%XX` with upper-case digits.
   An empty path is `/`.
3. Normalise escapes (section 1).
4. Remove dot segments: split the path at `/`; walk the segments, dropping `.`, and for `..` removing the last kept segment unless only the leading empty segment is left; when the last segment is `.` or `..`, end with an empty segment (a trailing `/`). Join with `/` and make sure the result starts with `/`. Empty segments (`//`) are kept.
5. The query names: split the raw query at `&`; take each part up to its first `=`; normalise its escapes; drop empty names and repeats; sort the names by their bytes. When there is at least one, append `?` and the names joined with `&`.
6. The URL is the origin, the path and the query names. User info, query values and the fragment are dropped.

Vectors: `canonical/url.json`.

### 4.3 Web URL (`weburl.Parse`)

The URL rules of the web attack surface: recipe `ctis-fp/2` (`dast`: origin and path), endpoint origins and paths, and path templates.

1. Refuse a value longer than 2048 bytes, a value that is not UTF-8, and a value with a code point that is a Unicode control character (general category `Cc`), has the `White_Space` property, or has the `Bidi_Control` property.
2. Parse as in section 4. The scheme, lowercased, must be `http` or `https`; the value must have an authority with a host; refuse user info.
3. The host: remove one trailing `.`; refuse an empty host. If it is an IP address (IPv4 dotted decimal without leading zeros, or IPv6 without a zone), write it as in 3.2 step 4 and 5. Otherwise refuse a host containing `:`, `%`, `[` or `]`; lowercase it; for each label, encode a non-ASCII label as `xn--` + Punycode, then refuse a label that is empty, longer than 63 bytes, starts or ends with `-`, or has a byte other than `a`-`z`, `0`-`9`, `-`, `_`. Refuse a host whose last label is digits only or starts with `0x`, and a host longer than 253 bytes.
4. The port: refuse a port that is not 1 to 65535 or starts with `0`; drop the default port.
5. The path: write it as in 4.2 step 2, then refuse it when it is longer than 2048 bytes. Split it at `/`; in each segment remove every `;jsessionid=` parameter (matched case-insensitively, up to the next `;` or the end of the segment), then normalise its escapes, refusing a malformed escape and an escape of a byte below 0x20 or of 0x7F. Drop empty and `.` segments; `..` removes the last kept segment. The path is `/` followed by the kept segments joined with `/` (no trailing slash, `/` for the root).
6. The parameter names: split the raw query at `&`; take each part up to its first `=`; decode it as a query component (`+` is a space, `%XX` the byte), keeping the raw text when it does not decode; trim it; drop it when it is empty, longer than 128 bytes, not UTF-8, contains a `Cc` code point, or repeats. Sort by bytes and keep the first 100.
7. The origin is `<scheme>://<host>[:<port>]` (IPv6 in brackets). Refuse when origin plus path is longer than 2048 bytes. The fragment and the query values are never kept.

The **path template** replaces each segment of the path, matched after percent-decoding (the segment as written when it does not decode), by the first rule that matches, else keeps it:

| Variable | Segment |
|---|---|
| `{int}` | `^[0-9]+$` |
| `{uuid}` | `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$` |
| `{date}` | `^[0-9]{4}-[0-9]{2}-[0-9]{2}$` |
| `{email}` | `^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}$` |
| `{hex}` | `^[0-9a-fA-F]{16,}$` |
| `{token}` | `^[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}$` and at least 20 bytes; or `^[A-Za-z0-9_-]{20,}$` with an upper-case letter, a lower-case letter and a digit |
| `{id}` | `^[A-Za-z0-9]{12,}$` with at least one letter and one digit |

Vectors: `weburl/urls.json`.

## 5. Software and artifacts

### 5.1 Repository (`CanonicalRepository`)

1. Trim.
2. If the value contains `://` after its first character, remove everything up to and including it. Otherwise, if it contains `@`, the text from the first `@` on contains `:`, and the text before the first `@` contains no `/` (scp-like `user@host:owner/name`), replace it with the text between `@` and the next `:`, then `/`, then the rest.
3. If the last `@` comes before the first `/` (or there is no `/`), remove everything up to and including that `@`.
4. Remove every trailing `/`, then one trailing `.git`.
5. Split at the first `/` into host and path; refuse when there is no `/` or the path is empty.
6. Remove a `:port` from the host and make it a canonical domain name (3.1; an IP address is refused).
7. Refuse a path containing `//`, a control character (section 1), a space, `?` or `#`.
8. Lowercase the path when the host is `github.com`, `gitlab.com`, `bitbucket.org` or `codeberg.org`; keep it otherwise.
9. The value is `<host>/<path>`.

Vectors: `canonical/repository.json`.

### 5.2 Package URL (`CanonicalPurl`)

1. Trim. Refuse a value that does not start with `pkg:` (lower case).
2. Remove `pkg:` and every following `/`.
3. Cut the rest at the first `#`, then at the first `?` (subpath and qualifiers are not identity).
4. If the rest contains `@` and no `/` follows the last `@`, the version is the text after it, percent-decoded (refuse an invalid escape; `+` stays `+`), and the rest ends before it.
5. Remove leading and trailing `/` and split at `/`. Refuse fewer than two parts.
6. The type is the first part, lowercased; refuse an empty type or one with a byte other than `a`-`z`, `0`-`9`, `.`, `+`, `-`.
7. For each other part, in order: skip an empty part; percent-decode it (refuse an invalid escape); lowercase it when the type is `bitbucket`, `github`, `npm`, `pypi`, `composer` or `hex`; for `pypi`, in the last part replace every `_` with `-`; percent-encode every byte that is not unreserved as `%XX` (upper-case digits). Refuse when no part is left.
8. The identity is `pkg:<type>/<parts joined with />`; the version is separate.

Vectors: `canonical/purl.json`.

### 5.3 CPE (`CanonicalCPE`)

1. Trim and lowercase the whole string.
2. A CPE 2.2 URI (`cpe:/...`): refuse it when the part after `cpe:/` contains `%` or `~`; split that part at `:`; refuse more than 7 components; append `*` until there are 11; replace empty components with `*`; the string becomes `cpe:2.3:` followed by the components joined with `:`.
3. Split at every `:` that is not escaped (a `\` escapes the character after it). Refuse unless there are 13 parts, the first is `cpe` and the second `2.3`.
4. Refuse a third part other than `a`, `o`, `h` or `*`.
5. Replace empty parts with `*` and join with `:`.

Vectors: `canonical/cpe.json`.

### 5.4 Container image (`CanonicalImage`)

1. Trim.
2. If the value contains `@`, the digest is the text after the first `@`, lowercased; refuse it unless it is `sha256:` followed by 64 hexadecimal digits. The reference is the text before the `@`.
3. If the reference contains `/` and its first component contains `.` or `:` or is `localhost`, that component, lowercased, is the registry and the rest is the repository. Otherwise the registry is `docker.io` and the repository is the whole reference.
4. `index.docker.io` and `registry-1.docker.io` are `docker.io`.
5. Remove a tag: the text from the last `:` when that `:` comes after the last `/`.
6. Refuse a repository that is empty, has a byte other than `a`-`z`, `0`-`9`, `.`, `_`, `-`, `/` (upper case is refused, not lowercased), starts or ends with `/`, or contains `//`.
7. On `docker.io`, a repository without `/` gets `library/` in front.
8. The value is `<registry>/<repository>`, followed by `@<digest>` when there is one. Without a digest the value names the repository, not one image.

Vectors: `canonical/image.json`.

### 5.5 Certificate fingerprint (`CanonicalCertificateFingerprint`)

Trim, remove every `:` and space, lowercase; refuse unless the result is 64 hexadecimal digits (the SHA-256 of the DER).

Vectors: `canonical/certificate.json`.

### 5.6 Autonomous system

Remove a leading `AS`, then a leading `as`. Refuse unless the rest is 1 to 10 ASCII digits without a leading zero (`0` alone is fine) and at most 4294967295. The value is `AS` followed by the number in decimal.

## 6. Cloud resources

### 6.1 ARN (`CanonicalARN`)

1. Trim and split at `:` into at most six parts (the sixth keeps any further `:`).
2. Refuse unless there are six parts, the first is `arn` in any case, and the partition, service and resource parts are not empty.
3. Lowercase the first four parts (`arn`, partition, service, region). The account and resource keep their case.

### 6.2 Azure resource id (`CanonicalAzureResourceID`)

Trim, lowercase, remove every trailing `/`. Refuse unless the result starts with `/subscriptions/` or `/providers/`, and refuse one that contains `//`.

### 6.3 GCP full resource name (`CanonicalGCPResourceName`)

1. Trim. Refuse unless the value starts with `//` and has a `/` after the host.
2. Lowercase the host; refuse it unless it ends in `.googleapis.com` and has a service name before that.
3. Remove every trailing `/` from the path; refuse an empty path or one containing `//`.
4. The value is `//<host>/<path>`; the path keeps its case.

### 6.4 Cloud id (the cloud asset types)

A value whose lowercase form starts with `arn:` follows 6.1; one that starts with `//` follows 6.3; one that starts with `/` follows 6.2. Any other provider id is free-form (refuse a control character; keep the trimmed value).

Vectors: `canonical/cloud.json`, the cloud entries of `canonical/asset-value.json`.

## 7. Asset key (`AssetKey`)

The asset key is the UUID version 5 (RFC 9562) in the namespace `9678743b-b91d-59fa-b168-ed192fe9eed3` (itself `uuidv5(NAMESPACE_URL, "urn:ctis:asset-key")`) of the UTF-8 bytes of `<type>` + U+001F + `<canonical value>`, written in lowercase with hyphens. The value must already be canonical: the key function does not canonicalise.

Vectors: `canonical/asset-key.json`.

## 8. Vulnerability ids

### 8.1 One raw id (`NormalizeVulnerabilityID`)

1. Trim. The id is not an id when it is empty, longer than 128 bytes, or does not match `^[A-Za-z0-9][A-Za-z0-9._:/+\-]*$`.
2. If its ASCII upper-case form starts with `CVE-`: it is a `cve` when that upper-case form matches `^CVE-\d{4}-\d{4,}$` (the id is the upper-case form), else it is not an id.
3. If its upper-case form starts with `GHSA-`: the id is `GHSA-` followed by the rest in lower case; it is a `ghsa` when that matches `^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`, else it is not an id.
4. If its upper-case form starts with one of `PYSEC-`, `GO-`, `RUSTSEC-`, `OSV-`, `GSD-`, `MAL-`, `HSEC-`, `BIT-` (in that order) and is longer than that prefix, it is an `osv` id: the upper-case prefix followed by the rest as written.
5. Otherwise it is a `vendor` id, as written (trimmed).

Vectors: `vulnerability-id.json`.

### 8.2 Declared ids and the preferred id (`PreferredVulnerabilityID`)

The ids of `vulnerability.ids[]` are read in order. Each entry's `id` is normalised (8.1); the entry is skipped when it is not an id, when its declared `type` is not one of `cve`, `ghsa`, `osv`, `vendor`, or when it declares `cve` or `ghsa` and 8.1 found another type. Otherwise the entry keeps its declared type with the normalised id (an OSV-looking id declared `vendor` stays `vendor`). Entries with the same type and id after this count once; at most the first 64 kept entries count.

The preferred id is the smallest `cve` (compare the year as a number, then the sequence as a number ignoring leading zeros, then the text), else the first `ghsa`, else the first `osv`, else the first `vendor`; none when no entry is kept.

Vectors: `preferred-id.json`.

## 9. Location key (`LocationKey`)

The first rule that applies gives the key; none gives the empty string.

1. **Package.** `vulnerability.purl`, trimmed, starts with `pkg:` in any case: remove those four characters and every following `/`; cut at the first `?` or `#`, then at the last `@`; split at the first `/` into type and rest. When both are non-empty, the key is `pkg:` + the type lowercased + `/` + the rest without leading and trailing `/`. Escapes and the case of the rest are kept as written (this is not 5.2).
2. **Web URL.** `web.url`, then `location.path`: the value, trimmed, starts with `http://` or `https://` in any case and parses (section 4) with a non-empty host. The key is `url:` + the scheme lowercased + `://` + the host lowercased (brackets removed, no IDNA encoding, an IPv6 host bracketed again) + `:<port>` when the port is present and not the scheme's default (as written) + the path written as in 4.2 step 2 (`/` when empty). There is no escape normalisation and no dot-segment removal; user info, query and fragment are dropped.
3. **File.** `location.path` that is not blank: trim; remove a leading `file:` in any case and the `/` after it; replace every `\` with `/`; resolve it as an absolute POSIX path (`/` + the path, `.` and empty segments dropped, `..` removes the previous segment and is dropped at the root); remove the leading `/`. The key is `file:` + the result (case kept).
4. **Network.** `network` is present: `net:host` when `port` is 0 or absent, else `net:<port>/<transport>` with the transport trimmed and lowercased, `tcp` when empty.
5. **Resource.** `misconfiguration` with a non-empty `resource_type` or `resource_name`: `resource:` + the type trimmed + `/` + the name trimmed.

A key longer than 512 bytes is cut to its first 479 bytes (fewer, so the cut falls on a UTF-8 character boundary), followed by `#` and the first 32 hexadecimal digits (lowercase) of the SHA-256 of the whole key.

Vectors: `location-key.json`, and the `location_key` of every case in `correlation/correlation.json`.
