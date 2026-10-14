### Added: a line-independent SAST snippet hash a producer can send instead of the code

- `fingerprint.SnippetHash` hashes the code a SAST finding flags, independent of its line and indentation, and `fingerprint.PartialSnippetHash` (`snippetHash/v1`) is the `partial_fingerprints` key that carries it. A producer that has the scanned tree but no snippet from its scanner sends the hash, not the code; the receiver keys the finding on the flagged code, so a finding marked a false positive stays one when code above it moves.
- `fingerprint.MaxSnippetHashLines` (10) is where a producer reading the lines from the file cuts a long match, the same place the scanners cut it.

### Upgrade notes

- Additive: new functions and constants; nothing existing changed.
