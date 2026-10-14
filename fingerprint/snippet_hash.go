package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// PartialSnippetHash is the partial_fingerprints key that carries
// SnippetHash of a SAST finding's source lines when the report does not
// carry the lines themselves. A producer that has the scanned tree (a CI
// job, a sensor) sends the hash instead of the code: the receiver keys the
// finding on the code it flags without receiving that code.
const PartialSnippetHash = "snippetHash/v1"

// MaxSnippetHashLines is how many lines of a match SnippetHash input should
// hold at most. Scanners cut long matches (Semgrep and Opengrep keep the
// first lines of a match), so a producer that reads the lines from the file
// cuts at the same place and both agree.
const MaxSnippetHashLines = 10

// snippetSpace is a run of ASCII whitespace (RE2 \s).
var snippetSpace = regexp.MustCompile(`\s+`)

// SnippetHash is the hash of the code a SAST finding flags, independent of
// the line it is on and of indentation: CRLF becomes LF, each line is trimmed
// and every run of whitespace inside it becomes one space, empty lines are
// dropped, and the rest is joined with LF. The result is the first 16 bytes
// of its SHA-256 in lowercase hex (32 characters), or "" when no code is
// left. Moving the code changes nothing; editing it changes the hash.
//
// The receiver computes the same value from finding.location.snippet, so a
// producer that sends the snippet and one that sends only this hash (as
// PartialSnippetHash) key the same finding the same way.
func SnippetHash(snippet string) string {
	lines := strings.Split(strings.ReplaceAll(snippet, "\r\n", "\n"), "\n")
	kept := make([]string, 0, len(lines))
	for _, l := range lines {
		if t := strings.TrimSpace(l); t != "" {
			kept = append(kept, snippetSpace.ReplaceAllString(t, " "))
		}
	}
	if len(kept) == 0 {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.Join(kept, "\n")))
	return hex.EncodeToString(sum[:16])
}
