package ctis

import (
	"crypto/rand"
	"encoding/binary"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Identifiers in a document (spec section "Design principles").
//
// A document carries natural keys (the canonical forms of its assets) and the
// producer's own references, never a receiver's database keys:
//
//   - metadata.id is a producer-generated UUIDv7, the idempotency key of the
//     document. It is the only UUID a document is expected to carry.
//   - id and *_ref members are document-local references. They link items
//     inside one document and mean nothing outside it. They follow
//     DocumentRefPattern and MUST NOT be UUID-shaped, so a receiver's
//     database key cannot be passed off as one.
//   - source_refs[] carry the producer's own identifiers of an item in its
//     own systems ({system, id}).

// Limits of the identifier members.
const (
	MaxDocumentRefLen  = 255
	MaxSourceRefs      = 16
	MaxSourceRefIDLen  = 256
	MaxSourceSystemLen = 64
)

// DocumentRefPattern is the form of a document-local reference: visible
// ASCII starting with a letter or digit, at most 255 characters.
const DocumentRefPattern = `^[A-Za-z0-9][A-Za-z0-9._:/@+=~%-]{0,254}$`

// UUIDShapePattern matches a UUID in its canonical, braced or URN form. A
// document-local reference MUST NOT match it.
const UUIDShapePattern = `^(urn:uuid:|\{)?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?$`

// ReportIDPattern is the form of metadata.id: a lowercase UUID of version 7.
const ReportIDPattern = `^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`

var (
	documentRefRE = regexp.MustCompile(DocumentRefPattern)
	uuidShapeRE   = regexp.MustCompile(UUIDShapePattern)
	reportIDRE    = regexp.MustCompile(ReportIDPattern)
)

// IsDocumentRef reports whether s is a valid document-local reference: it
// follows DocumentRefPattern and is not UUID-shaped.
func IsDocumentRef(s string) bool {
	return documentRefRE.MatchString(s) && !IsUUIDShaped(s)
}

// IsUUIDShaped reports whether s looks like a UUID (canonical, braced or URN
// form).
func IsUUIDShaped(s string) bool { return uuidShapeRE.MatchString(s) }

// IsReportID reports whether s is a valid metadata.id (lowercase UUIDv7).
func IsReportID(s string) bool { return reportIDRE.MatchString(s) }

var (
	uuidMu   sync.Mutex
	uuidLast int64
	uuidSeq  uint16
)

// NewReportID returns a new UUIDv7 (RFC 9562) for metadata.id: 48 bits of
// Unix milliseconds, a 12-bit counter that keeps ids from one process
// monotonic within a millisecond, and 62 random bits.
func NewReportID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("ctis: crypto/rand failed: " + err.Error())
	}
	uuidMu.Lock()
	ms := time.Now().UnixMilli()
	if ms <= uuidLast {
		ms = uuidLast
		uuidSeq++
		if uuidSeq > 0x0fff {
			ms++
			uuidSeq = 0
		}
	} else {
		uuidSeq = binary.BigEndian.Uint16(b[6:8]) & 0x07ff
	}
	uuidLast = ms
	seq := uuidSeq
	uuidMu.Unlock()

	b[0], b[1], b[2], b[3], b[4], b[5] = byte(ms>>40), byte(ms>>32), byte(ms>>24), byte(ms>>16), byte(ms>>8), byte(ms)
	b[6] = 0x70 | byte(seq>>8)
	b[7] = byte(seq)
	b[8] = 0x80 | (b[8] & 0x3f)
	return formatUUID(b)
}

// validateDocumentRef checks one id or *_ref member value; empty is the
// caller's business.
func validateDocumentRef(where, v string, add func(string, ...any)) {
	switch {
	case v == "":
	case len(v) > MaxDocumentRefLen:
		add("%s longer than %d", where, MaxDocumentRefLen)
	case IsUUIDShaped(v):
		add("%s %q is UUID-shaped: document-local references must not carry a database key (use source_refs for the producer's own ids)", where, truncateForError(v))
	case !documentRefRE.MatchString(v):
		add("%s %q is not a document reference (%s)", where, truncateForError(v), DocumentRefPattern)
	}
}

// validateSourceRefs checks a source_refs list.
func validateSourceRefs(where string, refs []SourceRef, add func(string, ...any)) {
	if len(refs) > MaxSourceRefs {
		add("%s has %d entries, at most %d", where, len(refs), MaxSourceRefs)
	}
	for i, r := range refs {
		if i >= MaxSourceRefs {
			break
		}
		if !IsOpenToken(r.System) {
			add("%s[%d].system %q is not a lowercase token", where, i, truncateForError(r.System))
		}
		switch {
		case strings.TrimSpace(r.ID) == "":
			add("%s[%d].id is required", where, i)
		case len(r.ID) > MaxSourceRefIDLen:
			add("%s[%d].id longer than %d", where, i, MaxSourceRefIDLen)
		case hasControlRune(r.ID):
			add("%s[%d].id has a control character", where, i)
		}
	}
}
