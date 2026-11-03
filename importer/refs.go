package importer

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/ctis/v2"
)

// Helpers for the CTIS 2.0 members the importers fill: document references,
// raw-text evidence, threat signals, web URLs.

// docRef builds a document-local reference "<prefix>-<s>" (ctis.IsDocumentRef:
// never UUID-shaped, at most 255 characters of the reference alphabet). When
// s does not fit the alphabet or the length, the reference is the prefix and
// a hash of s, so it is stable and still unique per s.
func docRef(prefix, s string) string {
	ref := prefix + "-" + s
	if ctis.IsDocumentRef(ref) && !strings.HasSuffix(ref, "-") {
		return ref
	}
	h := sha256.Sum256([]byte(s))
	return prefix + "-h" + hex.EncodeToString(h[:12])
}

// refOr returns s when it already is a document reference, else a reference
// derived from it (docRef with the prefix).
func refOr(prefix, s string) string {
	if ctis.IsDocumentRef(s) {
		return s
	}
	return docRef(prefix, s)
}

// webURL returns s when it is an http or https URL, else "".
func webURL(s string) string {
	s = strings.TrimSpace(s)
	if ctis.IsWebURL(s) {
		return s
	}
	return ""
}

// addWebRefs appends the http(s) URLs among refs (bounded, distinct).
func addWebRefs(dst []string, refs ...string) []string {
	for _, r := range refs {
		if u := webURL(r); u != "" {
			dst = addRefs(dst, u)
		}
	}
	return dst
}

// rawTextEvidence adds source text as a raw_text evidence item. The text is
// bounded; an empty text adds nothing. Callers pass text that holds no
// credential (ctis.RedactSecretFinding masks what the builder sees).
func rawTextEvidence(f *ctis.Finding, label, body, protocol string) {
	body = text(body, capEvidence)
	if body == "" || len(f.EvidenceItems) >= ctis.MaxEvidenceItems {
		return
	}
	if len(body) > ctis.MaxEvidenceTextBytes {
		cut := ctis.MaxEvidenceTextBytes - len(truncMarker)
		for cut > 0 && !utf8.RuneStart(body[cut]) {
			cut--
		}
		body = body[:cut] + truncMarker
	}
	f.EvidenceItems = append(f.EvidenceItems, ctis.EvidenceItem{
		Kind: ctis.EvidenceKindRawText, Version: 1, Label: line(label, ctis.MaxEvidenceLabelLen),
		Text: body, Protocol: protocol,
	})
}

// addSignal records a threat assertion of source on v.
func addSignal(v *ctis.VulnerabilityDetails, typ ctis.ThreatSignalType, source string, asOf *time.Time) {
	for _, s := range v.ThreatSignals {
		if s.Type == typ && s.Source == source {
			return
		}
	}
	if len(v.ThreatSignals) >= ctis.MaxThreatSignals {
		return
	}
	v.ThreatSignals = append(v.ThreatSignals, ctis.ThreatSignal{Type: typ, Source: source, AsOf: asOf})
}

// ianaName returns s lowercased when it is an IANA service name, else "".
func ianaName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > 15 {
		return ""
	}
	for i, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || (r == '-' && i > 0 && i < len(s)-1)
		if !ok {
			return ""
		}
	}
	return s
}

// transportOf returns the CTIS transport of a protocol word, or "".
func transportOf(s string) ctis.Transport {
	switch t := ctis.Transport(strings.ToLower(strings.TrimSpace(s))); t {
	case ctis.TransportTCP, ctis.TransportUDP, ctis.TransportSCTP:
		return t
	}
	return ""
}

// commitOf returns the commit info of a finding location, or nil when every
// member is empty.
func commitOf(sha, author, email string, at *time.Time) *ctis.CommitInfo {
	if sha == "" && author == "" && email == "" && at == nil {
		return nil
	}
	return &ctis.CommitInfo{SHA: sha, Author: author, AuthorEmail: email, CommittedAt: at}
}

// ensureRemediation returns the finding's remediation, creating it.
func ensureRemediation(f *ctis.Finding) *ctis.Remediation {
	if f.Remediation == nil {
		f.Remediation = &ctis.Remediation{}
	}
	return f.Remediation
}

// assetValue returns the canonical value of an asset the builder holds.
func (b *builder) assetValue(id string) string {
	if i, ok := b.assets[id]; ok {
		return b.res.Report.Assets[i].Value
	}
	return ""
}

// relate adds a relationship between two assets of the report, once.
func (b *builder) relate(typ ctis.RelationshipType, from, to string) {
	if from == "" || to == "" || from == to {
		return
	}
	if b.rels == nil {
		b.rels = map[string]bool{}
	}
	k := string(typ) + "\x1f" + from + "\x1f" + to
	if b.rels[k] || len(b.res.Report.Relationships) >= ctis.MaxRelationships {
		return
	}
	b.rels[k] = true
	b.res.Report.Relationships = append(b.res.Report.Relationships, ctis.Relationship{Type: typ, FromRef: from, ToRef: to})
}

// service adds the service asset host:port/transport exposed by the asset
// hostID (a host, domain name or address) and returns its id, or "" when the
// pieces make no canonical service value. appProtocol is an IANA service
// name or empty.
func (b *builder) service(hostID string, port int, transport ctis.Transport, appProtocol string) string {
	host := b.assetValue(hostID)
	if host == "" || port < 1 || port > 65535 || transport == "" {
		return ""
	}
	value, err := ctis.CanonicalService(host, port, string(transport))
	if err != nil {
		return ""
	}
	id, err := b.asset(ctis.Asset{
		Type: ctis.AssetTypeService, Value: value, Name: value,
		Technical: &ctis.AssetTechnical{Service: &ctis.ServiceTechnical{Port: port, Transport: transport, AppProtocol: ianaName(appProtocol)}},
	})
	if err != nil || id == "" {
		return ""
	}
	b.relate(ctis.RelExposes, hostID, id)
	return id
}

// tokenOf lowercases the name of an advisory source into an open token
// (a-z, 0-9, '.', '_', '-'); anything else becomes '-'. It may be empty.
func tokenOf(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-':
			b.WriteRune(r)
		case b.Len() > 0:
			b.WriteByte('-')
		}
		if b.Len() >= 63 {
			break
		}
	}
	return strings.Trim(b.String(), "-")
}
