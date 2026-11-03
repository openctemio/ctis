package importer

import (
	"strings"
	"time"

	"github.com/openctemio/ctis/v2"
)

// Helpers for the CTIS 2.0 members the importers fill: document references,
// raw-text evidence, threat signals, web URLs.

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
func (b *Builder) assetValue(id string) string {
	if i, ok := b.assets[id]; ok {
		return b.res.Report.Assets[i].Value
	}
	return ""
}

// relate adds a relationship between two assets of the report, once.
func (b *Builder) relate(typ ctis.RelationshipType, from, to string) {
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
func (b *Builder) service(hostID string, port int, transport ctis.Transport, appProtocol string) string {
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
