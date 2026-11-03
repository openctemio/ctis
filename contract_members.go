package ctis

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Contract members (CTIS 1.5, spec section 4.11): the capability a report
// answers, typed technologies, typed relationships between the report's
// assets, and the ATT&CK techniques a finding enables. All optional.

// Limits of the 1.5 members. The schema states them too; Validate refuses a
// report that exceeds them.
const (
	MaxCapabilityRefLen    = 128
	MaxTechnologies        = 100
	MaxTechnologyNameLen   = 128
	MaxTechnologyVerLen    = 64
	MaxTechnologyCPELen    = 255
	MaxTechnologyCategory  = 10
	MaxTechnologyCatLen    = 64
	MaxFindingTechniques   = 20
	MaxRelationships       = 10000
	MaxRelationshipRefLen  = 255
	MaxFindingEvidenceSize = 64 * 1024
)

var (
	// capabilityRefRE is the form of a capability reference: a dotted id
	// and a major, "scan.ports@1".
	capabilityRefRE = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+@[1-9][0-9]{0,2}$`)
	// attackTechniqueRE is a MITRE ATT&CK technique or sub-technique id.
	attackTechniqueRE = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)
)

// IsCapabilityRef reports whether s has the form of a capability reference
// ("scan.ports@1"). It does not say whether the capability exists; the
// capability package does.
func IsCapabilityRef(s string) bool {
	return len(s) <= MaxCapabilityRefLen && capabilityRefRE.MatchString(s)
}

// IsAttackTechniqueID reports whether s is a well-formed MITRE ATT&CK
// technique id ("T1190") or sub-technique id ("T1595.002").
func IsAttackTechniqueID(s string) bool { return attackTechniqueRE.MatchString(s) }

// Technology is a technology an asset runs, as a fingerprinting tool
// identified it.
type Technology struct {
	// Name of the product or framework ("nginx", "WordPress").
	Name string `json:"name"`

	// Version when the tool could tell.
	Version string `json:"version,omitempty"`

	// CPE 2.3 name when the tool could tell.
	CPE string `json:"cpe,omitempty"`

	// Categories the tool puts the technology in ("web-server", "cms").
	Categories []string `json:"categories,omitempty"`

	// How sure the tool is, 0-100.
	Confidence int `json:"confidence,omitempty"`
}

// RelationshipType is the type of a relationship between two assets of a
// report. The set is closed.
type RelationshipType string

// Relationship types.
const (
	// RelSubdomainOf: from (a subdomain) is a name below to (a domain).
	RelSubdomainOf RelationshipType = "subdomain_of"
	// RelResolvesTo: from (a name) resolves to to (an address).
	RelResolvesTo RelationshipType = "resolves_to"
	// RelCnameOf: from (a name) is an alias of to (a name).
	RelCnameOf RelationshipType = "cname_of"
	// RelExposes: from (a host or address) exposes to (a service or port).
	RelExposes RelationshipType = "exposes"
	// RelServesCertificate: from (a service) serves to (a certificate).
	RelServesCertificate RelationshipType = "serves_certificate"
	// RelHostedBy: from (a service or address) is hosted by to (a provider
	// or a host).
	RelHostedBy RelationshipType = "hosted_by"

	// Relationship types added in 2.0. Each reads "from <type> to".

	// RelContains: from (a cluster, account, network, image) contains to.
	RelContains RelationshipType = "contains"
	// RelRunsOn: from (a workload, container, service) runs on to (a host,
	// cluster, cloud resource).
	RelRunsOn RelationshipType = "runs_on"
	// RelDependsOn: from (an application, package) depends on to (a
	// package, service).
	RelDependsOn RelationshipType = "depends_on"
	// RelDeployedFrom: from (a workload, image) is deployed from to (a
	// repository, image).
	RelDeployedFrom RelationshipType = "deployed_from"
	// RelMemberOf: from (an identity, host) is a member of to (a group,
	// network, account).
	RelMemberOf RelationshipType = "member_of"
	// RelRoutesTo: from (a load balancer, gateway, origin) routes traffic
	// to to.
	RelRoutesTo RelationshipType = "routes_to"
	// RelHasAccessTo: from (an identity) has access to to (a resource).
	RelHasAccessTo RelationshipType = "has_access_to"
)

// AllRelationshipTypes returns every relationship type.
func AllRelationshipTypes() []RelationshipType {
	return []RelationshipType{
		RelSubdomainOf, RelResolvesTo, RelCnameOf, RelExposes, RelServesCertificate, RelHostedBy,
		RelContains, RelRunsOn, RelDependsOn, RelDeployedFrom, RelMemberOf, RelRoutesTo, RelHasAccessTo,
	}
}

// IsValid reports whether t is a known relationship type.
func (t RelationshipType) IsValid() bool {
	for _, v := range AllRelationshipTypes() {
		if t == v {
			return true
		}
	}
	return false
}

// Relationship is a typed edge between two assets of the same report, named
// by their ids.
type Relationship struct {
	Type    RelationshipType `json:"type"`
	FromRef string           `json:"from_ref"`
	ToRef   string           `json:"to_ref"`

	// When the producer first and last observed the edge, and how sure it
	// is, 0-100 (2.0).
	FirstSeenAt *time.Time `json:"first_seen_at,omitempty"`
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`
	Confidence  int        `json:"confidence,omitempty"`

	// Namespaced producer data (2.0).
	Extensions Extensions `json:"extensions,omitempty"`
}

// validateContractReport checks the 1.5 report-level members.
func validateContractReport(r *Report, assetIDs map[string]bool, add func(string, ...any)) {
	if c := r.Metadata.Capability; c != "" && !IsCapabilityRef(c) {
		add("metadata.capability %q is not a capability reference (id@major)", truncateForError(c))
	}
	if len(r.Relationships) > MaxRelationships {
		add("relationships has %d entries, at most %d", len(r.Relationships), MaxRelationships)
	}
	for i, rel := range r.Relationships {
		if i >= MaxRelationships {
			break
		}
		if !rel.Type.IsValid() {
			add("relationships[%d]: invalid type %q", i, truncateForError(string(rel.Type)))
		}
		for _, ref := range [][2]string{{"from_ref", rel.FromRef}, {"to_ref", rel.ToRef}} {
			switch {
			case strings.TrimSpace(ref[1]) == "":
				add("relationships[%d]: %s is required", i, ref[0])
			case len(ref[1]) > MaxRelationshipRefLen:
				add("relationships[%d]: %s longer than %d", i, ref[0], MaxRelationshipRefLen)
			case !assetIDs[ref[1]]:
				add("relationships[%d]: %s %q names no asset in this report", i, ref[0], truncateForError(ref[1]))
			}
		}
		if rel.FromRef != "" && rel.FromRef == rel.ToRef {
			add("relationships[%d]: an asset cannot relate to itself", i)
		}
		if rel.Confidence < 0 || rel.Confidence > 100 {
			add("relationships[%d]: confidence %d is outside 0-100", i, rel.Confidence)
		}
		if seenOrder(rel.FirstSeenAt, rel.LastSeenAt) {
			add("relationships[%d]: last_seen_at is before first_seen_at", i)
		}
		validateExtensions(fmt.Sprintf("relationships[%d].extensions", i), rel.Extensions, add)
	}
}

// validateTechnologies checks asset.technologies.
func validateTechnologies(i int, techs []Technology, add func(string, ...any)) {
	validateTechnologyList(func(format string, args ...any) {
		add("assets[%d]: "+format, append([]any{i}, args...)...)
	}, techs)
}

// validateTechnologyList checks a technologies list; add's messages are
// relative to the list's owner.
func validateTechnologyList(add func(string, ...any), techs []Technology) {
	if len(techs) > MaxTechnologies {
		add("technologies has %d entries, at most %d", len(techs), MaxTechnologies)
	}
	for j, t := range techs {
		if j >= MaxTechnologies {
			break
		}
		switch {
		case strings.TrimSpace(t.Name) == "":
			add("technologies[%d].name is required", j)
		case tooLong(t.Name, MaxTechnologyNameLen):
			add("technologies[%d].name longer than %d", j, MaxTechnologyNameLen)
		}
		if tooLong(t.Version, MaxTechnologyVerLen) {
			add("technologies[%d].version longer than %d", j, MaxTechnologyVerLen)
		}
		if tooLong(t.CPE, MaxTechnologyCPELen) {
			add("technologies[%d].cpe longer than %d", j, MaxTechnologyCPELen)
		}
		if len(t.Categories) > MaxTechnologyCategory {
			add("technologies[%d].categories has %d entries, at most %d", j, len(t.Categories), MaxTechnologyCategory)
		}
		for k, c := range t.Categories {
			if k < MaxTechnologyCategory && tooLong(c, MaxTechnologyCatLen) {
				add("technologies[%d].categories[%d] longer than %d", j, k, MaxTechnologyCatLen)
			}
		}
		if t.Confidence < 0 || t.Confidence > 100 {
			add("technologies[%d].confidence %d is outside 0-100", j, t.Confidence)
		}
	}
}

// validateFindingTechniques checks finding.attack.
func validateFindingTechniques(i int, ids []string, add func(string, ...any)) {
	if len(ids) > MaxFindingTechniques {
		add("findings[%d]: attack has %d entries, at most %d", i, len(ids), MaxFindingTechniques)
	}
	for j, id := range ids {
		if j < MaxFindingTechniques && !IsAttackTechniqueID(id) {
			add("findings[%d]: attack[%d] %q is not an ATT&CK technique id", i, j, truncateForError(id))
		}
	}
}

// truncateForError bounds a hostile value quoted in an error message.
func truncateForError(s string) string {
	const max = 64
	n := 0
	for i := range s {
		if n == max {
			return s[:i] + "..."
		}
		n++
	}
	return s
}
