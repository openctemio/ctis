package ctis

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// CTEM coverage members (CTIS 2.0, spec sections 4.14 to 4.17): namespaced
// extensions, asset context, finding validation and provenance, threat
// signals, and per-target completeness. All optional. Every member is
// untrusted producer input: each carries a bound in the schema, and Validate
// refuses a report that exceeds it. No member carries a tenant identifier.

// Limits of the 2.0 additive members.
const (
	MaxExtensionNamespaces   = 32
	MaxExtensionNamespaceLen = 128
	MaxExtensionsBytes       = 64 * 1024

	MaxAssetOwners      = 20
	MaxOwnerRefLen      = 256
	MaxValidatorLen     = 256
	MaxValidationNotes  = 4096
	MaxEvidenceRefs     = 20
	MaxEvidenceRefLen   = 128
	MaxCAPECIDs         = 32
	MaxThreatSignals    = 16
	MaxSignalSourceLen  = 64
	MaxSignalRefLen     = 2048
	MaxTargets          = 100000
	MaxTargetLen        = 2048
	MaxSegmentCount     = 10000
	MaxDependencyRefLen = 255
)

// OpenTokenPattern is the form of an open vocabulary value (2.0): a member
// whose known values are listed in the documentation but whose set is not
// closed, such as technical.cloud.provider and native.scheme.
const OpenTokenPattern = `^[a-z0-9][a-z0-9_.-]{0,63}$`

// ExtensionNamespacePattern is the form of an extensions key: a reverse-DNS
// name of at least two labels ("io.openctem", "com.example.scanner").
const ExtensionNamespacePattern = `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`

var (
	openTokenRE    = regexp.MustCompile(OpenTokenPattern)
	extNamespaceRE = regexp.MustCompile(ExtensionNamespacePattern)
	capecIDRE      = regexp.MustCompile(`^CAPEC-[1-9][0-9]{0,5}$`)
	dateOnlyRE     = regexp.MustCompile(`^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$`)
	evidenceRefRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

// IsOpenToken reports whether s is a value of an open vocabulary.
func IsOpenToken(s string) bool { return openTokenRE.MatchString(s) }

// IsExtensionNamespace reports whether s is a valid extensions key.
func IsExtensionNamespace(s string) bool {
	return len(s) <= MaxExtensionNamespaceLen && extNamespaceRE.MatchString(s)
}

// Extensions holds namespaced producer data: each key is a reverse-DNS
// namespace and each value an object whose members that namespace defines.
// A receiver validates a namespace it knows and ignores one it does not.
type Extensions map[string]map[string]any

// =============================================================================
// Asset context
// =============================================================================

// Environment is the deployment environment of an asset.
type Environment string

// Environments. unknown is the fallback for a value a receiver does not know.
const (
	EnvironmentProduction  Environment = "production"
	EnvironmentStaging     Environment = "staging"
	EnvironmentDevelopment Environment = "development"
	EnvironmentTest        Environment = "test"
	EnvironmentUnknown     Environment = "unknown"
)

// AllEnvironments returns every environment.
func AllEnvironments() []Environment {
	return []Environment{EnvironmentProduction, EnvironmentStaging, EnvironmentDevelopment, EnvironmentTest, EnvironmentUnknown}
}

// IsValid reports whether e is a known environment.
func (e Environment) IsValid() bool { return slices.Contains(AllEnvironments(), e) }

// OwnerKind is what an asset owner reference names.
type OwnerKind string

// Owner kinds.
const (
	OwnerKindTeam   OwnerKind = "team"
	OwnerKindPerson OwnerKind = "person"
	OwnerKindGroup  OwnerKind = "group"
)

// AllOwnerKinds returns every owner kind.
func AllOwnerKinds() []OwnerKind { return []OwnerKind{OwnerKindTeam, OwnerKindPerson, OwnerKindGroup} }

// IsValid reports whether k is a known owner kind.
func (k OwnerKind) IsValid() bool { return slices.Contains(AllOwnerKinds(), k) }

// OwnerRole is the responsibility an owner has for an asset.
type OwnerRole string

// Owner roles.
const (
	OwnerRoleTechnical OwnerRole = "technical"
	OwnerRoleBusiness  OwnerRole = "business"
	OwnerRoleSecurity  OwnerRole = "security"
)

// AllOwnerRoles returns every owner role.
func AllOwnerRoles() []OwnerRole {
	return []OwnerRole{OwnerRoleTechnical, OwnerRoleBusiness, OwnerRoleSecurity}
}

// IsValid reports whether r is a known owner role.
func (r OwnerRole) IsValid() bool { return slices.Contains(AllOwnerRoles(), r) }

// AssetOwner is one owner of an asset. Ref is personal data when Kind is
// person (an e-mail address, a user name): receivers must be able to erase
// it.
type AssetOwner struct {
	Kind OwnerKind `json:"kind"`
	Ref  string    `json:"ref"`
	Role OwnerRole `json:"role,omitempty"`
}

// AssetState is the state of an asset as the producer observed it.
type AssetState string

// Asset states. gone needs an authoritative signal (StateReason); every
// other absence of an asset is "not seen" (spec section 4.17).
const (
	AssetStateActive AssetState = "active"
	AssetStateGone   AssetState = "gone"
)

// AllAssetStates returns every asset state.
func AllAssetStates() []AssetState { return []AssetState{AssetStateActive, AssetStateGone} }

// IsValid reports whether s is a known asset state.
func (s AssetState) IsValid() bool { return slices.Contains(AllAssetStates(), s) }

// AssetStateReason is the authoritative signal behind AssetStateGone.
type AssetStateReason string

// Asset state reasons.
const (
	// StateReasonNameGone: an authoritative NXDOMAIN or NODATA answer.
	StateReasonNameGone AssetStateReason = "name_gone"
	// StateReasonResourceDeleted: the provider's API reports the resource
	// deleted.
	StateReasonResourceDeleted AssetStateReason = "resource_deleted"
	// StateReasonInventoryRemoved: the authoritative inventory the producer
	// reads (a CMDB, an identity provider) no longer lists the asset.
	StateReasonInventoryRemoved AssetStateReason = "inventory_removed"
)

// AllAssetStateReasons returns every asset state reason.
func AllAssetStateReasons() []AssetStateReason {
	return []AssetStateReason{StateReasonNameGone, StateReasonResourceDeleted, StateReasonInventoryRemoved}
}

// IsValid reports whether r is a known asset state reason.
func (r AssetStateReason) IsValid() bool { return slices.Contains(AllAssetStateReasons(), r) }

// =============================================================================
// Finding validation
// =============================================================================

// ValidationStatus is the result of validating a finding.
type ValidationStatus string

// Validation statuses.
const (
	ValidationExploited       ValidationStatus = "exploited"
	ValidationNotExploited    ValidationStatus = "not_exploited"
	ValidationBlocked         ValidationStatus = "blocked"
	ValidationDetected        ValidationStatus = "detected"
	ValidationNotReproducible ValidationStatus = "not_reproducible"
	ValidationNotTested       ValidationStatus = "not_tested"
)

// AllValidationStatuses returns every validation status.
func AllValidationStatuses() []ValidationStatus {
	return []ValidationStatus{
		ValidationExploited, ValidationNotExploited, ValidationBlocked,
		ValidationDetected, ValidationNotReproducible, ValidationNotTested,
	}
}

// IsValid reports whether s is a known validation status.
func (s ValidationStatus) IsValid() bool { return slices.Contains(AllValidationStatuses(), s) }

// ValidationMethod is how a finding was validated.
type ValidationMethod string

// Validation methods.
const (
	ValidationMethodPentest          ValidationMethod = "pentest"
	ValidationMethodBAS              ValidationMethod = "bas"
	ValidationMethodAutomatedExploit ValidationMethod = "automated_exploit"
	ValidationMethodRetest           ValidationMethod = "retest"
	ValidationMethodManualReview     ValidationMethod = "manual_review"
)

// AllValidationMethods returns every validation method.
func AllValidationMethods() []ValidationMethod {
	return []ValidationMethod{
		ValidationMethodPentest, ValidationMethodBAS, ValidationMethodAutomatedExploit,
		ValidationMethodRetest, ValidationMethodManualReview,
	}
}

// IsValid reports whether m is a known validation method.
func (m ValidationMethod) IsValid() bool { return slices.Contains(AllValidationMethods(), m) }

// FindingValidation says whether and how a finding was shown to be
// exploitable. Validator is personal data.
type FindingValidation struct {
	Status       ValidationStatus `json:"status"`
	Method       ValidationMethod `json:"method,omitempty"`
	ValidatedAt  *time.Time       `json:"validated_at,omitempty"`
	Validator    string           `json:"validator,omitempty"`
	EvidenceRefs []string         `json:"evidence_refs,omitempty"`
	Notes        string           `json:"notes,omitempty"`
}

// =============================================================================
// Threat signals
// =============================================================================

// ThreatSignalType is the kind of a threat assertion about a vulnerability.
type ThreatSignalType string

// Threat signal types.
const (
	ThreatSignalKEV             ThreatSignalType = "kev"
	ThreatSignalExploitedInWild ThreatSignalType = "exploited_in_wild"
	ThreatSignalPublicExploit   ThreatSignalType = "public_exploit"
	ThreatSignalRansomwareUse   ThreatSignalType = "ransomware_use"
	ThreatSignalWeaponized      ThreatSignalType = "weaponized"
)

// AllThreatSignalTypes returns every threat signal type.
func AllThreatSignalTypes() []ThreatSignalType {
	return []ThreatSignalType{
		ThreatSignalKEV, ThreatSignalExploitedInWild, ThreatSignalPublicExploit,
		ThreatSignalRansomwareUse, ThreatSignalWeaponized,
	}
}

// IsValid reports whether t is a known threat signal type.
func (t ThreatSignalType) IsValid() bool { return slices.Contains(AllThreatSignalTypes(), t) }

// ThreatSignal is a threat assertion made by a named source at a date. Ref
// is an external reference (a catalog id or a URL); receivers never fetch
// it. DueOn is a date-only remediation due date (a KEV due date).
type ThreatSignal struct {
	Type   ThreatSignalType `json:"type"`
	Source string           `json:"source"`
	AsOf   *time.Time       `json:"as_of,omitempty"`
	Ref    string           `json:"ref,omitempty"`
	DueOn  string           `json:"due_on,omitempty"`
}

// =============================================================================
// Completeness: per-target outcomes and segments
// =============================================================================

// TargetState is how one target of the work ended. The vocabulary is the
// one of the outcome package (revision 2), copied here so the root package
// does not import it; a test keeps the two equal.
type TargetState string

// Target states.
const (
	TargetDone       TargetState = "done"
	TargetFailed     TargetState = "failed"
	TargetSkipped    TargetState = "skipped"
	TargetUnfinished TargetState = "unfinished"
)

// AllTargetStates returns every target state.
func AllTargetStates() []TargetState {
	return []TargetState{TargetDone, TargetFailed, TargetSkipped, TargetUnfinished}
}

// IsValid reports whether s is a known target state.
func (s TargetState) IsValid() bool { return slices.Contains(AllTargetStates(), s) }

// TargetClass says why a target failed or was skipped.
type TargetClass string

// Target classes.
const (
	TargetClassUnreachable        TargetClass = "unreachable"
	TargetClassTimeout            TargetClass = "timeout"
	TargetClassToolError          TargetClass = "tool_error"
	TargetClassEgressRefused      TargetClass = "egress_refused"
	TargetClassNameGone           TargetClass = "name_gone"
	TargetClassResolverFailed     TargetClass = "resolver_failed"
	TargetClassSensorNetworkFault TargetClass = "sensor_network_fault"
	TargetClassRateLimited        TargetClass = "rate_limited"
	TargetClassEdgeChallenged     TargetClass = "edge_challenged"
	TargetClassEdgeBlocked        TargetClass = "edge_blocked"
	TargetClassRefused            TargetClass = "refused"
	TargetClassExcluded           TargetClass = "excluded"
)

// AllTargetClasses returns every target class.
func AllTargetClasses() []TargetClass {
	return []TargetClass{
		TargetClassUnreachable, TargetClassTimeout, TargetClassToolError, TargetClassEgressRefused,
		TargetClassNameGone, TargetClassResolverFailed, TargetClassSensorNetworkFault, TargetClassRateLimited,
		TargetClassEdgeChallenged, TargetClassEdgeBlocked, TargetClassRefused, TargetClassExcluded,
	}
}

// IsValid reports whether c is a known target class.
func (c TargetClass) IsValid() bool { return slices.Contains(AllTargetClasses(), c) }

// fits reports whether class c is one state s takes.
func (c TargetClass) fits(s TargetState) bool {
	switch s {
	case TargetFailed:
		return c != TargetClassRefused && c != TargetClassExcluded && c.IsValid()
	case TargetSkipped:
		switch c {
		case TargetClassRefused, TargetClassExcluded, TargetClassEdgeChallenged, TargetClassEdgeBlocked:
			return true
		}
	}
	return false
}

// TargetCause says whose side a not-covered target is on.
type TargetCause string

// Target causes.
const (
	TargetCauseTarget   TargetCause = "target"
	TargetCauseSensor   TargetCause = "sensor"
	TargetCausePlatform TargetCause = "platform"
)

// AllTargetCauses returns every target cause.
func AllTargetCauses() []TargetCause {
	return []TargetCause{TargetCauseTarget, TargetCauseSensor, TargetCausePlatform}
}

// IsValid reports whether c is a known target cause.
func (c TargetCause) IsValid() bool { return slices.Contains(AllTargetCauses(), c) }

// TargetOutcome is how one target of the work ended. Done and unfinished
// take no class or cause; failed and skipped need a class of their own.
type TargetOutcome struct {
	Target string      `json:"target"`
	Kind   AssetType   `json:"kind,omitempty"`
	State  TargetState `json:"state"`
	Class  TargetClass `json:"class,omitempty"`
	Cause  TargetCause `json:"cause,omitempty"`
}

// Segment places a document in a result split over Count documents that
// share one metadata.id. Index is zero-based.
type Segment struct {
	Index int `json:"index"`
	Count int `json:"count"`
}

// =============================================================================
// Validation of the 2.0 additive members
// =============================================================================

// seenOrder reports whether both times are set and last is before first.
func seenOrder(first, last *time.Time) bool {
	return first != nil && last != nil && last.Before(*first)
}

// validateExtensions checks one extensions object.
func validateExtensions(where string, ext Extensions, add func(string, ...any)) {
	if len(ext) == 0 {
		return
	}
	if len(ext) > MaxExtensionNamespaces {
		add("%s has %d namespaces, at most %d", where, len(ext), MaxExtensionNamespaces)
	}
	for _, ns := range sortedKeysOf(ext) {
		if !IsExtensionNamespace(ns) {
			add("%s: %q is not a reverse-DNS namespace", where, truncateForError(ns))
		}
		if ext[ns] == nil {
			add("%s[%q] must be an object", where, truncateForError(ns))
		}
	}
	raw, err := json.Marshal(ext)
	switch {
	case err != nil:
		add("%s does not encode: %v", where, err)
	case len(raw) > MaxExtensionsBytes:
		add("%s is %d bytes, at most %d", where, len(raw), MaxExtensionsBytes)
	}
}

func sortedKeysOf[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// validateCoverageMetadata checks the 2.0 metadata members.
func validateCoverageMetadata(m *ReportMetadata, add func(string, ...any)) {
	if seenOrder(m.StartedAt, m.EndedAt) {
		add("metadata.ended_at is before metadata.started_at")
	}
	if s := m.Segment; s != nil {
		if s.Count < 1 || s.Count > MaxSegmentCount {
			add("metadata.segment.count %d is outside 1-%d", s.Count, MaxSegmentCount)
		}
		if s.Index < 0 || s.Index >= s.Count {
			add("metadata.segment.index %d is outside 0-%d", s.Index, s.Count-1)
		}
		if strings.TrimSpace(m.ID) == "" {
			add("metadata.segment needs metadata.id: the segments of one result share it")
		}
	}
	if len(m.Targets) > MaxTargets {
		add("metadata.targets has %d entries, at most %d", len(m.Targets), MaxTargets)
	}
	seen := make(map[string]bool, min(len(m.Targets), MaxTargets))
	for i, t := range m.Targets {
		if i >= MaxTargets {
			break
		}
		switch {
		case t.Target == "":
			add("metadata.targets[%d].target is required", i)
		case len(t.Target) > MaxTargetLen:
			add("metadata.targets[%d].target longer than %d bytes", i, MaxTargetLen)
		case seen[t.Target]:
			add("metadata.targets[%d]: duplicate target %q", i, truncateForError(t.Target))
		}
		seen[t.Target] = true
		if t.Kind != "" && !t.Kind.IsValid() {
			add("metadata.targets[%d]: invalid kind %q", i, truncateForError(string(t.Kind)))
		}
		if t.Cause != "" && !t.Cause.IsValid() {
			add("metadata.targets[%d]: invalid cause %q", i, truncateForError(string(t.Cause)))
		}
		switch t.State {
		case TargetDone, TargetUnfinished:
			if t.Class != "" || t.Cause != "" {
				add("metadata.targets[%d]: state %s takes no class or cause", i, t.State)
			}
		case TargetFailed, TargetSkipped:
			if !t.Class.fits(t.State) {
				add("metadata.targets[%d]: class %q does not fit state %s", i, truncateForError(string(t.Class)), t.State)
			}
		default:
			add("metadata.targets[%d]: invalid state %q", i, truncateForError(string(t.State)))
		}
	}
	validateExtensions("metadata.extensions", m.Extensions, add)
}

// validateCoverageAsset checks the 2.0 additive members of one asset.
func validateCoverageAsset(i int, a *Asset, add func(string, ...any)) {
	if a.Environment != "" && !a.Environment.IsValid() {
		add("assets[%d]: invalid environment %q", i, truncateForError(string(a.Environment)))
	}
	if len(a.Owners) > MaxAssetOwners {
		add("assets[%d]: owners has %d entries, at most %d", i, len(a.Owners), MaxAssetOwners)
	}
	for j, o := range a.Owners {
		if j >= MaxAssetOwners {
			break
		}
		if !o.Kind.IsValid() {
			add("assets[%d]: owners[%d]: invalid kind %q", i, j, truncateForError(string(o.Kind)))
		}
		switch {
		case strings.TrimSpace(o.Ref) == "":
			add("assets[%d]: owners[%d].ref is required", i, j)
		case tooLong(o.Ref, MaxOwnerRefLen):
			add("assets[%d]: owners[%d].ref longer than %d", i, j, MaxOwnerRefLen)
		}
		if o.Role != "" && !o.Role.IsValid() {
			add("assets[%d]: owners[%d]: invalid role %q", i, j, truncateForError(string(o.Role)))
		}
	}
	if seenOrder(a.FirstSeenAt, a.LastSeenAt) {
		add("assets[%d]: last_seen_at is before first_seen_at", i)
	}
	if a.State != "" && !a.State.IsValid() {
		add("assets[%d]: invalid state %q", i, truncateForError(string(a.State)))
	}
	if a.StateReason != "" && !a.StateReason.IsValid() {
		add("assets[%d]: invalid state_reason %q", i, truncateForError(string(a.StateReason)))
	}
	if a.State == AssetStateGone && a.StateReason == "" {
		add("assets[%d]: state gone needs a state_reason (an authoritative signal)", i)
	}
	if a.StateReason != "" && a.State != AssetStateGone {
		add("assets[%d]: state_reason is only for state gone", i)
	}
	validateExtensions(fmt.Sprintf("assets[%d].extensions", i), a.Extensions, add)
}

// validateCoverageFinding checks the 2.0 additive members of one finding.
func validateCoverageFinding(i int, f *Finding, depIDs map[string]bool, add func(string, ...any)) {
	if f.Tool != nil && strings.TrimSpace(f.Tool.Name) == "" {
		add("findings[%d]: tool.name is required when tool is present", i)
	}
	if f.DependencyRef != "" {
		switch {
		case len(f.DependencyRef) > MaxDependencyRefLen:
			add("findings[%d]: dependency_ref longer than %d", i, MaxDependencyRefLen)
		case !depIDs[f.DependencyRef]:
			add("findings[%d]: dependency_ref %q names no dependency in this report", i, truncateForError(f.DependencyRef))
		}
	}
	if v := f.Validation; v != nil {
		if !v.Status.IsValid() {
			add("findings[%d]: validation: invalid status %q", i, truncateForError(string(v.Status)))
		}
		if v.Method != "" && !v.Method.IsValid() {
			add("findings[%d]: validation: invalid method %q", i, truncateForError(string(v.Method)))
		}
		if tooLong(v.Validator, MaxValidatorLen) {
			add("findings[%d]: validation.validator longer than %d", i, MaxValidatorLen)
		}
		if tooLong(v.Notes, MaxValidationNotes) {
			add("findings[%d]: validation.notes longer than %d", i, MaxValidationNotes)
		}
		if len(v.EvidenceRefs) > MaxEvidenceRefs {
			add("findings[%d]: validation.evidence_refs has %d entries, at most %d", i, len(v.EvidenceRefs), MaxEvidenceRefs)
		}
		for j, ref := range v.EvidenceRefs {
			if j < MaxEvidenceRefs && !evidenceRefRE.MatchString(ref) {
				add("findings[%d]: validation.evidence_refs[%d] %q is not a sha256:<hex> or attachment id", i, j, truncateForError(ref))
			}
		}
	}
	if vu := f.Vulnerability; vu != nil {
		if len(vu.CAPECIDs) > MaxCAPECIDs {
			add("findings[%d]: vulnerability.capec_ids has %d entries, at most %d", i, len(vu.CAPECIDs), MaxCAPECIDs)
		}
		for j, id := range vu.CAPECIDs {
			if j < MaxCAPECIDs && !capecIDRE.MatchString(id) {
				add("findings[%d]: vulnerability.capec_ids[%d] %q is not a CAPEC id", i, j, truncateForError(id))
			}
		}
		if len(vu.ThreatSignals) > MaxThreatSignals {
			add("findings[%d]: vulnerability.threat_signals has %d entries, at most %d", i, len(vu.ThreatSignals), MaxThreatSignals)
		}
		for j, s := range vu.ThreatSignals {
			if j >= MaxThreatSignals {
				break
			}
			if !s.Type.IsValid() {
				add("findings[%d]: vulnerability.threat_signals[%d]: invalid type %q", i, j, truncateForError(string(s.Type)))
			}
			switch {
			case strings.TrimSpace(s.Source) == "":
				add("findings[%d]: vulnerability.threat_signals[%d].source is required", i, j)
			case tooLong(s.Source, MaxSignalSourceLen):
				add("findings[%d]: vulnerability.threat_signals[%d].source longer than %d", i, j, MaxSignalSourceLen)
			}
			if tooLong(s.Ref, MaxSignalRefLen) {
				add("findings[%d]: vulnerability.threat_signals[%d].ref longer than %d", i, j, MaxSignalRefLen)
			}
			if s.DueOn != "" && !isDateOnly(s.DueOn) {
				add("findings[%d]: vulnerability.threat_signals[%d].due_on %q is not a YYYY-MM-DD date", i, j, truncateForError(s.DueOn))
			}
		}
	}
	validateExtensions(fmt.Sprintf("findings[%d].extensions", i), f.Extensions, add)
}

// isDateOnly reports whether s is a calendar date YYYY-MM-DD.
func isDateOnly(s string) bool {
	if !dateOnlyRE.MatchString(s) {
		return false
	}
	_, err := time.Parse(time.DateOnly, s)
	return err == nil
}
