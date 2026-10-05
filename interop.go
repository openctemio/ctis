package ctis

import "time"

// Interoperability members (CTIS 1.4).
//
// These members carry what a source scanner or importer knows about a finding
// in the source's own terms, next to the normalized CTIS values, so a report
// converted from Nessus, Qualys, DefectDojo, SARIF, CycloneDX, OSV, CSAF or
// OpenVEX loses nothing a receiver needs for deduplication, correlation or a
// round trip. Every member is optional; a 1.3 report is a valid 1.4 report.
//
// The rule throughout: the normalized value goes in the existing CTIS member
// (severity, status, cve_ids, ...), and the source's own value is kept beside
// it here. A receiver never has to choose between them.

// Size limits of the interoperability members. They are part of the contract
// (the schema states them and Validate enforces them), so a hostile or broken
// producer cannot make a receiver store unbounded data through them.
const (
	MaxScores               = 32
	MaxScoreVectorLen       = 512
	MaxScoreSourceLen       = 64
	MaxScoreLabelLen        = 32
	MaxVulnerabilityIDs     = 64
	MaxVulnerabilityIDLen   = 128
	MaxAdvisories           = 50
	MaxAdvisoryURLLen       = 2048
	MaxNativeValueLen       = 64  // native severity, status, justification
	MaxNativeIDLen          = 256 // native vuln id, instance id, family
	MaxRawRefLen            = 1024
	MaxVEXStatementLen      = 4096
	MaxVEXSourceLen         = 512
	MaxSourceExtraEntries   = 64
	MaxSourceExtraKeyLen    = 128
	MaxSourceExtraValueLen  = 4096
	MaxSourceExtraBytes     = 32 * 1024 // keys plus values, in bytes
	MaxIdentityHintLen      = 255
	MaxIdentityHintMACs     = 32
	MaxTimesFound           = 1_000_000_000
	maxVendorScoreMagnitude = 1e6
)

// NativeIdentity is the finding as the source tool names it.
type NativeIdentity struct {
	// Vocabulary of the native values below. Selects the mapping tables of
	// NormalizeNativeSeverity, NormalizeNativeStatus and
	// NormalizeDetectionType.
	Scheme NativeScheme `json:"scheme,omitempty"`

	// The tool's id of the vulnerability or check: a Nessus plugin ID, a
	// Qualys QID, a DefectDojo vuln_id_from_tool, a SARIF rule id.
	VulnID string `json:"vuln_id,omitempty"`

	// The tool's id of this occurrence (DefectDojo unique_id_from_tool, a
	// Tenable or Qualys detection id), when it has one.
	InstanceID string `json:"instance_id,omitempty"`

	// The tool's family or category of the check (Nessus plugin family,
	// Qualys vulnerability category).
	Family string `json:"family,omitempty"`

	// The tool's severity exactly as reported ("4", "5", "High", "error").
	// finding.severity holds the normalized level.
	Severity string `json:"severity,omitempty"`

	// The tool's status exactly as reported ("Re-Opened", "fixed",
	// "risk_accepted"). finding.status and source_lifecycle.state hold the
	// normalized values.
	Status string `json:"status,omitempty"`

	// Whether the tool confirmed the issue or only suspects it.
	DetectionType DetectionType `json:"detection_type,omitempty"`

	// Whether the scan that found it was authenticated on the target. Absent
	// means unknown; false means the scan ran without credentials.
	Credentialed *bool `json:"credentialed,omitempty"`

	// Where the raw record can be found again: a URL into the source, or a
	// locator inside the imported file. Informational; receivers never fetch
	// it.
	RawRef string `json:"raw_ref,omitempty"`
}

// NativeScheme names the vocabulary of a finding's native values.
type NativeScheme string

const (
	NativeSchemeNessus     NativeScheme = "nessus"
	NativeSchemeQualys     NativeScheme = "qualys"
	NativeSchemeDefectDojo NativeScheme = "defectdojo"
	NativeSchemeSARIF      NativeScheme = "sarif"
	NativeSchemeOther      NativeScheme = "other"
)

// AllNativeSchemes returns every valid native scheme.
func AllNativeSchemes() []NativeScheme {
	return []NativeScheme{NativeSchemeNessus, NativeSchemeQualys, NativeSchemeDefectDojo, NativeSchemeSARIF, NativeSchemeOther}
}

// IsValid reports whether s is a recognized native scheme.
func (s NativeScheme) IsValid() bool { return inEnum(s, AllNativeSchemes()) }

// DetectionType says how sure the source is that the issue is present.
type DetectionType string

const (
	// The source verified the issue (a Qualys Confirmed detection).
	DetectionTypeConfirmed DetectionType = "confirmed"
	// The source could not verify it (a Qualys Potential detection, a
	// version-only match).
	DetectionTypePotential DetectionType = "potential"
	// Information gathered, not a vulnerability.
	DetectionTypeInfo DetectionType = "info"
)

// AllDetectionTypes returns every valid detection type.
func AllDetectionTypes() []DetectionType {
	return []DetectionType{DetectionTypeConfirmed, DetectionTypePotential, DetectionTypeInfo}
}

// IsValid reports whether d is a recognized detection type.
func (d DetectionType) IsValid() bool { return inEnum(d, AllDetectionTypes()) }

// Score is one score of a finding, with where it came from and when. A
// finding may carry several: CVSS v3.1 and v4.0 together, a vendor's rating,
// EPSS and an SSVC decision.
type Score struct {
	// Scoring system (required).
	System ScoreSystem `json:"system"`

	// System version: "2.0", "3.0", "3.1" or "4.0" for CVSS (required
	// there), the model version for EPSS, "2" for SSVC.
	Version string `json:"version,omitempty"`

	// Vector string ("CVSS:3.1/AV:N/...", an SSVC vector).
	Vector string `json:"vector,omitempty"`

	// Numeric value: 0-10 for cvss and vpr, 0-1 for epss and
	// epss_percentile (FIRST's fractions), absent for ssvc.
	Value *float64 `json:"value,omitempty"`

	// Qualitative rating as the source states it ("high", "Act").
	Label string `json:"label,omitempty"`

	// Who assigned it: nvd, ghsa, vendor, tenable, qualys, first, cisa, ...
	Source string `json:"source,omitempty"`

	// When the source assigned or last updated it.
	AsOf *time.Time `json:"as_of,omitempty"`
}

// ScoreSystem names a scoring system.
type ScoreSystem string

const (
	ScoreSystemCVSS           ScoreSystem = "cvss"
	ScoreSystemEPSS           ScoreSystem = "epss"
	ScoreSystemEPSSPercentile ScoreSystem = "epss_percentile"
	ScoreSystemSSVC           ScoreSystem = "ssvc"
	// Tenable Vulnerability Priority Rating, 0-10.
	ScoreSystemVPR ScoreSystem = "vpr"
	// Any other vendor score (a Qualys detection score, a risk score);
	// source names the vendor.
	ScoreSystemVendor ScoreSystem = "vendor"
)

// AllScoreSystems returns every valid score system.
func AllScoreSystems() []ScoreSystem {
	return []ScoreSystem{ScoreSystemCVSS, ScoreSystemEPSS, ScoreSystemEPSSPercentile, ScoreSystemSSVC, ScoreSystemVPR, ScoreSystemVendor}
}

// IsValid reports whether s is a recognized score system.
func (s ScoreSystem) IsValid() bool { return inEnum(s, AllScoreSystems()) }

// VEX is an exploitability statement about the vulnerability of a finding,
// in the CSAF / OpenVEX vocabulary.
type VEX struct {
	// Status (required).
	Status VEXStatus `json:"status"`

	// Why the product is not affected. Only with status not_affected, which
	// needs a justification or a statement.
	Justification VEXJustification `json:"justification,omitempty"`

	// The justification as the source document states it (a CycloneDX
	// analysis.justification such as code_not_reachable).
	NativeJustification string `json:"native_justification,omitempty"`

	// Impact or action statement, plain text.
	Statement string `json:"statement,omitempty"`

	// Who made the statement: a document id or URL, a vendor, a team.
	Source string `json:"source,omitempty"`

	// When the statement was made.
	AsOf *time.Time `json:"as_of,omitempty"`
}

// VEXStatus is the exploitability status of a VEX statement.
type VEXStatus string

const (
	VEXStatusNotAffected        VEXStatus = "not_affected"
	VEXStatusAffected           VEXStatus = "affected"
	VEXStatusFixed              VEXStatus = "fixed"
	VEXStatusUnderInvestigation VEXStatus = "under_investigation"
)

// AllVEXStatuses returns every valid VEX status.
func AllVEXStatuses() []VEXStatus {
	return []VEXStatus{VEXStatusNotAffected, VEXStatusAffected, VEXStatusFixed, VEXStatusUnderInvestigation}
}

// IsValid reports whether s is a recognized VEX status.
func (s VEXStatus) IsValid() bool { return inEnum(s, AllVEXStatuses()) }

// VEXJustification is why a product is not affected (CSAF flags, OpenVEX
// justifications).
type VEXJustification string

const (
	VEXJustificationComponentNotPresent                         VEXJustification = "component_not_present"
	VEXJustificationVulnerableCodeNotPresent                    VEXJustification = "vulnerable_code_not_present"
	VEXJustificationVulnerableCodeNotInExecutePath              VEXJustification = "vulnerable_code_not_in_execute_path"
	VEXJustificationVulnerableCodeCannotBeControlledByAdversary VEXJustification = "vulnerable_code_cannot_be_controlled_by_adversary"
	VEXJustificationInlineMitigationsAlreadyExist               VEXJustification = "inline_mitigations_already_exist"
)

// AllVEXJustifications returns every valid VEX justification.
func AllVEXJustifications() []VEXJustification {
	return []VEXJustification{
		VEXJustificationComponentNotPresent,
		VEXJustificationVulnerableCodeNotPresent,
		VEXJustificationVulnerableCodeNotInExecutePath,
		VEXJustificationVulnerableCodeCannotBeControlledByAdversary,
		VEXJustificationInlineMitigationsAlreadyExist,
	}
}

// IsValid reports whether j is a recognized VEX justification.
func (j VEXJustification) IsValid() bool { return inEnum(j, AllVEXJustifications()) }

// SourceLifecycle is the finding's history as the source tracks it. It is the
// source's view and stays separate from the receiver's own lifecycle: a
// scanner may call a finding fixed that a receiver keeps open until verified.
type SourceLifecycle struct {
	// When the source first found it.
	FirstFound *time.Time `json:"first_found,omitempty"`

	// When the source last found it.
	LastFound *time.Time `json:"last_found,omitempty"`

	// When the source last saw it fixed.
	LastFixed *time.Time `json:"last_fixed,omitempty"`

	// How many times the source has found it.
	TimesFound int `json:"times_found,omitempty"`

	// The source state, normalized (native.status keeps the source's word).
	State SourceState `json:"state,omitempty"`
}

// SourceState is the normalized state of a finding in its source.
type SourceState string

const (
	SourceStateNew      SourceState = "new"
	SourceStateActive   SourceState = "active"
	SourceStateReopened SourceState = "reopened"
	SourceStateFixed    SourceState = "fixed"
)

// AllSourceStates returns every valid source state.
func AllSourceStates() []SourceState {
	return []SourceState{SourceStateNew, SourceStateActive, SourceStateReopened, SourceStateFixed}
}

// IsValid reports whether s is a recognized source state.
func (s SourceState) IsValid() bool { return inEnum(s, AllSourceStates()) }

// VulnerabilityID is one identifier of a vulnerability, with its namespace.
// One vulnerability often has several (a CVE, a GHSA and an OSV id);
// receivers deduplicate on any shared id.
type VulnerabilityID struct {
	// Namespace (required).
	Type VulnerabilityIDType `json:"type"`

	// The identifier (required): CVE-2024-3094, GHSA-xxxx-xxxx-xxxx,
	// PYSEC-2021-1, RHSA-2024:1234.
	ID string `json:"id"`

	// Issuer of a vendor id (redhat, microsoft, ubuntu, ...).
	Source string `json:"source,omitempty"`
}

// VulnerabilityIDType is the namespace of a vulnerability id.
type VulnerabilityIDType string

const (
	VulnerabilityIDCVE    VulnerabilityIDType = "cve"
	VulnerabilityIDGHSA   VulnerabilityIDType = "ghsa"
	VulnerabilityIDOSV    VulnerabilityIDType = "osv"
	VulnerabilityIDVendor VulnerabilityIDType = "vendor"
)

// AllVulnerabilityIDTypes returns every valid vulnerability id type.
func AllVulnerabilityIDTypes() []VulnerabilityIDType {
	return []VulnerabilityIDType{VulnerabilityIDCVE, VulnerabilityIDGHSA, VulnerabilityIDOSV, VulnerabilityIDVendor}
}

// IsValid reports whether t is a recognized vulnerability id type.
func (t VulnerabilityIDType) IsValid() bool { return inEnum(t, AllVulnerabilityIDTypes()) }

// SolutionType is the kind of fix a remediation is.
type SolutionType string

const (
	SolutionTypePatch      SolutionType = "patch"
	SolutionTypeUpgrade    SolutionType = "upgrade"
	SolutionTypeConfig     SolutionType = "config"
	SolutionTypeWorkaround SolutionType = "workaround"
	SolutionTypeMitigation SolutionType = "mitigation"
	SolutionTypeNoFix      SolutionType = "no_fix"
)

// AllSolutionTypes returns every valid solution type.
func AllSolutionTypes() []SolutionType {
	return []SolutionType{SolutionTypePatch, SolutionTypeUpgrade, SolutionTypeConfig, SolutionTypeWorkaround, SolutionTypeMitigation, SolutionTypeNoFix}
}

// IsValid reports whether s is a recognized solution type.
func (s SolutionType) IsValid() bool { return inEnum(s, AllSolutionTypes()) }

// Advisory is a vendor advisory that addresses a finding.
type Advisory struct {
	// Advisory id (MS24-001, RHSA-2024:1234, DSA-5600-1).
	ID string `json:"id,omitempty"`

	// Advisory URL.
	URL string `json:"url,omitempty"`

	// Issuer (microsoft, redhat, debian, ...).
	Source string `json:"source,omitempty"`
}

// IdentityHints are what a scanner observed about a host that helps match it
// to the same host seen by another tool. Unlike AssetIdentifiers, which are
// read from the asset itself and trusted as identity, hints are remote
// observations (a NetBIOS name from a probe, a MAC from an ARP table) and a
// receiver weighs them accordingly.
type IdentityHints struct {
	// Fully qualified DNS name the scanner resolved.
	FQDN string `json:"fqdn,omitempty"`

	// NetBIOS name.
	NetBIOSName string `json:"netbios_name,omitempty"`

	// MAC addresses observed.
	MACAddresses []string `json:"mac_addresses,omitempty"`

	// CPE of the detected operating system (cpe:/o:... or cpe:2.3:o:...).
	OSCPE string `json:"os_cpe,omitempty"`

	// Cloud resource id the scanner reported (instance id, ARN).
	CloudResourceID string `json:"cloud_resource_id,omitempty"`

	// Id of the scanner's own agent installed on the host (a Nessus or
	// Qualys agent UUID). Unique per scanner, not across scanners. The Go
	// name says whose agent it is, so it is not read as a receiver's own
	// endpoint software.
	ScannerAgentID string `json:"agent_id,omitempty"`
}

func inEnum[T comparable](v T, all []T) bool {
	for _, a := range all {
		if v == a {
			return true
		}
	}
	return false
}
