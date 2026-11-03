package ctis

import (
	"slices"
	"time"
)

// Report is the root CTIS document: one producer's observations of assets and
// findings at metadata.generated_at. A document carries natural keys
// (canonical forms) and the producer's own references, never a receiver's
// database keys.
type Report struct {
	// Specification version, MAJOR.MINOR (required).
	Version string `json:"version"`

	// Schema URL for validation (optional). An identifier: receivers never
	// fetch it.
	Schema string `json:"$schema,omitempty"`

	// Report metadata (required).
	Metadata ReportMetadata `json:"metadata"`

	// The tool that produced the report.
	Tool *Tool `json:"tool,omitempty"`

	// Assets observed.
	Assets []Asset `json:"assets,omitempty"`

	// Rules and checks the findings name by rule_ref, described once.
	Rules []Rule `json:"rules,omitempty"`

	// Findings observed. Each names its asset by asset_ref.
	Findings []Finding `json:"findings,omitempty"`

	// Software components (SBOM).
	Dependencies []Dependency `json:"dependencies,omitempty"`

	// Typed relationships between assets of this report.
	Relationships []Relationship `json:"relationships,omitempty"`

	// Endpoints are the methods and paths web origins serve, as a tool saw
	// them. Names of parameters only, never values.
	Endpoints []Endpoint `json:"endpoints,omitempty"`

	// An opaque bag. Receivers MUST NOT give meaning to its keys; namespaced
	// data goes in Extensions.
	Properties Properties `json:"properties,omitempty"`

	// Namespaced producer data, keyed by a reverse-DNS namespace.
	Extensions Extensions `json:"extensions,omitempty"`
}

// ReportMetadata contains metadata about the report.
type ReportMetadata struct {
	// Producer-generated UUIDv7 that identifies this document (required). A
	// retry re-sends the same id; receivers deduplicate on (credential, id).
	// Every segment of a split result shares it. It is never a receiver's
	// key.
	ID string `json:"id"`

	// When the producer generated the report (required).
	GeneratedAt time.Time `json:"generated_at"`

	// Duration of the work in milliseconds.
	DurationMs int `json:"duration_ms,omitempty"`

	// How the data reached the document: scanner, collector, integration,
	// manual.
	Channel Channel `json:"channel,omitempty"`

	// The producer's own references for the work (a job id in the
	// producer's scheduler, a scan id in the source product).
	SourceRefs []SourceRef `json:"source_refs,omitempty"`

	// Coverage type: full, incremental, partial. Only full lets a receiver
	// call an absent item gone (with targets).
	CoverageType CoverageType `json:"coverage_type,omitempty"`

	// Branch information for git-based scans.
	Branch *BranchInfo `json:"branch,omitempty"`

	// Conformance profiles the producer claims for this document.
	Profiles []Profile `json:"profiles,omitempty"`

	// When the work that produced the report started and ended.
	StartedAt *time.Time `json:"started_at,omitempty"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`

	// How each target of the work ended. With coverage_type full, a target
	// in state done is what lets a receiver call an item gone.
	Targets []TargetOutcome `json:"targets,omitempty"`

	// Segment places this document in a result split over several
	// documents that share one metadata.id.
	Segment *Segment `json:"segment,omitempty"`

	// Opaque bag; no meaning.
	Properties Properties `json:"properties,omitempty"`

	// Namespaced producer data.
	Extensions Extensions `json:"extensions,omitempty"`
}

// Channel is how the data of a report reached the document.
type Channel string

// Channels.
const (
	ChannelScanner     Channel = "scanner"
	ChannelCollector   Channel = "collector"
	ChannelIntegration Channel = "integration"
	ChannelManual      Channel = "manual"
)

// AllChannels returns every channel.
func AllChannels() []Channel {
	return []Channel{ChannelScanner, ChannelCollector, ChannelIntegration, ChannelManual}
}

// IsValid reports whether c is a known channel.
func (c Channel) IsValid() bool { return slices.Contains(AllChannels(), c) }

// CoverageType says how much of the scope the work covered.
type CoverageType string

// Coverage types.
const (
	CoverageFull        CoverageType = "full"
	CoverageIncremental CoverageType = "incremental"
	CoveragePartial     CoverageType = "partial"
)

// AllCoverageTypes returns every coverage type.
func AllCoverageTypes() []CoverageType {
	return []CoverageType{CoverageFull, CoverageIncremental, CoveragePartial}
}

// IsValid reports whether c is a known coverage type.
func (c CoverageType) IsValid() bool { return slices.Contains(AllCoverageTypes(), c) }

// Profile is a conformance profile a producer claims for a document.
type Profile string

// Profiles.
const (
	ProfileCore          Profile = "core"
	ProfileDiscovery     Profile = "discovery"
	ProfileVulnerability Profile = "vulnerability"
	ProfileCode          Profile = "code"
	ProfileSBOM          Profile = "sbom"
	ProfileValidation    Profile = "validation"
	ProfileWeb3          Profile = "web3"
)

// AllProfiles returns every profile.
func AllProfiles() []Profile {
	return []Profile{ProfileCore, ProfileDiscovery, ProfileVulnerability, ProfileCode, ProfileSBOM, ProfileValidation, ProfileWeb3}
}

// IsValid reports whether p is a known profile.
func (p Profile) IsValid() bool { return slices.Contains(AllProfiles(), p) }

// SourceRef is a producer's own identifier of an item in its own system: a
// plugin id, a scan id, an issue key in the source product. System is an
// open token naming the system; ID is opaque. It is never a receiver's key,
// and receivers never use it as one.
type SourceRef struct {
	System string `json:"system"`
	ID     string `json:"id"`
}

// BranchInfo contains git branch context for CI/CD scans.
type BranchInfo struct {
	// Branch name ("main", "feature/xyz").
	Name string `json:"name"`

	// Whether this is the repository's default branch. Auto-resolve applies
	// only to default branch scans.
	IsDefaultBranch bool `json:"is_default_branch"`

	// Commit SHA being scanned.
	CommitSHA string `json:"commit_sha,omitempty"`

	// Base branch for pull request scans.
	BaseBranch string `json:"base_branch,omitempty"`

	// Pull request number.
	PullRequestNumber int `json:"pull_request_number,omitempty"`

	// Pull request URL (http or https).
	PullRequestURL string `json:"pull_request_url,omitempty"`

	// Repository URL (http or https).
	RepositoryURL string `json:"repository_url,omitempty"`
}

// Tool describes the tool that generated the report, or one finding.
type Tool struct {
	// Tool name (required).
	Name string `json:"name"`

	// Tool version.
	Version string `json:"version,omitempty"`

	// Tool vendor or organization.
	Vendor string `json:"vendor,omitempty"`

	// Tool information URL (http or https).
	InfoURL string `json:"info_url,omitempty"`

	// Detection techniques the tool applies. A finding may override with
	// its own technique.
	Techniques []Technique `json:"techniques,omitempty"`
}

// Technique is a detection technique: how a finding was found. It is a
// separate axis from the channel (how the data reached the document).
type Technique string

// Techniques (closed set).
const (
	TechniqueSAST      Technique = "sast"
	TechniqueSCA       Technique = "sca"
	TechniqueSecret    Technique = "secret"
	TechniqueIaC       Technique = "iac"
	TechniqueContainer Technique = "container"
	TechniqueDAST      Technique = "dast"
	TechniqueVA        Technique = "va"
	TechniqueEASM      Technique = "easm"
	TechniqueCSPM      Technique = "cspm"
	TechniqueBAS       Technique = "bas"
	TechniquePentest   Technique = "pentest"
	TechniqueManual    Technique = "manual"
)

// AllTechniques returns every technique.
func AllTechniques() []Technique {
	return []Technique{
		TechniqueSAST, TechniqueSCA, TechniqueSecret, TechniqueIaC, TechniqueContainer, TechniqueDAST,
		TechniqueVA, TechniqueEASM, TechniqueCSPM, TechniqueBAS, TechniquePentest, TechniqueManual,
	}
}

// IsValid reports whether t is a known technique.
func (t Technique) IsValid() bool { return slices.Contains(AllTechniques(), t) }

// =============================================================================
// Assets
// =============================================================================

// Asset is an observed asset. Its identity is AssetKey(type, canonical
// value); receivers compute the key and never trust a producer's.
type Asset struct {
	// Document-local reference (required): findings, relationships,
	// dependencies and endpoints name the asset by it. Never UUID-shaped,
	// never a receiver's key.
	ID string `json:"id"`

	// Asset type (required).
	Type AssetType `json:"type"`

	// The asset's value in the canonical form of its type (required):
	// "www.example.com", "192.0.2.10", "192.0.2.10:443/tcp",
	// "https://www.example.com", "github.com/org/repo".
	Value string `json:"value"`

	// Human-readable name.
	Name string `json:"name,omitempty"`

	// Description (plain text).
	Description string `json:"description,omitempty"`

	// Tags for categorization.
	Tags []string `json:"tags,omitempty"`

	// Business criticality: critical, high, medium, low.
	Criticality Criticality `json:"criticality,omitempty"`

	// How sure the producer is about the asset, 0-100.
	Confidence int `json:"confidence,omitempty"`

	// When the producer first and last observed the asset.
	FirstSeenAt *time.Time `json:"first_seen_at,omitempty"`
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`

	// Type-specific technical details.
	Technical *AssetTechnical `json:"technical,omitempty"`

	// Compliance context.
	Compliance *AssetCompliance `json:"compliance,omitempty"`

	// Whether the asset is reachable from the internet. Absent means
	// unknown; false means verified not reachable.
	IsInternetAccessible *bool `json:"is_internet_accessible,omitempty"`

	// Stable identifiers read from the asset itself.
	Identifiers *AssetIdentifiers `json:"identifiers,omitempty"`

	// Remote observations that help match the asset across tools.
	IdentityHints *IdentityHints `json:"identity_hints,omitempty"`

	// Technologies the asset runs.
	Technologies []Technology `json:"technologies,omitempty"`

	// Deployment environment.
	Environment Environment `json:"environment,omitempty"`

	// Who owns the asset. The refs are personal data.
	Owners []AssetOwner `json:"owners,omitempty"`

	// State of the asset. gone only on an authoritative signal, named by
	// StateReason.
	State       AssetState       `json:"state,omitempty"`
	StateReason AssetStateReason `json:"state_reason,omitempty"`

	// The producer's own identifiers of the asset in its own systems.
	SourceRefs []SourceRef `json:"source_refs,omitempty"`

	// Opaque bag; no meaning.
	Properties Properties `json:"properties,omitempty"`

	// Namespaced producer data.
	Extensions Extensions `json:"extensions,omitempty"`
}

// AssetIdentifiers holds identifiers that stay the same when an asset is
// renamed or readdressed, read from the asset itself. In order of trust:
// MachineID, CloudResourceID, BIOSUUID then SerialNumber, MACAddresses.
// SCMRepoID identifies a repository. They are the asset's own identifiers,
// never a receiver's keys.
type AssetIdentifiers struct {
	// Host ID read on the host: /etc/machine-id, MachineGuid,
	// IOPlatformUUID.
	MachineID string `json:"machine_id,omitempty"`

	// Cloud instance ID, VM ID or resource ARN.
	CloudResourceID string `json:"cloud_resource_id,omitempty"`

	// SMBIOS system UUID.
	BIOSUUID string `json:"bios_uuid,omitempty"`

	// Hardware serial number.
	SerialNumber string `json:"serial_number,omitempty"`

	// MAC addresses of the host's interfaces.
	MACAddresses []string `json:"mac_addresses,omitempty"`

	// Repository ID assigned by the source-code host. It survives renames.
	SCMRepoID string `json:"scm_repo_id,omitempty"`
}

// AssetCompliance contains compliance context for an asset.
type AssetCompliance struct {
	// Compliance frameworks the asset is in scope for, from the framework
	// registry (ComplianceFramework).
	Frameworks []ComplianceFramework `json:"frameworks,omitempty"`

	// Data classification: public, internal, confidential, restricted.
	DataClassification DataClassification `json:"data_classification,omitempty"`

	// The asset holds personally identifiable information.
	HasPII bool `json:"has_pii,omitempty"`

	// The asset holds protected health information.
	HasPHI bool `json:"has_phi,omitempty"`
}

// DataClassification is a data classification level.
type DataClassification string

// Data classification levels.
const (
	DataPublic       DataClassification = "public"
	DataInternal     DataClassification = "internal"
	DataConfidential DataClassification = "confidential"
	DataRestricted   DataClassification = "restricted"
)

// AllDataClassifications returns every data classification level.
func AllDataClassifications() []DataClassification {
	return []DataClassification{DataPublic, DataInternal, DataConfidential, DataRestricted}
}

// IsValid reports whether d is a known data classification.
func (d DataClassification) IsValid() bool { return slices.Contains(AllDataClassifications(), d) }

// AssetTechnical contains type-specific technical details. Set the member
// that matches the asset type.
type AssetTechnical struct {
	// For domain_name assets.
	Domain *DomainTechnical `json:"domain,omitempty"`

	// For ip_address assets.
	IPAddress *IPAddressTechnical `json:"ip_address,omitempty"`

	// For repository assets.
	Repository *RepositoryTechnical `json:"repository,omitempty"`

	// For certificate assets.
	Certificate *CertificateTechnical `json:"certificate,omitempty"`

	// For cloud assets.
	Cloud *CloudTechnical `json:"cloud,omitempty"`

	// For service assets.
	Service *ServiceTechnical `json:"service,omitempty"`

	// For web_origin assets.
	HTTP *HTTPTechnical `json:"http,omitempty"`

	// For identity assets.
	Identity *IdentityTechnical `json:"identity,omitempty"`

	// For web3 assets (web3 profile).
	Web3 *Web3Technical `json:"web3,omitempty"`
}

// DomainTechnical contains domain-specific technical details.
type DomainTechnical struct {
	// Registrar.
	Registrar string `json:"registrar,omitempty"`

	// Registration and expiry times.
	RegisteredAt *time.Time `json:"registered_at,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`

	// Nameservers (canonical domain names).
	Nameservers []string `json:"nameservers,omitempty"`

	// DNS records.
	DNSRecords []DNSRecord `json:"dns_records,omitempty"`

	// WHOIS data, as key/value strings.
	WHOIS map[string]string `json:"whois,omitempty"`
}

// DNSRecord represents a DNS record. Type is the RR type verbatim (A, AAAA,
// CNAME, MX, TXT ...); TTL is in seconds.
type DNSRecord struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   int    `json:"ttl,omitempty"`
}

// IPAddressTechnical contains IP address-specific technical details. Open
// ports are service assets linked by exposes.
type IPAddressTechnical struct {
	// IP version: 4 or 6.
	Version int `json:"version,omitempty"`

	// Hostname (if resolved).
	Hostname string `json:"hostname,omitempty"`

	// Autonomous system number and organization.
	ASN    int    `json:"asn,omitempty"`
	ASNOrg string `json:"asn_org,omitempty"`

	// ISO 3166-1 alpha-2 country code.
	Country string `json:"country,omitempty"`

	// City.
	City string `json:"city,omitempty"`

	// Geolocation.
	Geolocation *Geolocation `json:"geolocation,omitempty"`
}

// Geolocation contains geographic coordinates; accuracy is in meters.
type Geolocation struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Accuracy  float64 `json:"accuracy,omitempty"`
}

// RepositoryTechnical contains repository-specific technical details.
type RepositoryTechnical struct {
	// Source-code host: an open token (github, gitlab, bitbucket).
	Platform string `json:"platform,omitempty"`

	// Organization or owner path.
	Owner string `json:"owner,omitempty"`

	// Repository name.
	Name string `json:"name,omitempty"`

	// Default branch.
	DefaultBranch string `json:"default_branch,omitempty"`

	// Visibility: public, private, internal.
	Visibility string `json:"visibility,omitempty"`

	// Repository web URL (http or https).
	URL string `json:"url,omitempty"`

	// Bytes per language.
	Languages map[string]int `json:"languages,omitempty"`

	// Stars and forks.
	Stars int `json:"stars,omitempty"`
	Forks int `json:"forks,omitempty"`

	// Last commit.
	LastCommitSHA string     `json:"last_commit_sha,omitempty"`
	LastCommitAt  *time.Time `json:"last_commit_at,omitempty"`
}

// CertificateTechnical contains certificate details. The asset value is the
// SHA-256 fingerprint of the DER.
type CertificateTechnical struct {
	SerialNumber       string     `json:"serial_number,omitempty"`
	SubjectCN          string     `json:"subject_cn,omitempty"`
	SubjectAltNames    []string   `json:"subject_alt_names,omitempty"`
	IssuerCN           string     `json:"issuer_cn,omitempty"`
	IssuerOrg          string     `json:"issuer_org,omitempty"`
	NotBefore          *time.Time `json:"not_before,omitempty"`
	NotAfter           *time.Time `json:"not_after,omitempty"`
	SignatureAlgorithm string     `json:"signature_algorithm,omitempty"`
	KeyAlgorithm       string     `json:"key_algorithm,omitempty"`
	KeySize            int        `json:"key_size,omitempty"` // bits

	// SHA-256 of the DER, lowercase hex.
	SHA256Fingerprint string `json:"sha256_fingerprint,omitempty"`

	IsSelfSigned bool `json:"is_self_signed,omitempty"`
	IsWildcard   bool `json:"is_wildcard,omitempty"`
}

// CloudTechnical contains cloud resource details.
type CloudTechnical struct {
	// Provider: an open token (aws, azure, gcp, oci, alibaba).
	Provider string `json:"provider,omitempty"`

	// Account, subscription or project.
	AccountID string `json:"account_id,omitempty"`

	Region       string `json:"region,omitempty"`
	Zone         string `json:"zone,omitempty"`
	ResourceType string `json:"resource_type,omitempty"`
	ResourceID   string `json:"resource_id,omitempty"`
	ARN          string `json:"arn,omitempty"`

	// Resource tags.
	Tags map[string]string `json:"tags,omitempty"`
}

// ServiceTechnical is the one shape of a network service: the technical
// details of a service asset (value host:port/transport), linked from its
// host or address by an exposes relationship.
type ServiceTechnical struct {
	// Port number (required).
	Port int `json:"port"`

	// Transport (required): tcp, udp, sctp.
	Transport Transport `json:"transport"`

	// Application protocol, an IANA service name (http, https, ssh, smtp,
	// domain, ldap, microsoft-ds, mysql ...).
	AppProtocol string `json:"app_protocol,omitempty"`

	// Port state: open, closed, filtered.
	State PortState `json:"state,omitempty"`

	// Product and version ("OpenSSH" "9.6").
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`

	// CPE 2.3 name.
	CPE string `json:"cpe,omitempty"`

	// Banner and extra information as the probe saw them (plain text).
	Banner    string `json:"banner,omitempty"`
	ExtraInfo string `json:"extra_info,omitempty"`

	// TLS.
	IsTLS      bool       `json:"is_tls,omitempty"`
	TLSVersion TLSVersion `json:"tls_version,omitempty"`

	// Authentication.
	IsAuthRequired        bool     `json:"is_auth_required,omitempty"`
	AuthMethods           []string `json:"auth_methods,omitempty"`
	HasDefaultCredentials bool     `json:"has_default_credentials,omitempty"`
	HasAnonymousAccess    bool     `json:"has_anonymous_access,omitempty"`

	// Response time in milliseconds.
	ResponseTimeMs int `json:"response_time_ms,omitempty"`

	// Protocol-dependent details, as strings (SSH algorithms, SMTP
	// extensions).
	Details map[string]string `json:"details,omitempty"`
}

// Transport is a transport protocol.
type Transport string

// Transports.
const (
	TransportTCP  Transport = "tcp"
	TransportUDP  Transport = "udp"
	TransportSCTP Transport = "sctp"
)

// AllTransports returns every transport.
func AllTransports() []Transport { return []Transport{TransportTCP, TransportUDP, TransportSCTP} }

// IsValid reports whether t is a known transport.
func (t Transport) IsValid() bool { return slices.Contains(AllTransports(), t) }

// PortState is the state of a port.
type PortState string

// Port states.
const (
	PortOpen     PortState = "open"
	PortClosed   PortState = "closed"
	PortFiltered PortState = "filtered"
)

// AllPortStates returns every port state.
func AllPortStates() []PortState { return []PortState{PortOpen, PortClosed, PortFiltered} }

// IsValid reports whether s is a known port state.
func (s PortState) IsValid() bool { return slices.Contains(AllPortStates(), s) }

// TLSVersion is a TLS or SSL protocol version.
type TLSVersion string

// TLS versions.
const (
	TLSVersionSSL3  TLSVersion = "ssl3"
	TLSVersionTLS10 TLSVersion = "tls1.0"
	TLSVersionTLS11 TLSVersion = "tls1.1"
	TLSVersionTLS12 TLSVersion = "tls1.2"
	TLSVersionTLS13 TLSVersion = "tls1.3"
)

// AllTLSVersions returns every TLS version.
func AllTLSVersions() []TLSVersion {
	return []TLSVersion{TLSVersionSSL3, TLSVersionTLS10, TLSVersionTLS11, TLSVersionTLS12, TLSVersionTLS13}
}

// IsValid reports whether v is a known TLS version.
func (v TLSVersion) IsValid() bool { return slices.Contains(AllTLSVersions(), v) }

// HTTPTechnical is what a probe saw on a web origin.
type HTTPTechnical struct {
	// Status code of the probe's response.
	StatusCode int `json:"status_code,omitempty"`

	// Page title and server header (plain text).
	Title     string `json:"title,omitempty"`
	WebServer string `json:"web_server,omitempty"`

	// Content type of the response.
	ContentType string `json:"content_type,omitempty"`

	// TLS version the origin negotiated (https origins).
	TLSVersion TLSVersion `json:"tls_version,omitempty"`

	// Where the origin redirects to (http or https URL).
	RedirectURL string `json:"redirect_url,omitempty"`

	// Content delivery network and web application firewall in front of
	// the origin, as open tokens (cloudflare, akamai).
	CDN string `json:"cdn,omitempty"`
	WAF string `json:"waf,omitempty"`

	// TLS server fingerprints (JARM) and the favicon hash (MurmurHash3 of
	// the base64 body), as the probe computed them.
	JARM        string `json:"jarm,omitempty"`
	FaviconMMH3 string `json:"favicon_mmh3,omitempty"`

	// Security response headers the origin sets.
	SecurityHeaders *SecurityHeaders `json:"security_headers,omitempty"`
}

// SecurityHeaders is the security posture of a web origin's response
// headers. Each value is the header as received (bounded), absent when the
// origin does not send it.
type SecurityHeaders struct {
	StrictTransportSecurity string `json:"strict_transport_security,omitempty"`
	ContentSecurityPolicy   string `json:"content_security_policy,omitempty"`
	XFrameOptions           string `json:"x_frame_options,omitempty"`
	XContentTypeOptions     string `json:"x_content_type_options,omitempty"`
	ReferrerPolicy          string `json:"referrer_policy,omitempty"`
	PermissionsPolicy       string `json:"permissions_policy,omitempty"`

	// CORS response headers.
	AccessControlAllowOrigin      string `json:"access_control_allow_origin,omitempty"`
	AccessControlAllowCredentials string `json:"access_control_allow_credentials,omitempty"`

	// The cookies the origin sets: names and flags, never values.
	Cookies []CookieFlags `json:"cookies,omitempty"`
}

// CookieFlags is what a Set-Cookie header says about a cookie, without its
// value.
type CookieFlags struct {
	Name         string `json:"name"`
	IsSecure     bool   `json:"is_secure,omitempty"`
	IsHTTPOnly   bool   `json:"is_http_only,omitempty"`
	IsPersistent bool   `json:"is_persistent,omitempty"`
	// SameSite: strict, lax, none.
	SameSite string `json:"same_site,omitempty"`
}

// IdentityTechnical describes an identity asset.
type IdentityTechnical struct {
	// Kind (required): user, service_account, role, group, workload.
	Kind IdentityKind `json:"kind"`

	// Identity provider: an open token (aws, azure, gcp, okta, ldap).
	Provider string `json:"provider,omitempty"`
}

// IdentityKind is the kind of an identity.
type IdentityKind string

// Identity kinds.
const (
	IdentityUser           IdentityKind = "user"
	IdentityServiceAccount IdentityKind = "service_account"
	IdentityRole           IdentityKind = "role"
	IdentityGroup          IdentityKind = "group"
	IdentityWorkload       IdentityKind = "workload"
)

// AllIdentityKinds returns every identity kind.
func AllIdentityKinds() []IdentityKind {
	return []IdentityKind{IdentityUser, IdentityServiceAccount, IdentityRole, IdentityGroup, IdentityWorkload}
}

// IsValid reports whether k is a known identity kind.
func (k IdentityKind) IsValid() bool { return slices.Contains(AllIdentityKinds(), k) }

// =============================================================================
// Findings
// =============================================================================

// Finding is a security finding on one asset of the report.
type Finding struct {
	// Document-local reference. Never UUID-shaped, never a receiver's key.
	ID string `json:"id,omitempty"`

	// Finding type (required).
	Type FindingType `json:"type"`

	// Short title (required, plain text).
	Title string `json:"title"`

	// Detailed description (plain text).
	Description string `json:"description,omitempty"`

	// Primary message (plain text), distinct from title and description.
	Message string `json:"message,omitempty"`

	// Severity (required).
	Severity Severity `json:"severity"`

	// How sure the producer is, 0-100.
	Confidence int `json:"confidence,omitempty"`

	// Finding category.
	Category string `json:"category,omitempty"`

	// Vulnerability classes ("SQL Injection", "XSS").
	VulnerabilityClasses []string `json:"vulnerability_classes,omitempty"`

	// Subcategories ("audit", "vuln", "secure default").
	Subcategories []string `json:"subcategories,omitempty"`

	// Rule or check that detected the finding.
	RuleID   string `json:"rule_id,omitempty"`
	RuleName string `json:"rule_name,omitempty"`

	// The rule of this report's rules[] that detected the finding. When
	// set, rule_id is required and equals the rule's rule_id.
	RuleRef string `json:"rule_ref,omitempty"`

	// The asset of this report the finding is on (required).
	AssetRef string `json:"asset_ref"`

	// Code location.
	Location *FindingLocation `json:"location,omitempty"`

	// Network location: the host, port and protocol the finding was
	// observed on.
	Network *NetworkLocation `json:"network,omitempty"`

	// Where on a web origin the finding was observed.
	Web *WebLocation `json:"web,omitempty"`

	// Type-specific details.
	Vulnerability    *VulnerabilityDetails    `json:"vulnerability,omitempty"`
	Secret           *SecretDetails           `json:"secret,omitempty"`
	Misconfiguration *MisconfigurationDetails `json:"misconfiguration,omitempty"`
	Compliance       *ComplianceDetails       `json:"compliance,omitempty"`

	// Web3 details (web3 profile) on a vulnerability or weakness finding.
	Web3 *Web3VulnerabilityDetails `json:"web3,omitempty"`

	// Remediation guidance.
	Remediation *Remediation `json:"remediation,omitempty"`

	// References (http or https URLs). Receivers never fetch them.
	References []string `json:"references,omitempty"`

	// Tags.
	Tags []string `json:"tags,omitempty"`

	// The producer's fingerprint (recipe ctis-fp/2). Receivers recompute
	// it and never trust it as a key.
	Fingerprint string `json:"fingerprint,omitempty"`

	// Contributing identity components (SARIF partialFingerprints).
	PartialFingerprints map[string]string `json:"partial_fingerprints,omitempty"`

	// Groups logically identical results across runs (SARIF
	// correlationGuid), the producer's own.
	CorrelationID string `json:"correlation_id,omitempty"`

	// Status relative to the producer's previous run (SARIF baselineState):
	// new, unchanged, updated, absent.
	BaselineState string `json:"baseline_state,omitempty"`

	// Evaluation state (SARIF kind): not_applicable, pass, fail, review,
	// open, informational. A compliance result is a kind.
	Kind string `json:"kind,omitempty"`

	// Priority 0-100 (SARIF rank).
	Rank float64 `json:"rank,omitempty"`

	// How often the result was observed (SARIF occurrenceCount).
	OccurrenceCount int `json:"occurrence_count,omitempty"`

	// SARIF relatedLocations, stacks, attachments, workItemUris,
	// hostedViewerUri.
	RelatedLocations []*FindingLocation `json:"related_locations,omitempty"`
	Stacks           []*StackTrace      `json:"stacks,omitempty"`
	Attachments      []*Attachment      `json:"attachments,omitempty"`
	WorkItemURIs     []string           `json:"work_item_uris,omitempty"`
	HostedViewerURI  string             `json:"hosted_viewer_uri,omitempty"`

	// When the producer first and last observed the finding.
	FirstSeenAt *time.Time `json:"first_seen_at,omitempty"`
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`

	// Status hint from the producer.
	Status FindingStatus `json:"status,omitempty"`

	// Taint trace (source to sink).
	DataFlow *DataFlow `json:"data_flow,omitempty"`

	// Suppression (SARIF suppressions).
	Suppression *Suppression `json:"suppression,omitempty"`

	// Exposure of the finding.
	Exposure *FindingExposure `json:"exposure,omitempty"`

	// The finding as the source tool names it.
	Native *NativeIdentity `json:"native,omitempty"`

	// Every score of the finding with its source and date: CVSS (each
	// version), EPSS, SSVC, vendor ratings.
	Scores []Score `json:"scores,omitempty"`

	// Exploitability statement (VEX).
	VEX *VEX `json:"vex,omitempty"`

	// The finding's history as the source tracks it.
	SourceLifecycle *SourceLifecycle `json:"source_lifecycle,omitempty"`

	// Source fields no CTIS member holds, as strings. Bounded: at most 64
	// entries, keys of 128 and values of 4096 bytes, 32 KiB in all. Use
	// SetSourceExtra.
	SourceExtra map[string]string `json:"source_extra,omitempty"`

	// MITRE ATT&CK technique ids the finding enables ("T1190"), at most 20.
	AttackTechniqueIDs []string `json:"attack_technique_ids,omitempty"`

	// CAPEC attack pattern ids ("CAPEC-66").
	CAPECIDs []string `json:"capec_ids,omitempty"`

	// Typed evidence (at most 20): HTTP exchanges, raw text, command
	// output, file excerpts, artifacts. Sensitive values only inside spans
	// marked in their sensitive list.
	EvidenceItems []EvidenceItem `json:"evidence_items,omitempty"`

	// Overrides the report's tool for this finding.
	Tool *Tool `json:"tool,omitempty"`

	// Overrides the tool's techniques for this finding.
	Technique Technique `json:"technique,omitempty"`

	// Whether and how the finding was shown to be exploitable.
	Validation *FindingValidation `json:"validation,omitempty"`

	// The dependency of this report the finding affects.
	DependencyRef string `json:"dependency_ref,omitempty"`

	// The producer's own identifiers of the finding in its own systems.
	SourceRefs []SourceRef `json:"source_refs,omitempty"`

	// Opaque bag; no meaning.
	Properties Properties `json:"properties,omitempty"`

	// Namespaced producer data.
	Extensions Extensions `json:"extensions,omitempty"`
}

// FindingExposure contains exposure information for a finding.
type FindingExposure struct {
	// Attack vector (CVSS AV vocabulary): network, adjacent, local,
	// physical.
	Vector ExposureVector `json:"vector,omitempty"`

	// Reachability. Absent means unknown; false means verified not
	// reachable.
	IsNetworkAccessible  *bool `json:"is_network_accessible,omitempty"`
	IsInternetAccessible *bool `json:"is_internet_accessible,omitempty"`

	// Prerequisites for exploitation (plain text).
	AttackPrerequisites string `json:"attack_prerequisites,omitempty"`
}

// ExposureVector is an attack vector in the CVSS AV vocabulary.
type ExposureVector string

// Exposure vectors.
const (
	VectorNetwork  ExposureVector = "network"
	VectorAdjacent ExposureVector = "adjacent"
	VectorLocal    ExposureVector = "local"
	VectorPhysical ExposureVector = "physical"
)

// AllExposureVectors returns every exposure vector.
func AllExposureVectors() []ExposureVector {
	return []ExposureVector{VectorNetwork, VectorAdjacent, VectorLocal, VectorPhysical}
}

// IsValid reports whether v is a known exposure vector.
func (v ExposureVector) IsValid() bool { return slices.Contains(AllExposureVectors(), v) }

// FindingStatus represents the status of a finding.
type FindingStatus string

// Finding statuses.
const (
	FindingStatusOpen          FindingStatus = "open"
	FindingStatusResolved      FindingStatus = "resolved"
	FindingStatusSuppressed    FindingStatus = "suppressed"
	FindingStatusFalsePositive FindingStatus = "false_positive"
	FindingStatusAcceptedRisk  FindingStatus = "accepted_risk"
	FindingStatusInProgress    FindingStatus = "in_progress"
)

// AllFindingStatuses returns every valid finding status.
func AllFindingStatuses() []FindingStatus {
	return []FindingStatus{
		FindingStatusOpen,
		FindingStatusResolved,
		FindingStatusSuppressed,
		FindingStatusFalsePositive,
		FindingStatusAcceptedRisk,
		FindingStatusInProgress,
	}
}

// IsValid reports whether s is a recognized finding status.
func (s FindingStatus) IsValid() bool { return slices.Contains(AllFindingStatuses(), s) }

// StackTrace represents a call stack trace (SARIF stack).
type StackTrace struct {
	Message string        `json:"message,omitempty"`
	Frames  []*StackFrame `json:"frames,omitempty"`
}

// StackFrame represents a single frame in a call stack.
type StackFrame struct {
	Location   *FindingLocation `json:"location,omitempty"`
	Module     string           `json:"module,omitempty"`
	ThreadID   int              `json:"thread_id,omitempty"`
	Parameters []string         `json:"parameters,omitempty"`
}

// Attachment represents an artifact or evidence attachment (SARIF
// attachment).
type Attachment struct {
	Description      string             `json:"description,omitempty"`
	ArtifactLocation *ArtifactLocation  `json:"artifact_location,omitempty"`
	Regions          []*FindingLocation `json:"regions,omitempty"`
}

// ArtifactLocation represents the location of an artifact.
type ArtifactLocation struct {
	URI       string `json:"uri,omitempty"`
	URIBaseID string `json:"uri_base_id,omitempty"`
	Index     int    `json:"index,omitempty"`
}

// Suppression contains information about finding suppression (SARIF).
type Suppression struct {
	// Suppression kind: in_source, external.
	Kind string `json:"kind,omitempty"`

	// Suppression status: accepted, under_review, rejected.
	Status string `json:"status,omitempty"`

	// Short reason code ("false_positive", "test_code", "risk_accepted").
	Reason string `json:"reason,omitempty"`

	// Justification (plain text).
	Justification string `json:"justification,omitempty"`

	// Who suppressed the finding (personal data).
	SuppressedBy string `json:"suppressed_by,omitempty"`

	SuppressedAt *time.Time `json:"suppressed_at,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

// FindingLocation contains location information for code-based findings.
type FindingLocation struct {
	// File path, case kept.
	Path string `json:"path,omitempty"`

	StartLine   int `json:"start_line,omitempty"`
	EndLine     int `json:"end_line,omitempty"`
	StartColumn int `json:"start_column,omitempty"`
	EndColumn   int `json:"end_column,omitempty"`

	// Code snippet.
	Snippet string `json:"snippet,omitempty"`

	// Branch name.
	Branch string `json:"branch,omitempty"`

	// The commit that introduced the finding. Author fields are personal
	// data.
	Commit *CommitInfo `json:"commit,omitempty"`

	// Logical location (function, class, method).
	LogicalLocation *LogicalLocation `json:"logical_location,omitempty"`

	// Surrounding code and the line it starts at.
	ContextSnippet   string `json:"context_snippet,omitempty"`
	ContextStartLine int    `json:"context_start_line,omitempty"`
}

// CommitInfo is a commit of a repository. Author and AuthorEmail are
// personal data; producers SHOULD omit AuthorEmail unless asked to send it.
type CommitInfo struct {
	SHA         string     `json:"sha,omitempty"`
	Author      string     `json:"author,omitempty"`
	AuthorEmail string     `json:"author_email,omitempty"`
	CommittedAt *time.Time `json:"committed_at,omitempty"`
}

// NetworkLocation describes where a network finding was observed.
type NetworkLocation struct {
	// Host (canonical IP or domain name). Optional when the finding's
	// asset already is the host.
	Host string `json:"host,omitempty"`

	// Port (0: not port-specific).
	Port int `json:"port,omitempty"`

	// Transport: tcp, udp, sctp.
	Transport Transport `json:"transport,omitempty"`

	// Application protocol, an IANA service name.
	AppProtocol string `json:"app_protocol,omitempty"`
}

// LogicalLocation represents a logical code location.
type LogicalLocation struct {
	FullyQualifiedName string `json:"fully_qualified_name,omitempty"`
	Name               string `json:"name,omitempty"`
	// Kind: function, method, class, module, namespace.
	Kind        string `json:"kind,omitempty"`
	ParentIndex int    `json:"parent_index,omitempty"`
}

// VulnerabilityDetails contains vulnerability-specific details.
type VulnerabilityDetails struct {
	// Every id of the vulnerability with its namespace: CVE, GHSA, OSV,
	// vendor (with source).
	IDs []VulnerabilityID `json:"ids,omitempty"`

	// CWE ids ("CWE-79").
	CWEIDs []string `json:"cwe_ids,omitempty"`

	// OWASP Top 10 ids ("A01:2021").
	OWASPIDs []string `json:"owasp_ids,omitempty"`

	// Affected package name, its purl and the installed version.
	PackageName      string `json:"package_name,omitempty"`
	PURL             string `json:"purl,omitempty"`
	InstalledVersion string `json:"installed_version,omitempty"`

	// Affected version range as the source states it.
	AffectedVersionRange string `json:"affected_version_range,omitempty"`

	// Versions that fix the vulnerability.
	FixedVersions []string `json:"fixed_versions,omitempty"`

	// Advisory publication and last modification.
	PublishedAt *time.Time `json:"published_at,omitempty"`
	ModifiedAt  *time.Time `json:"modified_at,omitempty"`

	// Affected CPE.
	CPE string `json:"cpe,omitempty"`

	// Direct dependency (not transitive), and the path for a transitive
	// one.
	IsDirect       bool     `json:"is_direct,omitempty"`
	DependencyPath []string `json:"dependency_path,omitempty"`

	// Vulnerability database the producer matched against.
	DataSource *VulnDataSource `json:"data_source,omitempty"`

	// Container layer where the package was found.
	Layer *ContainerLayer `json:"layer,omitempty"`

	// Threat assertions made by a named source at a date: KEV listing,
	// exploitation in the wild, public exploit. Receivers SHOULD prefer
	// their own intelligence.
	ThreatSignals []ThreatSignal `json:"threat_signals,omitempty"`
}

// VulnDataSource contains information about the vulnerability data source.
type VulnDataSource struct {
	// Open token ("nvd", "ghsa", "osv").
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	// http or https URL.
	URL string `json:"url,omitempty"`
}

// ContainerLayer identifies a container image layer.
type ContainerLayer struct {
	Digest string `json:"digest,omitempty"`
	DiffID string `json:"diff_id,omitempty"`
}

// SecretDetails contains secret-specific details. No usable secret value is
// ever carried: masked_value only.
type SecretDetails struct {
	// Secret type: api_key, password, token, certificate, private_key ...
	Type string `json:"type,omitempty"`

	// Service the secret belongs to: an open token (aws, github, stripe).
	Service string `json:"service,omitempty"`

	// Masked value (first and last few characters at most).
	MaskedValue string `json:"masked_value,omitempty"`

	// Length and entropy of the secret.
	Length  int     `json:"length,omitempty"`
	Entropy float64 `json:"entropy,omitempty"`

	// Verification result. Absent means not verified.
	IsValid    *bool      `json:"is_valid,omitempty"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`

	IsRevoked bool       `json:"is_revoked,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`

	// Scopes or permissions of the secret.
	Scopes []string `json:"scopes,omitempty"`

	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	AgeDays       int        `json:"age_days,omitempty"`
	RotationDueAt *time.Time `json:"rotation_due_at,omitempty"`

	// The secret is only in history, not at HEAD, and the number of commits
	// it appears in.
	IsHistoryOnly bool `json:"is_history_only,omitempty"`
	CommitCount   int  `json:"commit_count,omitempty"`
}

// MisconfigurationDetails contains misconfiguration-specific details.
type MisconfigurationDetails struct {
	PolicyID     string `json:"policy_id,omitempty"`
	PolicyName   string `json:"policy_name,omitempty"`
	ResourceType string `json:"resource_type,omitempty"`
	ResourceName string `json:"resource_name,omitempty"`
	// Provider: an open token (aws, azure, gcp, kubernetes).
	Provider  string `json:"provider,omitempty"`
	Service   string `json:"service,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Query     string `json:"query,omitempty"`
	Expected  string `json:"expected,omitempty"`
	Actual    string `json:"actual,omitempty"`
	Cause     string `json:"cause,omitempty"`
}

// ComplianceDetails names the control a compliance finding evaluates. The
// result is the finding's kind (pass, fail, review, not_applicable).
type ComplianceDetails struct {
	// Framework from the registry (ComplianceFramework).
	Framework        ComplianceFramework `json:"framework,omitempty"`
	FrameworkVersion string              `json:"framework_version,omitempty"`

	ControlID          string `json:"control_id,omitempty"`
	ControlName        string `json:"control_name,omitempty"`
	ControlDescription string `json:"control_description,omitempty"`
}

// ComplianceFramework is a compliance framework, an open token with a
// registry of known values (the constants).
type ComplianceFramework string

// Registered compliance frameworks.
const (
	FrameworkPCIDSS    ComplianceFramework = "pci_dss"
	FrameworkHIPAA     ComplianceFramework = "hipaa"
	FrameworkSOC2      ComplianceFramework = "soc2"
	FrameworkISO27001  ComplianceFramework = "iso27001"
	FrameworkNISTCSF   ComplianceFramework = "nist_csf"
	FrameworkNIST80053 ComplianceFramework = "nist_800_53"
	FrameworkCIS       ComplianceFramework = "cis"
	FrameworkGDPR      ComplianceFramework = "gdpr"
	FrameworkFedRAMP   ComplianceFramework = "fedramp"
	FrameworkOWASPASVS ComplianceFramework = "owasp_asvs"
)

// AllComplianceFrameworks returns the registered frameworks.
func AllComplianceFrameworks() []ComplianceFramework {
	return []ComplianceFramework{
		FrameworkPCIDSS, FrameworkHIPAA, FrameworkSOC2, FrameworkISO27001, FrameworkNISTCSF,
		FrameworkNIST80053, FrameworkCIS, FrameworkGDPR, FrameworkFedRAMP, FrameworkOWASPASVS,
	}
}

// IsValid reports whether f is a registered framework. Validate accepts any
// open token.
func (f ComplianceFramework) IsValid() bool { return slices.Contains(AllComplianceFrameworks(), f) }

// Remediation is the one remediation object of a finding.
type Remediation struct {
	// Short recommendation (plain text).
	Recommendation string `json:"recommendation,omitempty"`

	// Fix steps.
	Steps []string `json:"steps,omitempty"`

	// Kind of fix (CSAF remediation categories plus config_change and
	// upgrade).
	SolutionType SolutionType `json:"solution_type,omitempty"`

	// Effort: trivial, low, medium, high.
	Effort Effort `json:"effort,omitempty"`

	// Estimated time to fix in minutes.
	EstimatedMinutes int `json:"estimated_minutes,omitempty"`

	// A fix exists. Absent means unknown; false means verified no fix.
	IsFixAvailable *bool `json:"is_fix_available,omitempty"`

	// The tool can apply the fix itself.
	IsAutoFixable bool `json:"is_auto_fixable,omitempty"`

	// Replacement code, and a regex fix.
	FixCode  string    `json:"fix_code,omitempty"`
	FixRegex *FixRegex `json:"fix_regex,omitempty"`

	// When the vendor published the patch.
	PatchPublishedAt *time.Time `json:"patch_published_at,omitempty"`

	// Vendor advisories that address the finding.
	Advisories []Advisory `json:"advisories,omitempty"`
}

// Effort is the effort of a fix.
type Effort string

// Efforts.
const (
	EffortTrivial Effort = "trivial"
	EffortLow     Effort = "low"
	EffortMedium  Effort = "medium"
	EffortHigh    Effort = "high"
)

// AllEfforts returns every effort.
func AllEfforts() []Effort { return []Effort{EffortTrivial, EffortLow, EffortMedium, EffortHigh} }

// IsValid reports whether e is a known effort.
func (e Effort) IsValid() bool { return slices.Contains(AllEfforts(), e) }

// FixRegex contains regex-based auto-fix information.
type FixRegex struct {
	Regex       string `json:"regex,omitempty"`
	Replacement string `json:"replacement,omitempty"`
	// Number of replacements (0: all).
	Count int `json:"count,omitempty"`
}

// =============================================================================
// Enums and value objects
// =============================================================================

// AssetType is the type of an asset. Each type has one canonical value form
// (spec section "Assets").
type AssetType string

// Asset types.
const (
	// Discovery / external attack surface.
	AssetTypeDomainName       AssetType = "domain_name"       // DNS name; the apex is derived
	AssetTypeIPAddress        AssetType = "ip_address"        // IPv4 or IPv6 address
	AssetTypeIPRange          AssetType = "ip_range"          // CIDR block
	AssetTypeCertificate      AssetType = "certificate"       // X.509 certificate (SHA-256 of DER)
	AssetTypeAutonomousSystem AssetType = "autonomous_system" // BGP autonomous system ("AS64500")

	// Applications and services.
	AssetTypeWebOrigin       AssetType = "web_origin"       // scheme://host[:port]
	AssetTypeWebApplication  AssetType = "web_application"  // a web application behind one or more origins
	AssetTypeAPI             AssetType = "api"              // an API (REST, GraphQL, gRPC)
	AssetTypeMobileApp       AssetType = "mobile_app"       // mobile application (bundle id)
	AssetTypeSaaSApplication AssetType = "saas_application" // SaaS application tenant
	AssetTypeService         AssetType = "service"          // host:port/transport

	// Code and artifacts.
	AssetTypeRepository     AssetType = "repository"      // host/owner/name
	AssetTypePackage        AssetType = "package"         // versionless purl
	AssetTypeContainerImage AssetType = "container_image" // registry/repository@sha256:digest
	AssetTypeAIModel        AssetType = "ai_model"        // machine learning model

	// Cloud.
	AssetTypeCloudAccount      AssetType = "cloud_account"      // account, subscription, project
	AssetTypeCloudResource     AssetType = "cloud_resource"     // resource by provider id
	AssetTypeStorage           AssetType = "storage"            // object storage bucket or container
	AssetTypeDatabase          AssetType = "database"           // managed database
	AssetTypeServerless        AssetType = "serverless"         // function
	AssetTypeContainerRegistry AssetType = "container_registry" // registry

	// Infrastructure and devices.
	AssetTypeHost                AssetType = "host"                 // physical or virtual machine
	AssetTypeContainer           AssetType = "container"            // running container
	AssetTypeKubernetesCluster   AssetType = "kubernetes_cluster"   // cluster
	AssetTypeKubernetesNamespace AssetType = "kubernetes_namespace" // namespace
	AssetTypeKubernetesWorkload  AssetType = "kubernetes_workload"  // Deployment, StatefulSet, Job, Pod
	AssetTypeEndpointDevice      AssetType = "endpoint_device"      // laptop, desktop, phone
	AssetTypeIoTDevice           AssetType = "iot_device"           // IoT device
	AssetTypeOTDevice            AssetType = "ot_device"            // operational technology device
	AssetTypeNetworkDevice       AssetType = "network_device"       // router, switch, access point

	// Network.
	AssetTypeVPC          AssetType = "vpc"
	AssetTypeSubnet       AssetType = "subnet"
	AssetTypeLoadBalancer AssetType = "load_balancer"
	AssetTypeFirewall     AssetType = "firewall"

	// Identity.
	AssetTypeIdentity AssetType = "identity" // with technical.identity.kind

	// Web3 profile.
	AssetTypeSmartContract AssetType = "smart_contract"
	AssetTypeWallet        AssetType = "wallet"
	AssetTypeNFTCollection AssetType = "nft_collection"
	AssetTypeDeFiProtocol  AssetType = "defi_protocol"
	AssetTypeToken         AssetType = "token"
	AssetTypeBlockchain    AssetType = "blockchain"

	// Not yet classified.
	AssetTypeUnclassified AssetType = "unclassified"
)

// AllAssetTypes returns all valid asset types.
func AllAssetTypes() []AssetType {
	return []AssetType{
		AssetTypeDomainName, AssetTypeIPAddress, AssetTypeIPRange, AssetTypeCertificate, AssetTypeAutonomousSystem,
		AssetTypeWebOrigin, AssetTypeWebApplication, AssetTypeAPI, AssetTypeMobileApp, AssetTypeSaaSApplication, AssetTypeService,
		AssetTypeRepository, AssetTypePackage, AssetTypeContainerImage, AssetTypeAIModel,
		AssetTypeCloudAccount, AssetTypeCloudResource, AssetTypeStorage, AssetTypeDatabase, AssetTypeServerless, AssetTypeContainerRegistry,
		AssetTypeHost, AssetTypeContainer, AssetTypeKubernetesCluster, AssetTypeKubernetesNamespace, AssetTypeKubernetesWorkload,
		AssetTypeEndpointDevice, AssetTypeIoTDevice, AssetTypeOTDevice, AssetTypeNetworkDevice,
		AssetTypeVPC, AssetTypeSubnet, AssetTypeLoadBalancer, AssetTypeFirewall,
		AssetTypeIdentity,
		AssetTypeSmartContract, AssetTypeWallet, AssetTypeNFTCollection, AssetTypeDeFiProtocol, AssetTypeToken, AssetTypeBlockchain,
		AssetTypeUnclassified,
	}
}

// IsValid checks if the asset type is valid.
func (t AssetType) IsValid() bool { return slices.Contains(AllAssetTypes(), t) }

// String returns the string representation.
func (t AssetType) String() string { return string(t) }

// FindingType represents the type of a finding.
type FindingType string

// Finding types.
const (
	FindingTypeVulnerability    FindingType = "vulnerability"    // a known vulnerability (advisory id)
	FindingTypeWeakness         FindingType = "weakness"         // a code or design weakness without an advisory id
	FindingTypeSecret           FindingType = "secret"           // an exposed credential
	FindingTypeMisconfiguration FindingType = "misconfiguration" // a setting that weakens security
	FindingTypeCompliance       FindingType = "compliance"       // a control evaluation
	FindingTypeExposure         FindingType = "exposure"         // something reachable that should not be
	FindingTypeMalware          FindingType = "malware"          // malicious code or package
	FindingTypeLicense          FindingType = "license"          // license policy violation
)

// AllFindingTypes returns all valid finding types.
func AllFindingTypes() []FindingType {
	return []FindingType{
		FindingTypeVulnerability, FindingTypeWeakness, FindingTypeSecret, FindingTypeMisconfiguration,
		FindingTypeCompliance, FindingTypeExposure, FindingTypeMalware, FindingTypeLicense,
	}
}

// IsValid checks if the finding type is valid.
func (t FindingType) IsValid() bool { return slices.Contains(AllFindingTypes(), t) }

// String returns the string representation.
func (t FindingType) String() string { return string(t) }

// Severity represents the severity level.
type Severity string

// Severities.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
	// SeverityUnknown: the source gave no severity, or one that maps to none
	// of the others. Also the fallback for a severity a receiver does not
	// know in a newer-minor document.
	SeverityUnknown Severity = "unknown"
)

// AllSeverities returns all valid severities.
func AllSeverities() []Severity {
	return []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo, SeverityUnknown}
}

// IsValid checks if the severity is valid.
func (s Severity) IsValid() bool { return slices.Contains(AllSeverities(), s) }

// String returns the string representation.
func (s Severity) String() string { return string(s) }

// Score returns a numeric score for the severity (0-10).
//
// An unrecognized, empty or unknown severity intentionally scores 5.0
// (Medium), not 0: a finding whose severity the producer got wrong must
// still surface in score-based triage rather than sink and be missed.
// Callers that want to reject unknown severities use Validate.
func (s Severity) Score() float64 {
	switch s {
	case SeverityCritical:
		return 10.0
	case SeverityHigh:
		return 7.5
	case SeverityLow:
		return 2.5
	case SeverityInfo:
		return 0.0
	default:
		return 5.0
	}
}

// Criticality is the business criticality of an asset.
type Criticality string

// Criticalities.
const (
	CriticalityCritical Criticality = "critical"
	CriticalityHigh     Criticality = "high"
	CriticalityMedium   Criticality = "medium"
	CriticalityLow      Criticality = "low"
)

// AllCriticalities returns all valid criticalities.
func AllCriticalities() []Criticality {
	return []Criticality{CriticalityCritical, CriticalityHigh, CriticalityMedium, CriticalityLow}
}

// IsValid checks if the criticality is valid. Empty is valid (not stated).
func (c Criticality) IsValid() bool { return c == "" || slices.Contains(AllCriticalities(), c) }

// String returns the string representation.
func (c Criticality) String() string { return string(c) }

// Properties is an opaque bag. Receivers MUST NOT give meaning to its keys.
type Properties map[string]any

// =============================================================================
// Factory functions
// =============================================================================

// NewReport creates a new empty CTIS report stamped with the specification
// version, the schema URL, a fresh UUIDv7 metadata.id and the current time.
func NewReport() *Report {
	return &Report{
		Version: SchemaVersion,
		Schema:  SchemaURL,
		Metadata: ReportMetadata{
			ID:          NewReportID(),
			GeneratedAt: time.Now().UTC(),
			Channel:     ChannelScanner,
		},
		Assets:   make([]Asset, 0),
		Findings: make([]Finding, 0),
	}
}

// Bool returns a pointer to b, for the tri-state boolean members.
func Bool(b bool) *bool { return &b }
