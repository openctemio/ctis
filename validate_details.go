package ctis

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Limits of the core members (the schema states them too).
const (
	MaxReferences         = 100
	MaxURLLen             = 2048
	MaxDependencyLocation = 100
	MaxDependsOn          = 1000
	MaxLicenses           = 32
	MaxCWEIDs             = 32
	MaxFixedVersions      = 64
	MaxAuthMethods        = 16
	MaxServiceDetails     = 32
	MaxDetailValueLen     = 1024
	MaxHeaderValueLen     = 2048
	MaxSecretScopes       = 64
)

var (
	countryRE = regexp.MustCompile(`^[A-Z]{2}$`)
	cweIDRE   = regexp.MustCompile(`^CWE-[1-9][0-9]{0,5}$`)
	owaspIDRE = regexp.MustCompile(`^A(0[1-9]|10):20[0-9]{2}$`)
	sha256RE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// IsWebURL reports whether s is an absolute http or https URL with a host,
// the only schemes CTIS URL members accept.
func IsWebURL(s string) bool {
	if len(s) > MaxURLLen || hasControlRune(s) {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return false
	}
	sc := strings.ToLower(u.Scheme)
	return sc == "http" || sc == "https"
}

// checkWebURL reports a URL member that is set and not http(s).
func checkWebURL(where, s string, add func(string, ...any)) {
	if s != "" && !IsWebURL(s) {
		add("%s %q is not an http or https URL", where, truncateForError(s))
	}
}

func validateAssetTechnical(i int, a *Asset, add func(string, ...any)) {
	t := a.Technical
	if t == nil {
		if a.Type == AssetTypeIdentity {
			add("assets[%d]: identity needs technical.identity.kind", i)
		}
		return
	}
	p := func(format string, args ...any) { add("assets[%d]: technical."+format, append([]any{i}, args...)...) }
	if ip := t.IPAddress; ip != nil {
		if ip.Version != 0 && ip.Version != 4 && ip.Version != 6 {
			p("ip_address.version %d is not 4 or 6", ip.Version)
		}
		if ip.Country != "" && !countryRE.MatchString(ip.Country) {
			p("ip_address.country %q is not an ISO 3166-1 alpha-2 code", truncateForError(ip.Country))
		}
		if g := ip.Geolocation; g != nil && (!inRange(g.Latitude, -90, 90) || !inRange(g.Longitude, -180, 180) || !inRange(g.Accuracy, 0, 1e8)) {
			p("ip_address.geolocation is out of range")
		}
	}
	if r := t.Repository; r != nil {
		checkWebURL(fmt.Sprintf("assets[%d].technical.repository.url", i), r.URL, add)
		if r.Platform != "" && !IsOpenToken(r.Platform) {
			p("repository.platform %q is not a lowercase token", truncateForError(r.Platform))
		}
	}
	if c := t.Certificate; c != nil {
		if c.SHA256Fingerprint != "" && !sha256RE.MatchString(c.SHA256Fingerprint) {
			p("certificate.sha256_fingerprint is not 64 lowercase hex digits")
		}
		if a.Type == AssetTypeCertificate && c.SHA256Fingerprint != "" && c.SHA256Fingerprint != a.Value {
			p("certificate.sha256_fingerprint differs from the asset value")
		}
	}
	if c := t.Cloud; c != nil && c.Provider != "" && !IsOpenToken(c.Provider) {
		p("cloud.provider %q is not a lowercase token", truncateForError(c.Provider))
	}
	if s := t.Service; s != nil {
		if s.Port < 1 || s.Port > 65535 {
			p("service.port %d is outside 1-65535", s.Port)
		}
		if !s.Transport.IsValid() {
			p("service.transport %q is not tcp, udp or sctp", truncateForError(string(s.Transport)))
		}
		if s.AppProtocol != "" && !ianaServiceRE.MatchString(s.AppProtocol) {
			p("service.app_protocol %q is not an IANA service name", truncateForError(s.AppProtocol))
		}
		if s.State != "" && !s.State.IsValid() {
			p("service.state %q is invalid", truncateForError(string(s.State)))
		}
		if s.TLSVersion != "" && !s.TLSVersion.IsValid() {
			p("service.tls_version %q is invalid", truncateForError(string(s.TLSVersion)))
		}
		if len(s.AuthMethods) > MaxAuthMethods {
			p("service.auth_methods has %d entries, at most %d", len(s.AuthMethods), MaxAuthMethods)
		}
		if len(s.Details) > MaxServiceDetails {
			p("service.details has %d entries, at most %d", len(s.Details), MaxServiceDetails)
		}
		for k, v := range s.Details {
			if tooLong(k, 64) || tooLong(v, MaxDetailValueLen) {
				p("service.details has an over-long entry")
				break
			}
		}
		if s.ResponseTimeMs < 0 {
			p("service.response_time_ms is negative")
		}
		if a.Type == AssetTypeService && s.Port > 0 && s.Transport.IsValid() {
			if !strings.HasSuffix(a.Value, fmt.Sprintf(":%d/%s", s.Port, s.Transport)) {
				p("service port and transport differ from the asset value")
			}
		}
	}
	if h := t.HTTP; h != nil {
		if h.TLSVersion != "" && !h.TLSVersion.IsValid() {
			p("http.tls_version %q is invalid", truncateForError(string(h.TLSVersion)))
		}
		if !validStatus(h.StatusCode) {
			p("http.status_code %d is outside 100-599", h.StatusCode)
		}
		checkWebURL(fmt.Sprintf("assets[%d].technical.http.redirect_url", i), h.RedirectURL, add)
		for _, tok := range [][2]string{{"cdn", h.CDN}, {"waf", h.WAF}} {
			if tok[1] != "" && !IsOpenToken(tok[1]) {
				p("http.%s %q is not a lowercase token", tok[0], truncateForError(tok[1]))
			}
		}
		if sh := h.SecurityHeaders; sh != nil {
			for _, v := range []string{sh.StrictTransportSecurity, sh.ContentSecurityPolicy, sh.XFrameOptions, sh.XContentTypeOptions, sh.ReferrerPolicy, sh.PermissionsPolicy, sh.AccessControlAllowOrigin, sh.AccessControlAllowCredentials} {
				if tooLong(v, MaxHeaderValueLen) {
					p("http.security_headers has a value longer than %d", MaxHeaderValueLen)
					break
				}
			}
			if len(sh.Cookies) > MaxPostureCookies {
				p("http.security_headers.cookies has %d entries, at most %d", len(sh.Cookies), MaxPostureCookies)
			}
			for j, c := range sh.Cookies {
				if !validCookieToken(c.Name) {
					p("http.security_headers.cookies[%d].name is not a cookie name", j)
				}
				switch c.SameSite {
				case "", "strict", "lax", "none":
				default:
					p("http.security_headers.cookies[%d].same_site %q is invalid", j, truncateForError(c.SameSite))
				}
			}
		}
	}
	if id := t.Identity; id != nil {
		if !id.Kind.IsValid() {
			p("identity.kind %q is invalid", truncateForError(string(id.Kind)))
		}
		if id.Provider != "" && !IsOpenToken(id.Provider) {
			p("identity.provider %q is not a lowercase token", truncateForError(id.Provider))
		}
	} else if a.Type == AssetTypeIdentity {
		add("assets[%d]: identity needs technical.identity.kind", i)
	}
}

// ianaServiceRE is the form of an IANA service name (RFC 6335 section 5.1).
var ianaServiceRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,13}[a-z0-9])?$`)

func validateDependency(i int, d *Dependency, assetIDs, depIDs map[string]bool, add func(string, ...any)) {
	if strings.TrimSpace(d.Name) == "" {
		add("dependencies[%d]: name is required", i)
	}
	validateDocumentRef(fmt.Sprintf("dependencies[%d].id", i), d.ID, add)
	if d.Type != "" && !d.Type.IsValid() {
		add("dependencies[%d]: invalid type %q", i, truncateForError(string(d.Type)))
	}
	if d.Relationship != "" && !d.Relationship.IsValid() {
		add("dependencies[%d]: invalid relationship %q", i, truncateForError(string(d.Relationship)))
	}
	if d.PURL != "" {
		if _, _, err := CanonicalPurl(d.PURL); err != nil {
			add("dependencies[%d]: purl %q is not a package URL", i, truncateForError(d.PURL))
		}
	}
	if d.AssetRef != "" && !assetIDs[d.AssetRef] {
		add("dependencies[%d]: asset_ref %q names no asset in this report", i, truncateForError(d.AssetRef))
	}
	if len(d.DependsOn) > MaxDependsOn {
		add("dependencies[%d]: depends_on has %d entries, at most %d", i, len(d.DependsOn), MaxDependsOn)
	}
	for j, ref := range d.DependsOn {
		if j >= MaxDependsOn {
			break
		}
		if !depIDs[ref] {
			add("dependencies[%d]: depends_on[%d] %q names no dependency in this report", i, j, truncateForError(ref))
		}
	}
	if len(d.Locations) > MaxDependencyLocation {
		add("dependencies[%d]: locations has %d entries, at most %d", i, len(d.Locations), MaxDependencyLocation)
	}
	if len(d.Licenses) > MaxLicenses {
		add("dependencies[%d]: licenses has %d entries, at most %d", i, len(d.Licenses), MaxLicenses)
	}
	validateExtensions(fmt.Sprintf("dependencies[%d].extensions", i), d.Extensions, add)
}

func validateFindingDetails(i int, f *Finding, add func(string, ...any)) {
	p := func(format string, args ...any) { add("findings[%d]: "+format, append([]any{i}, args...)...) }
	if l := f.Location; l != nil {
		if l.StartLine < 0 || l.EndLine < 0 || l.StartColumn < 0 || l.EndColumn < 0 {
			p("location has a negative line or column")
		}
	}
	if n := f.Network; n != nil {
		if n.Port < 0 || n.Port > 65535 {
			p("network.port %d is outside 0-65535", n.Port)
		}
		if n.Transport != "" && !n.Transport.IsValid() {
			p("network.transport %q is not tcp, udp or sctp", truncateForError(string(n.Transport)))
		}
		if n.AppProtocol != "" && !ianaServiceRE.MatchString(n.AppProtocol) {
			p("network.app_protocol %q is not an IANA service name", truncateForError(n.AppProtocol))
		}
	}
	if v := f.Vulnerability; v != nil {
		if len(v.CWEIDs) > MaxCWEIDs {
			p("vulnerability.cwe_ids has %d entries, at most %d", len(v.CWEIDs), MaxCWEIDs)
		}
		for j, c := range v.CWEIDs {
			if j < MaxCWEIDs && !cweIDRE.MatchString(c) {
				p("vulnerability.cwe_ids[%d] %q is not CWE-<n>", j, truncateForError(c))
			}
		}
		for j, o := range v.OWASPIDs {
			if !owaspIDRE.MatchString(o) {
				p("vulnerability.owasp_ids[%d] %q is not A<nn>:<year>", j, truncateForError(o))
			}
		}
		if v.PURL != "" {
			if _, _, err := CanonicalPurl(v.PURL); err != nil {
				p("vulnerability.purl %q is not a package URL", truncateForError(v.PURL))
			}
		}
		if len(v.FixedVersions) > MaxFixedVersions {
			p("vulnerability.fixed_versions has %d entries, at most %d", len(v.FixedVersions), MaxFixedVersions)
		}
		if ds := v.DataSource; ds != nil {
			checkWebURL(fmt.Sprintf("findings[%d].vulnerability.data_source.url", i), ds.URL, add)
		}
	}
	if s := f.Secret; s != nil {
		if s.AgeDays < 0 || s.Length < 0 || s.CommitCount < 0 {
			p("secret has a negative count")
		}
		if len(s.Scopes) > MaxSecretScopes {
			p("secret.scopes has %d entries, at most %d", len(s.Scopes), MaxSecretScopes)
		}
	}
	if c := f.Compliance; c != nil && c.Framework != "" && !IsOpenToken(string(c.Framework)) {
		p("compliance.framework %q is not a framework token", truncateForError(string(c.Framework)))
	}
	if r := f.Remediation; r != nil {
		if r.Effort != "" && !r.Effort.IsValid() {
			p("remediation.effort %q is invalid", truncateForError(string(r.Effort)))
		}
		if r.EstimatedMinutes < 0 {
			p("remediation.estimated_minutes is negative")
		}
		for j, a := range r.Advisories {
			checkWebURL(fmt.Sprintf("findings[%d].remediation.advisories[%d].url", i, j), a.URL, add)
		}
	}
	if e := f.Exposure; e != nil && e.Vector != "" && !e.Vector.IsValid() {
		p("exposure.vector %q is invalid", truncateForError(string(e.Vector)))
	}
	if dfl := f.DataFlow; dfl != nil {
		for _, l := range dfl.GetFullPath() {
			if l.Type != "" && !validEnum(l.Type, AllDataFlowLocationTypes()) {
				p("data_flow: invalid location type %q", truncateForError(string(l.Type)))
				break
			}
		}
	}
}
