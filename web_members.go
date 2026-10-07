package ctis

import (
	"regexp"
	"strings"

	"github.com/openctemio/ctis/weburl"
)

// Web members (CTIS 1.6, spec section 4.12): the endpoints a crawler, a
// spec import or a scanner saw on a web origin, and the typed web location
// of a finding. A URL in either never carries a query value, user info or
// fragment: parameters are named, never valued.

// Limits of the web members.
const (
	MaxEndpoints        = 200000
	MaxEndpointParams   = 100
	MaxParamNameLen     = 128
	MaxEndpointPathLen  = 2048
	MaxContentTypeLen   = 255
	MaxParamTypeHintLen = 32
	MaxEndpointIDLen    = 128
	MaxWebRequestRefLen = 128
	maxStatusCode       = 599
	minStatusCode       = 100
)

// EndpointKind is what an endpoint serves.
type EndpointKind string

// Endpoint kinds.
const (
	EndpointKindPage      EndpointKind = "page"
	EndpointKindAPI       EndpointKind = "api"
	EndpointKindScript    EndpointKind = "script"
	EndpointKindForm      EndpointKind = "form"
	EndpointKindGraphQL   EndpointKind = "graphql"
	EndpointKindWebSocket EndpointKind = "websocket"
	EndpointKindStatic    EndpointKind = "static"
	EndpointKindOther     EndpointKind = "other"
)

// AllEndpointKinds returns every endpoint kind.
func AllEndpointKinds() []EndpointKind {
	return []EndpointKind{EndpointKindPage, EndpointKindAPI, EndpointKindScript, EndpointKindForm,
		EndpointKindGraphQL, EndpointKindWebSocket, EndpointKindStatic, EndpointKindOther}
}

// EndpointSource is how an endpoint was found.
type EndpointSource string

// Endpoint sources.
const (
	EndpointSourceCrawl   EndpointSource = "crawl"
	EndpointSourceJS      EndpointSource = "js"
	EndpointSourceSitemap EndpointSource = "sitemap"
	EndpointSourceRobots  EndpointSource = "robots"
	EndpointSourceSpec    EndpointSource = "spec"
	EndpointSourceHAR     EndpointSource = "har"
	EndpointSourceArchive EndpointSource = "archive"
	EndpointSourceDAST    EndpointSource = "dast"
	EndpointSourceProbe   EndpointSource = "probe"
)

// AllEndpointSources returns every endpoint source.
func AllEndpointSources() []EndpointSource {
	return []EndpointSource{EndpointSourceCrawl, EndpointSourceJS, EndpointSourceSitemap, EndpointSourceRobots,
		EndpointSourceSpec, EndpointSourceHAR, EndpointSourceArchive, EndpointSourceDAST, EndpointSourceProbe}
}

// EndpointAuth is whether an endpoint asked for authentication.
type EndpointAuth string

// Endpoint authentication states.
const (
	EndpointAuthNone          EndpointAuth = "none"
	EndpointAuthRequired      EndpointAuth = "required"
	EndpointAuthRedirectLogin EndpointAuth = "redirect_login"
	EndpointAuthUnknown       EndpointAuth = "unknown"
)

// AllEndpointAuths returns every endpoint authentication state.
func AllEndpointAuths() []EndpointAuth {
	return []EndpointAuth{EndpointAuthNone, EndpointAuthRequired, EndpointAuthRedirectLogin, EndpointAuthUnknown}
}

// ParamLocation is where a request parameter goes.
type ParamLocation string

// Parameter locations.
const (
	ParamLocationQuery      ParamLocation = "query"
	ParamLocationPath       ParamLocation = "path"
	ParamLocationHeader     ParamLocation = "header"
	ParamLocationCookie     ParamLocation = "cookie"
	ParamLocationForm       ParamLocation = "form"
	ParamLocationJSON       ParamLocation = "json"
	ParamLocationMultipart  ParamLocation = "multipart"
	ParamLocationGraphQLArg ParamLocation = "graphql_arg"
)

// AllParamLocations returns every parameter location.
func AllParamLocations() []ParamLocation {
	return []ParamLocation{ParamLocationQuery, ParamLocationPath, ParamLocationHeader, ParamLocationCookie,
		ParamLocationForm, ParamLocationJSON, ParamLocationMultipart, ParamLocationGraphQLArg}
}

// Endpoint is one method and path a web origin serves, as a tool saw it.
type Endpoint struct {
	// ID names the endpoint within the report (finding.web.endpoint_ref).
	ID string `json:"id,omitempty"`

	// Origin is the normalised origin, "https://api.example.com".
	Origin string `json:"origin"`

	// OriginRef names the http_service asset of the origin in this report.
	OriginRef string `json:"origin_ref,omitempty"`

	// Method is an HTTP method, or ANY when unknown.
	Method string `json:"method,omitempty"`

	// Path is the concrete path, without query or fragment.
	Path string `json:"path"`

	// Template is the producer's path template; a receiver recomputes it.
	Template string `json:"template,omitempty"`

	Kind   EndpointKind   `json:"kind,omitempty"`
	Source EndpointSource `json:"source,omitempty"`

	// Parent is the page the endpoint was found on, redacted (no query
	// values, user info or fragment).
	Parent string `json:"parent,omitempty"`

	StatusCode  int          `json:"status_code,omitempty"`
	ContentType string       `json:"content_type,omitempty"`
	Auth        EndpointAuth `json:"auth,omitempty"`

	Technologies []Technology `json:"technologies,omitempty"`

	// Params are the parameters the endpoint takes: names and hints,
	// never values.
	Params []EndpointParam `json:"params,omitempty"`
}

// EndpointParam is one parameter of an endpoint. It has no value member: a
// value is refused by every strict receiver.
type EndpointParam struct {
	Location ParamLocation `json:"location"`
	Name     string        `json:"name"`
	TypeHint string        `json:"type_hint,omitempty"`
	Required bool          `json:"required,omitempty"`
}

// WebLocation is where on a web origin a finding was observed.
type WebLocation struct {
	// URL is the redacted URL: no query values, user info or fragment.
	URL string `json:"url"`

	Method string `json:"method,omitempty"`

	// EndpointRef names an endpoint of this report.
	EndpointRef string `json:"endpoint_ref,omitempty"`

	// Parameter is the parameter the finding is about.
	Parameter *WebParameter `json:"parameter,omitempty"`

	// RequestRef names the evidence of the request ("sha256:<hex>" or an
	// attachment id).
	RequestRef string `json:"request_ref,omitempty"`

	StatusCode int `json:"status_code,omitempty"`
}

// WebParameter is one parameter of a request.
type WebParameter struct {
	Location ParamLocation `json:"location"`
	Name     string        `json:"name"`
}

var (
	reportIDRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	typeHintRE   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	requestRefRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

func validEnum[T ~string](v T, all []T) bool {
	for _, a := range all {
		if v == a {
			return true
		}
	}
	return false
}

// redactedURL reports whether s is a URL that carries no query value, user
// info or fragment (weburl.RedactURL leaves it unchanged) and parses.
func redactedURL(s string) bool {
	if s == "" || len(s) > weburl.MaxURLBytes || weburl.RedactURL(s) != s {
		return false
	}
	_, err := weburl.Parse(s)
	return err == nil
}

func validPath(p string) bool {
	if p == "" || p[0] != '/' || len(p) > MaxEndpointPathLen || strings.ContainsAny(p, "?#") {
		return false
	}
	return !hasControlRune(p)
}

func hasControlRune(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == '‮' || r == ' ' || r == ' ' {
			return true
		}
	}
	return false
}

func validStatus(c int) bool { return c == 0 || (c >= minStatusCode && c <= maxStatusCode) }

func validParamName(n string) bool {
	return strings.TrimSpace(n) != "" && len(n) <= MaxParamNameLen && !hasControlRune(n)
}

// validateEndpoints checks the report's endpoints and returns their ids.
func validateEndpoints(r *Report, assetIDs map[string]bool, add func(string, ...any)) map[string]bool {
	ids := map[string]bool{}
	if len(r.Endpoints) > MaxEndpoints {
		add("endpoints has %d entries, at most %d", len(r.Endpoints), MaxEndpoints)
		return ids
	}
	for i, e := range r.Endpoints {
		p := func(format string, args ...any) { add("endpoints[%d]: "+format, append([]any{i}, args...)...) }
		if e.ID != "" {
			switch {
			case !reportIDRE.MatchString(e.ID):
				p("invalid id")
			case ids[e.ID]:
				p("duplicate id %q", e.ID)
			}
			ids[e.ID] = true
		}
		if u, err := weburl.Parse(e.Origin); err != nil || u.Origin() != e.Origin {
			p("origin %q is not a normalised origin (scheme://host[:port])", truncateForError(e.Origin))
		}
		if e.OriginRef != "" && !assetIDs[e.OriginRef] {
			p("origin_ref %q names no asset in this report", truncateForError(e.OriginRef))
		}
		if _, ok := weburl.NormalizeMethod(e.Method); !ok {
			p("invalid method %q", truncateForError(e.Method))
		}
		if !validPath(e.Path) {
			p("path must start with '/', have no query or fragment, no control character, at most %d bytes", MaxEndpointPathLen)
		}
		if e.Template != "" && !validPath(e.Template) {
			p("invalid template")
		}
		if e.Kind != "" && !validEnum(e.Kind, AllEndpointKinds()) {
			p("invalid kind %q", truncateForError(string(e.Kind)))
		}
		if e.Source != "" && !validEnum(e.Source, AllEndpointSources()) {
			p("invalid source %q", truncateForError(string(e.Source)))
		}
		if e.Auth != "" && !validEnum(e.Auth, AllEndpointAuths()) {
			p("invalid auth %q", truncateForError(string(e.Auth)))
		}
		if e.Parent != "" && !redactedURL(e.Parent) {
			p("parent must be a redacted URL (no query value, user info or fragment)")
		}
		if !validStatus(e.StatusCode) {
			p("status_code %d is outside 100-599", e.StatusCode)
		}
		if len(e.ContentType) > MaxContentTypeLen || hasControlRune(e.ContentType) {
			p("invalid content_type")
		}
		validateTechnologyList(func(format string, args ...any) { p(format, args...) }, e.Technologies)
		if len(e.Params) > MaxEndpointParams {
			p("params has %d entries, at most %d", len(e.Params), MaxEndpointParams)
		}
		for j, prm := range e.Params {
			if j >= MaxEndpointParams {
				break
			}
			if !validEnum(prm.Location, AllParamLocations()) {
				p("params[%d]: invalid location %q", j, truncateForError(string(prm.Location)))
			}
			if !validParamName(prm.Name) {
				p("params[%d]: name must be 1 to %d bytes without control characters", j, MaxParamNameLen)
			}
			if prm.TypeHint != "" && !typeHintRE.MatchString(prm.TypeHint) {
				p("params[%d]: invalid type_hint", j)
			}
		}
	}
	return ids
}

// validateWebLocation checks finding.web.
func validateWebLocation(i int, w *WebLocation, endpointIDs map[string]bool, add func(string, ...any)) {
	if w == nil {
		return
	}
	p := func(format string, args ...any) { add("findings[%d]: web: "+format, append([]any{i}, args...)...) }
	if !redactedURL(w.URL) {
		p("url must be a redacted http(s) URL (no query value, user info or fragment)")
	}
	if w.Method != "" {
		if _, ok := weburl.NormalizeMethod(w.Method); !ok {
			p("invalid method %q", truncateForError(w.Method))
		}
	}
	if w.EndpointRef != "" && !endpointIDs[w.EndpointRef] {
		p("endpoint_ref %q names no endpoint in this report", truncateForError(w.EndpointRef))
	}
	if prm := w.Parameter; prm != nil {
		if !validEnum(prm.Location, AllParamLocations()) {
			p("parameter: invalid location %q", truncateForError(string(prm.Location)))
		}
		if !validParamName(prm.Name) {
			p("parameter: name must be 1 to %d bytes without control characters", MaxParamNameLen)
		}
	}
	if w.RequestRef != "" && !requestRefRE.MatchString(w.RequestRef) {
		p("invalid request_ref")
	}
	if !validStatus(w.StatusCode) {
		p("status_code %d is outside 100-599", w.StatusCode)
	}
}
