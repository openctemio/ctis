package fingerprint

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/openctemio/ctis/weburl"
)

// Recipe v2 (CTIS 2.0) is specified in docs/fingerprints.md. In short, a
// fingerprint is "ctis-fp/2:" followed by the lowercase hex SHA-256 of the
// canonical input. The canonical input is the recipe name and then the
// recipe's parts; every element is written as "<decimal byte length>:<bytes>"
// and the elements are joined with the unit separator 0x1F. Because each
// element carries its own length, no content can shift into a neighbouring
// element, whatever characters it holds.
//
// Rules shared by every recipe: rule ids and other identifiers are trimmed of
// white space and keep their case; file paths keep their case; hosts are
// lowercase without a trailing dot; no message or description is ever an
// input; line numbers are an input of the line-based SAST recipe only.

// Prefix is the start of every recipe v2 fingerprint.
const Prefix = "ctis-fp/2:"

// Recipe names added by v2 next to the Type constants of v1.
const (
	// TypeVA is for network vulnerability-assessment findings.
	TypeVA Type = "va"
	// TypeCompliance is for compliance control findings.
	TypeCompliance Type = "compliance"
)

// SecretDigest is HMAC-SHA256(producerKey, secret). It is the only form in
// which a secret enters a recipe v2 fingerprint: there is no unsalted path.
//
// Key handling: the producer holds the key. It never sends the key, the
// secret or a masked copy of the secret in a report; only the fingerprint
// leaves the producer. Use one key per producer installation (or per tenant)
// so two installations cannot confirm each other's secrets, keep it as secret
// as the credentials it protects, and keep it stable: rotating it changes the
// fingerprint of every secret finding once.
type SecretDigest [32]byte

// MinSecretKeyBytes is the shortest HMAC key NewSecretDigest accepts.
const MinSecretKeyBytes = 16

// ErrSecretKey is returned for a key shorter than MinSecretKeyBytes.
var ErrSecretKey = errors.New("fingerprint: secret HMAC key shorter than 16 bytes")

// ErrEmptySecret is returned for an empty secret.
var ErrEmptySecret = errors.New("fingerprint: empty secret")

// NewSecretDigest returns HMAC-SHA256(key, secret).
func NewSecretDigest(key, secret []byte) (SecretDigest, error) {
	var d SecretDigest
	if len(key) < MinSecretKeyBytes {
		return d, ErrSecretKey
	}
	if len(secret) == 0 {
		return d, ErrEmptySecret
	}
	m := hmac.New(sha256.New, key)
	m.Write(secret) // hash.Hash.Write never returns an error
	copy(d[:], m.Sum(nil))
	return d, nil
}

// String is the lowercase hex form.
func (d SecretDigest) String() string { return hex.EncodeToString(d[:]) }

// MarshalText is the hex form, so a digest is a JSON string.
func (d SecretDigest) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// UnmarshalText reads the 64 hex characters of MarshalText.
func (d *SecretDigest) UnmarshalText(b []byte) error {
	if len(b) != 2*len(d) {
		return errors.New("fingerprint: secret digest is not 64 hex characters")
	}
	_, err := hex.Decode(d[:], b)
	return err
}

// IsZero reports whether d is the zero value (no secret was digested).
func (d SecretDigest) IsZero() bool { return d == SecretDigest{} }

// V2Input is the input of V2Generate and V2Auto. Only the members a recipe
// reads are used.
type V2Input struct {
	Type Type `json:"type"`

	RuleID          string `json:"rule_id"`          // rule, check, template, plugin or SWC id
	VulnerabilityID string `json:"vulnerability_id"` // CVE, GHSA, vendor id
	FilePath        string `json:"file_path"`
	StartLine       int    `json:"start_line"`
	EndLine         int    `json:"end_line"`

	Snippet         string `json:"snippet"`          // sast-content: source text of the region
	LogicalLocation string `json:"logical_location"` // sast-content: enclosing function

	PackagePURL  string       `json:"package_purl"` // sca, container: package URL or "ecosystem/name"
	SecretDigest SecretDigest `json:"secret_digest"`

	ResourceType string `json:"resource_type"` // misconfig
	ResourceName string `json:"resource_name"` // misconfig

	URL       string `json:"url"`       // dast: http(s) URL of the affected endpoint
	Parameter string `json:"parameter"` // dast: parameter name, never its value

	ImageRef string `json:"image_ref"` // container: image reference, see ImageIdentity

	AssetValue string `json:"asset_value"` // va: host name or IP address
	Port       int    `json:"port"`        // va
	Transport  string `json:"transport"`   // va: tcp, udp

	Framework string `json:"framework"`  // compliance
	ControlID string `json:"control_id"` // compliance
	Resource  string `json:"resource"`   // compliance: the assessed resource

	ChainID         int    `json:"chain_id"`         // web3
	ContractAddress string `json:"contract_address"` // web3
	Function        string `json:"function"`         // web3: function signature
}

// V2Generate returns the recipe v2 fingerprint of in.Type. It fails when the
// input cannot form a stable key: an unparsable URL, a secret without a
// digest, a sast-content region without a snippet, an unknown type.
func V2Generate(in V2Input) (string, error) {
	parts, err := v2Parts(in)
	if err != nil {
		return "", err
	}
	return v2Hash(string(in.Type), parts), nil
}

// V2Auto is V2Generate with the type taken from V2Detect when in.Type is empty.
func V2Auto(in V2Input) (string, error) {
	if in.Type == "" {
		in.Type = V2Detect(in)
	}
	return V2Generate(in)
}

// V2Detect picks the recipe from the members that are set. It never returns
// an empty Type: input that fits no specific recipe is TypeGeneric.
func V2Detect(in V2Input) Type {
	switch {
	case in.ContractAddress != "":
		return TypeWeb3
	case in.ImageRef != "" && in.PackagePURL != "":
		return TypeContainer
	case in.Framework != "" || in.ControlID != "":
		return TypeCompliance
	case !in.SecretDigest.IsZero():
		return TypeSecret
	case in.URL != "":
		return TypeDAST
	case in.AssetValue != "" && (in.Port > 0 || in.Transport != ""):
		return TypeVA
	case in.PackagePURL != "" && in.VulnerabilityID != "":
		return TypeSCA
	case in.ResourceType != "" || in.ResourceName != "":
		return TypeMisconfiguration
	case in.FilePath != "" && in.RuleID != "" && strings.TrimSpace(in.Snippet) != "":
		return TypeSASTContent
	case in.FilePath != "" && in.RuleID != "" && in.StartLine > 0:
		return TypeSAST
	}
	return TypeGeneric
}

// V2Parts returns the recipe name and the normalised parts of in, before
// length-prefixing and hashing. Conformance vectors publish them so another
// implementation can compare each step.
func V2Parts(in V2Input) (recipe string, parts []string, err error) {
	parts, err = v2Parts(in)
	return string(in.Type), parts, err
}

func v2Parts(in V2Input) ([]string, error) {
	line := strconv.Itoa
	switch in.Type {
	case TypeSAST:
		return []string{v2Path(in.FilePath), v2ID(in.RuleID), line(in.StartLine), line(in.EndLine)}, nil
	case TypeSASTContent:
		snip := normalizeSnippet(in.Snippet)
		if snip == "" {
			return nil, errors.New("fingerprint: sast-content needs a snippet")
		}
		return []string{v2Path(in.FilePath), v2ID(in.RuleID), v2ID(in.LogicalLocation), Hash(snip)}, nil
	case TypeSCA:
		return []string{VersionlessPURL(in.PackagePURL), v2ID(in.VulnerabilityID)}, nil
	case TypeSecret:
		if in.SecretDigest.IsZero() {
			return nil, errors.New("fingerprint: secret recipe needs an HMAC digest")
		}
		return []string{v2Path(in.FilePath), v2ID(in.RuleID), in.SecretDigest.String()}, nil
	case TypeMisconfiguration:
		return []string{v2ID(in.ResourceType), v2ID(in.ResourceName), v2ID(in.RuleID), v2Path(in.FilePath)}, nil
	case TypeDAST:
		u, err := weburl.Parse(in.URL)
		if err != nil {
			return nil, fmt.Errorf("fingerprint: dast url: %w", err)
		}
		return []string{v2ID(in.RuleID), u.Origin(), u.Path, v2ID(in.Parameter)}, nil
	case TypeContainer:
		return []string{ImageIdentity(in.ImageRef), VersionlessPURL(in.PackagePURL), v2ID(in.VulnerabilityID)}, nil
	case TypeVA:
		return []string{v2Host(in.AssetValue), line(in.Port), strings.ToLower(strings.TrimSpace(in.Transport)), v2ID(in.VulnerabilityID)}, nil
	case TypeCompliance:
		return []string{v2ID(in.Framework), v2ID(in.ControlID), v2ID(in.Resource)}, nil
	case TypeWeb3:
		return []string{line(in.ChainID), v2Address(in.ContractAddress), v2ID(in.RuleID), v2ID(in.Function)}, nil
	case TypeGeneric:
		return []string{v2ID(in.RuleID), v2Path(in.FilePath), line(in.StartLine), line(in.EndLine)}, nil
	}
	return nil, fmt.Errorf("fingerprint: unknown recipe %q", in.Type)
}

// v2Encode is the canonical input: the recipe name and the parts, each as
// "<byte length>:<bytes>", joined with 0x1F.
func v2Encode(recipe string, parts []string) string {
	var b strings.Builder
	add := func(s string) {
		b.WriteString(strconv.Itoa(len(s)))
		b.WriteByte(':')
		b.WriteString(s)
	}
	add(recipe)
	for _, p := range parts {
		b.WriteByte(0x1f)
		add(p)
	}
	return b.String()
}

func v2Hash(recipe string, parts []string) string {
	return Prefix + Hash(v2Encode(recipe, parts))
}

// EncodeParts returns the canonical input of a recipe, the string that is
// hashed. It is exported for the other CTIS keys (the correlation key uses
// the same encoding) and for implementers checking an intermediate step.
func EncodeParts(recipe string, parts ...string) string { return v2Encode(recipe, parts) }

func v2ID(s string) string { return strings.TrimSpace(s) }

// v2Path normalises a file path: separators become "/", "." and empty
// segments are dropped, a leading "/" is kept. The case is kept and ".." is
// not resolved (it would need the file system).
func v2Path(p string) string {
	p = strings.ReplaceAll(strings.TrimSpace(p), `\`, "/")
	abs := strings.HasPrefix(p, "/")
	segs := strings.Split(p, "/")
	out := segs[:0]
	for _, s := range segs {
		if s == "" || s == "." {
			continue
		}
		out = append(out, s)
	}
	r := strings.Join(out, "/")
	if abs {
		return "/" + r
	}
	return r
}

// v2Host lowercases a host name or address and removes a trailing dot.
func v2Host(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

// v2Address lowercases a 0x-prefixed (or bare) 40 digit hexadecimal address,
// which is case-insensitive apart from its checksum casing; any other value
// keeps its case.
func v2Address(a string) string {
	a = strings.TrimSpace(a)
	hexPart := strings.TrimPrefix(strings.TrimPrefix(a, "0x"), "0X")
	if len(hexPart) == 40 && isHex(hexPart) {
		return "0x" + strings.ToLower(hexPart)
	}
	return a
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// VersionlessPURL returns a package URL without its version, qualifiers and
// subpath, with the type in lowercase: "pkg:maven/org.x/lib@1.2?type=jar"
// becomes "pkg:maven/org.x/lib". A value that is not a package URL (for
// example "npm/lodash") is returned trimmed.
func VersionlessPURL(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 4 || !strings.EqualFold(s[:4], "pkg:") {
		return s
	}
	rest := strings.TrimLeft(s[4:], "/")
	if i := strings.IndexAny(rest, "#?"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		rest = rest[:i]
	}
	typ, tail, ok := strings.Cut(rest, "/")
	if !ok {
		return "pkg:" + strings.ToLower(rest)
	}
	return "pkg:" + strings.ToLower(typ) + "/" + tail
}

// ImageIdentity is the canonical identity of a container image: the
// registry and repository, plus "@sha256:..." when the reference has a
// digest. The tag is dropped (a tag moves; the digest does not). A missing
// registry is "docker.io" and a Docker Hub repository without a namespace
// gets "library/". The registry is lowercase; the repository keeps its case.
func ImageIdentity(ref string) string {
	ref = strings.TrimSpace(ref)
	name, digest, _ := strings.Cut(ref, "@")
	// A tag is a ":" after the last "/"; an earlier ":" is a registry port.
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		name = name[:i]
	}
	registry, repo, ok := strings.Cut(name, "/")
	if !ok || (!strings.ContainsAny(registry, ".:") && registry != "localhost") {
		registry, repo = "docker.io", name
	}
	registry = strings.ToLower(registry)
	if registry == "index.docker.io" || registry == "registry-1.docker.io" {
		registry = "docker.io"
	}
	if registry == "docker.io" && !strings.Contains(repo, "/") {
		repo = "library/" + repo
	}
	id := registry + "/" + repo
	if digest != "" {
		id += "@" + strings.ToLower(digest)
	}
	return id
}

// V2SAST is the line-based SAST recipe: file, rule, start and end line. The
// identity changes when code above the finding moves; prefer V2SASTContent.
func V2SAST(filePath, ruleID string, startLine, endLine int) string {
	return v2Must(V2Input{Type: TypeSAST, FilePath: filePath, RuleID: ruleID, StartLine: startLine, EndLine: endLine})
}

// V2SASTContent is the line-independent SAST recipe: file, rule, enclosing
// function and the whitespace-collapsed snippet. It returns "" for an empty
// snippet; callers fall back to V2SAST.
func V2SASTContent(filePath, ruleID, logicalLocation, snippet string) string {
	return v2Must(V2Input{Type: TypeSASTContent, FilePath: filePath, RuleID: ruleID, LogicalLocation: logicalLocation, Snippet: snippet})
}

// V2SCA keys a dependency finding by its versionless package and the
// vulnerability id. packageRef is a package URL, or "ecosystem/name".
func V2SCA(packageRef, vulnID string) string {
	return v2Must(V2Input{Type: TypeSCA, PackagePURL: packageRef, VulnerabilityID: vulnID})
}

// V2Secret keys a secret finding by file, rule and the HMAC digest of the
// secret (NewSecretDigest). It returns "" for the zero digest.
func V2Secret(filePath, ruleID string, digest SecretDigest) string {
	return v2Must(V2Input{Type: TypeSecret, FilePath: filePath, RuleID: ruleID, SecretDigest: digest})
}

// V2Misconfiguration keys a configuration finding by resource and rule.
func V2Misconfiguration(resourceType, resourceName, ruleID, filePath string) string {
	return v2Must(V2Input{Type: TypeMisconfiguration, ResourceType: resourceType, ResourceName: resourceName, RuleID: ruleID, FilePath: filePath})
}

// V2Web keys a web finding by template or rule, origin, path and parameter
// name. rawURL is parsed with package weburl; it returns "" for a URL that
// does not parse.
func V2Web(ruleID, rawURL, parameter string) string {
	return v2Must(V2Input{Type: TypeDAST, RuleID: ruleID, URL: rawURL, Parameter: parameter})
}

// V2Container keys an image finding by image identity (ImageIdentity), the
// versionless package and the vulnerability id.
func V2Container(imageRef, packageRef, vulnID string) string {
	return v2Must(V2Input{Type: TypeContainer, ImageRef: imageRef, PackagePURL: packageRef, VulnerabilityID: vulnID})
}

// V2VA keys a network vulnerability-assessment finding by asset value, port,
// transport and vulnerability or plugin id.
func V2VA(assetValue string, port int, transport, vulnID string) string {
	return v2Must(V2Input{Type: TypeVA, AssetValue: assetValue, Port: port, Transport: transport, VulnerabilityID: vulnID})
}

// V2Compliance keys a compliance finding by framework, control id and the
// assessed resource.
func V2Compliance(framework, controlID, resource string) string {
	return v2Must(V2Input{Type: TypeCompliance, Framework: framework, ControlID: controlID, Resource: resource})
}

// V2Web3 keys a contract finding by chain id, address, rule (SWC id) and
// function signature.
func V2Web3(chainID int, address, ruleID, function string) string {
	return v2Must(V2Input{Type: TypeWeb3, ChainID: chainID, ContractAddress: address, RuleID: ruleID, Function: function})
}

// V2Generic keys any other finding by rule, file and lines. No message.
func V2Generic(ruleID, filePath string, startLine, endLine int) string {
	return v2Must(V2Input{Type: TypeGeneric, RuleID: ruleID, FilePath: filePath, StartLine: startLine, EndLine: endLine})
}

func v2Must(in V2Input) string {
	s, err := V2Generate(in)
	if err != nil {
		return ""
	}
	return s
}
