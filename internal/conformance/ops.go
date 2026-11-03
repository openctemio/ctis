package conformance

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/fingerprint"
	"github.com/openctemio/ctis/v2/importer/mapping"
	"github.com/openctemio/ctis/v2/internal/validatedoc"
	"github.com/openctemio/ctis/v2/interop/engine"
	"github.com/openctemio/ctis/v2/weburl"
)

// Operations of the conformance protocol (conformance/PROTOCOL.md). Do runs
// one of them with the Go reference implementation; Run and Serve both go
// through it, so the vectors and the protocol test the same code.

// Error categories of an operation. The document categories (version,
// decode, validate) are those of the documents manifest.
const (
	CategoryProtocol    = "protocol"    // the request is malformed
	CategoryUnsupported = "unsupported" // the implementation does not provide the op
	CategoryCanonical   = "canonical"   // the value has no canonical form
	CategoryFingerprint = "fingerprint" // the input forms no fingerprint
	CategoryWebURL      = "web_url"     // the URL is refused
	CategoryVersion     = validatedoc.CategoryVersion
	CategoryDecode      = validatedoc.CategoryDecode
	CategoryValidate    = validatedoc.CategoryValidate
	CategoryMapping     = "mapping" // a mapping file is refused
	CategoryInput       = "input"   // the input of a mapping is refused as a whole
)

// OpError is the error answer of an operation.
type OpError struct {
	Category string `json:"category"`
	Message  string `json:"message"`
}

func (e *OpError) Error() string { return e.Category + ": " + e.Message }

func opErr(category string, err error) *OpError {
	return &OpError{Category: category, Message: err.Error()}
}

func badInput(op string, err error) *OpError {
	return &OpError{Category: CategoryProtocol, Message: fmt.Sprintf("%s: bad input: %v", op, err)}
}

// RequiredOps are the operations every CTIS implementation provides (the
// core); OptionalOps belong to the declarative mapping language and the
// interoperability engine, which a binding may leave out.
var (
	RequiredOps = []string{
		"canonical", "asset_key", "vulnerability_id", "preferred_id", "location_key",
		"fingerprint", "secret_digest", "correlation_key", "web_url", "decode", "validate",
	}
	OptionalOps = []string{"mapping_apply", "interop_path_match", "interop_select", "interop_collect"}
)

// Info is the output of the "info" operation.
func Info(implementation, version string) map[string]any {
	ops := append(append([]string{"info"}, RequiredOps...), OptionalOps...)
	return map[string]any{
		"implementation": implementation,
		"version":        version,
		"ctis":           ctis.SchemaVersion,
		"ops":            ops,
	}
}

// Do runs one operation on its input and returns the output, or the error
// answer. The "info" operation is answered by the caller (Serve).
func Do(op string, in json.RawMessage) (any, *OpError) {
	switch op {
	case "canonical":
		return opCanonical(in)
	case "asset_key":
		return opAssetKey(in)
	case "vulnerability_id":
		return opVulnerabilityID(in)
	case "preferred_id":
		return opPreferredID(in)
	case "location_key":
		return opLocationKey(in)
	case "fingerprint":
		return opFingerprint(in)
	case "secret_digest":
		return opSecretDigest(in)
	case "correlation_key":
		return opCorrelationKey(in)
	case "web_url":
		return opWebURL(in)
	case "decode":
		return opDecode(in)
	case "validate":
		return opValidate(in)
	case "mapping_apply":
		return opMappingApply(in)
	case "interop_path_match":
		return opInteropPathMatch(in)
	case "interop_select":
		return opInteropSelect(in)
	case "interop_collect":
		return opInteropCollect(in)
	}
	return nil, &OpError{Category: CategoryUnsupported, Message: fmt.Sprintf("unknown op %q", op)}
}

func opCanonical(in json.RawMessage) (any, *OpError) {
	var req struct {
		Function string          `json:"function"`
		Value    json.RawMessage `json:"value"`
	}
	if err := strict(in, &req); err != nil {
		return nil, badInput("canonical", err)
	}
	if !knownFunction(req.Function) {
		return nil, &OpError{Category: CategoryProtocol, Message: fmt.Sprintf("canonical: unknown function %q", req.Function)}
	}
	out, err := Canonical(req.Function, req.Value)
	if err != nil {
		if errors.Is(err, ctis.ErrNotCanonicalizable) {
			return nil, opErr(CategoryCanonical, err)
		}
		return nil, badInput("canonical", err)
	}
	return out, nil
}

func opAssetKey(in json.RawMessage) (any, *OpError) {
	var req struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	if err := strict(in, &req); err != nil {
		return nil, badInput("asset_key", err)
	}
	return ctis.AssetKey(ctis.AssetType(req.Type), req.Value), nil
}

type typedID struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func opVulnerabilityID(in json.RawMessage) (any, *OpError) {
	var req struct {
		ID string `json:"id"`
	}
	if err := strict(in, &req); err != nil {
		return nil, badInput("vulnerability_id", err)
	}
	id, ok := ctis.NormalizeVulnerabilityID(req.ID)
	if !ok {
		return nil, nil
	}
	return typedID{string(id.Type), id.ID}, nil
}

func opPreferredID(in json.RawMessage) (any, *OpError) {
	var req struct {
		Vulnerability json.RawMessage `json:"vulnerability"`
	}
	var v ctis.VulnerabilityDetails
	if err := strict(in, &req); err != nil {
		return nil, badInput("preferred_id", err)
	}
	if err := strict(req.Vulnerability, &v); err != nil {
		return nil, badInput("preferred_id", err)
	}
	id, ok := ctis.PreferredVulnerabilityID(&v)
	if !ok {
		return nil, nil
	}
	return typedID{string(id.Type), id.ID}, nil
}

func decodeFinding(op string, raw json.RawMessage) (*ctis.Finding, *OpError) {
	var f ctis.Finding
	if err := strict(raw, &f); err != nil {
		return nil, badInput(op, err)
	}
	return &f, nil
}

func opLocationKey(in json.RawMessage) (any, *OpError) {
	var req struct {
		Finding json.RawMessage `json:"finding"`
	}
	if err := strict(in, &req); err != nil {
		return nil, badInput("location_key", err)
	}
	f, e := decodeFinding("location_key", req.Finding)
	if e != nil {
		return nil, e
	}
	return ctis.LocationKey(f), nil
}

func opFingerprint(in json.RawMessage) (any, *OpError) {
	var req struct {
		Input  json.RawMessage `json:"input"`
		Detect bool            `json:"detect"`
	}
	if err := strict(in, &req); err != nil {
		return nil, badInput("fingerprint", err)
	}
	var fi fingerprint.V2Input
	if err := strict(req.Input, &fi); err != nil {
		return nil, badInput("fingerprint", err)
	}
	if req.Detect && fi.Type == "" {
		fi.Type = fingerprint.V2Detect(fi)
	}
	recipe, parts, err := fingerprint.V2Parts(fi)
	if err != nil {
		return nil, opErr(CategoryFingerprint, err)
	}
	value, err := fingerprint.V2Generate(fi)
	if err != nil {
		return nil, opErr(CategoryFingerprint, err)
	}
	if parts == nil {
		parts = []string{}
	}
	return map[string]any{"recipe": recipe, "parts": parts, "value": value}, nil
}

func opSecretDigest(in json.RawMessage) (any, *OpError) {
	var req struct {
		KeyHex string `json:"key_hex"`
		Secret string `json:"secret"`
	}
	if err := strict(in, &req); err != nil {
		return nil, badInput("secret_digest", err)
	}
	key, err := hex.DecodeString(req.KeyHex)
	if err != nil {
		return nil, badInput("secret_digest", err)
	}
	d, err := fingerprint.NewSecretDigest(key, []byte(req.Secret))
	if err != nil {
		return nil, opErr(CategoryFingerprint, err)
	}
	return d.String(), nil
}

func opCorrelationKey(in json.RawMessage) (any, *OpError) {
	var req struct {
		AssetKey string          `json:"asset_key"`
		Tool     string          `json:"tool"`
		Finding  json.RawMessage `json:"finding"`
	}
	if err := strict(in, &req); err != nil {
		return nil, badInput("correlation_key", err)
	}
	f, e := decodeFinding("correlation_key", req.Finding)
	if e != nil {
		return nil, e
	}
	// The intermediate part 2 (spec: docs/fingerprints.md), published so
	// another implementation can compare each step.
	id := ""
	if f.Vulnerability != nil {
		if v, ok := ctis.PreferredVulnerabilityID(f.Vulnerability); ok {
			id = v.ID
		}
	}
	if id == "" {
		id = "rule:" + strings.TrimSpace(req.Tool) + "/" + strings.TrimSpace(f.RuleID)
	}
	return map[string]any{
		"vulnerability_id": id,
		"location_key":     ctis.LocationKey(f),
		"key":              ctis.CorrelationKeyForTool(req.AssetKey, req.Tool, f),
	}, nil
}

func opWebURL(in json.RawMessage) (any, *OpError) {
	var req struct {
		URL string `json:"url"`
	}
	if err := strict(in, &req); err != nil {
		return nil, badInput("web_url", err)
	}
	u, err := weburl.Parse(req.URL)
	if err != nil {
		return nil, opErr(CategoryWebURL, err)
	}
	params := u.Params
	if params == nil {
		params = []string{}
	}
	return map[string]any{"origin": u.Origin(), "path": u.Path, "template": u.Template(), "params": params}, nil
}

// documentBytes is the document of a decode or validate request: "text",
// the exact bytes, or "document", a JSON value taken as written.
func documentBytes(op string, in json.RawMessage) ([]byte, *OpError) {
	var req struct {
		Document json.RawMessage `json:"document"`
		Text     *string         `json:"text"`
	}
	if err := strict(in, &req); err != nil {
		return nil, badInput(op, err)
	}
	switch {
	case req.Text != nil && req.Document == nil:
		return []byte(*req.Text), nil
	case req.Text == nil && req.Document != nil:
		return req.Document, nil
	}
	return nil, badInput(op, errors.New("exactly one of document and text"))
}

func opDecode(in json.RawMessage) (any, *OpError) {
	raw, e := documentBytes("decode", in)
	if e != nil {
		return nil, e
	}
	// A version problem first, as the strict receiver reports it.
	var head struct {
		Version *string `json:"version"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, opErr(CategoryDecode, err)
	}
	if head.Version == nil {
		return nil, &OpError{Category: CategoryVersion, Message: "version is required"}
	}
	if major, _, ok := ctis.ParseVersion(*head.Version); !ok || major != ctis.SchemaMajor {
		_, _, err := ctis.Decode(bytes.NewReader(raw))
		if err == nil {
			err = fmt.Errorf("unsupported version %q", *head.Version)
		}
		return nil, opErr(CategoryVersion, err)
	}
	rep, unknown, err := ctis.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, opErr(CategoryDecode, err)
	}
	// The entries are a set: the protocol lists them sorted by path, then
	// kind, so any walk order gives the same answer.
	entries := append([]ctis.UnknownEntry{}, unknown.Entries...)
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Path != entries[j].Path {
			return entries[i].Path < entries[j].Path
		}
		return entries[i].Kind < entries[j].Kind
	})
	return map[string]any{"report": rep, "unknown": entries, "omitted": unknown.Omitted}, nil
}

func opValidate(in json.RawMessage) (any, *OpError) {
	raw, e := documentBytes("validate", in)
	if e != nil {
		return nil, e
	}
	if p := validatedoc.Check(raw); p != nil {
		return nil, &OpError{Category: p.Category, Message: p.Message}
	}
	return map[string]any{"valid": true}, nil
}

func opMappingApply(in json.RawMessage) (any, *OpError) {
	var req struct {
		Mapping json.RawMessage `json:"mapping"`
		Input   string          `json:"input"`
		Options struct {
			Now          string         `json:"now"`
			ReportID     string         `json:"report_id"`
			Tool         *ctis.Tool     `json:"tool"`
			Channel      string         `json:"channel"`
			DefaultAsset *ctis.Asset    `json:"default_asset"`
			Observe      bool           `json:"observe"`
			Limits       map[string]int `json:"limits"`
		} `json:"options"`
	}
	if err := strict(in, &req); err != nil {
		return nil, badInput("mapping_apply", err)
	}
	m, err := mapping.Load(req.Mapping)
	if err != nil {
		return nil, opErr(CategoryMapping, err)
	}
	opts := mapping.Options{
		ReportID:     req.Options.ReportID,
		Tool:         req.Options.Tool,
		Channel:      ctis.Channel(req.Options.Channel),
		DefaultAsset: req.Options.DefaultAsset,
		Observe:      req.Options.Observe,
	}
	if req.Options.Now != "" {
		now, err := time.Parse(time.RFC3339Nano, req.Options.Now)
		if err != nil {
			return nil, badInput("mapping_apply", err)
		}
		opts.Now = func() time.Time { return now }
	}
	for k, v := range req.Options.Limits {
		switch k {
		case "max_input_bytes":
			opts.MaxInputBytes = int64(v)
		case "max_record_bytes":
			opts.MaxRecordBytes = v
		case "max_records":
			opts.MaxRecords = v
		case "max_outputs":
			opts.MaxOutputs = v
		case "max_issues":
			opts.MaxIssues = v
		case "max_cell_bytes":
			opts.MaxCellBytes = v
		case "max_xml_elements":
			opts.MaxXMLElements = v
		default:
			return nil, badInput("mapping_apply", fmt.Errorf("unknown limit %q", k))
		}
	}
	rep, st, err := m.Apply(context.Background(), strings.NewReader(req.Input), opts)
	if err != nil {
		return nil, opErr(CategoryInput, err)
	}
	issues := make([]map[string]int, 0, len(st.Issues))
	for _, is := range st.Issues {
		issues = append(issues, map[string]int{"record": is.Record, "rule": is.Rule})
	}
	stats := map[string]any{
		"records": st.Records, "assets": st.Assets, "findings": st.Findings, "dependencies": st.Dependencies,
		"skipped": st.Skipped, "truncated": st.Truncated, "issues": issues,
	}
	if opts.Observe {
		stats["fields"] = nonNil(st.Fields)
		stats["fields_truncated"] = st.FieldsTruncated
		stats["unmapped"] = nonNil(st.Unmapped)
	}
	return map[string]any{"report": rep, "stats": stats}, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func opInteropPathMatch(in json.RawMessage) (any, *OpError) {
	var req struct {
		Pattern string `json:"pattern"`
		Path    string `json:"path"`
	}
	if err := strict(in, &req); err != nil {
		return nil, badInput("interop_path_match", err)
	}
	return engine.MatchPath(req.Pattern, req.Path), nil
}

func loadInterop(raw json.RawMessage) (*engine.Mapping, *OpError) {
	m, err := engine.Load(raw, engine.LoadOptions{})
	if err != nil {
		return nil, opErr(CategoryMapping, err)
	}
	return m, nil
}

func opInteropSelect(in json.RawMessage) (any, *OpError) {
	var req struct {
		Mappings []json.RawMessage `json:"mappings"`
		Document json.RawMessage   `json:"document"`
	}
	if err := strict(in, &req); err != nil {
		return nil, badInput("interop_select", err)
	}
	ms := make([]*engine.Mapping, 0, len(req.Mappings))
	for _, raw := range req.Mappings {
		m, e := loadInterop(raw)
		if e != nil {
			return nil, e
		}
		ms = append(ms, m)
	}
	set, err := engine.NewSet(ms...)
	if err != nil {
		return nil, opErr(CategoryMapping, err)
	}
	m, err := set.Select(req.Document)
	if err != nil {
		return nil, opErr(CategoryInput, err)
	}
	return m.Version, nil
}

func opInteropCollect(in json.RawMessage) (any, *OpError) {
	var req struct {
		Mapping  json.RawMessage `json:"mapping"`
		Document json.RawMessage `json:"document"`
		Records  []string        `json:"records"`
	}
	if err := strict(in, &req); err != nil {
		return nil, badInput("interop_collect", err)
	}
	m, e := loadInterop(req.Mapping)
	if e != nil {
		return nil, e
	}
	p, err := m.Collect(req.Document)
	if err != nil {
		return nil, opErr(CategoryInput, err)
	}
	records := map[string]any{}
	for _, ptr := range req.Records {
		set, err := setMembers(m, p, ptr)
		if err != nil {
			return nil, badInput("interop_collect", err)
		}
		records[ptr] = map[string]any{"extension": p.RecordExtension(ptr, nil), "set": set}
	}
	return map[string]any{"version": p.Version(), "report": p.DocExtension(), "records": records}, nil
}

// setMembers applies the set rules of the record at ptr to an empty record
// of its kind and returns the members they wrote, as dotted names.
func setMembers(m *engine.Mapping, p *engine.Passthrough, ptr string) (map[string]any, error) {
	path, ok := engine.PointerPath(ptr)
	if !ok {
		return nil, fmt.Errorf("record pointer %q", ptr)
	}
	kind := ""
	for _, r := range m.Records {
		if engine.MatchPath(r.Path, m.FoldPath(path)) {
			kind = r.Kind
			break
		}
	}
	var target any
	switch kind {
	case "finding":
		target = &ctis.Finding{}
	case "asset":
		target = &ctis.Asset{}
	case "dependency":
		target = &ctis.Dependency{}
	case "vex":
		target = &ctis.VEX{}
	default:
		return nil, fmt.Errorf("%q is not a record of the mapping", ptr)
	}
	before := flatten(target)
	if err := p.Apply(ptr, target); err != nil {
		return nil, err
	}
	out := map[string]any{}
	for k, v := range flatten(target) {
		if b, ok := before[k]; !ok || !jsonEqual(b, v) {
			out[k] = v
		}
	}
	return out, nil
}

// flatten encodes v and lists its leaves by dotted member name.
func flatten(v any) map[string]any {
	raw, _ := json.Marshal(v)
	var tree any
	_ = json.Unmarshal(raw, &tree)
	out := map[string]any{}
	var walk func(prefix string, t any)
	walk = func(prefix string, t any) {
		if m, ok := t.(map[string]any); ok && len(m) > 0 {
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				walk(p, m[k])
			}
			return
		}
		if prefix != "" {
			out[prefix] = t
		}
	}
	walk("", tree)
	return out
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// knownFunction reports whether Canonical implements a function name.
func knownFunction(fn string) bool {
	for _, f := range CanonicalFunctions {
		if f == fn {
			return true
		}
	}
	return false
}

// CanonicalFunctions are the function names of the "canonical" operation.
var CanonicalFunctions = []string{
	"CanonicalAssetValue", "CanonicalDomain", "CanonicalIP", "CanonicalCIDR", "CanonicalService",
	"CanonicalOrigin", "CanonicalURL", "CanonicalRepository", "CanonicalPurl", "CanonicalCPE",
	"CanonicalImage", "CanonicalARN", "CanonicalAzureResourceID", "CanonicalGCPResourceName",
	"CanonicalCertificateFingerprint",
}
