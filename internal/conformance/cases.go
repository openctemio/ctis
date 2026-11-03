package conformance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/openctemio/ctis/v2"
)

// Case is one vector as a protocol request and the answer it expects.
// scripts/conformance_harness.py builds the same cases from the same files.
type Case struct {
	Suite   string
	Name    string
	Op      string
	Input   json.RawMessage
	Want    json.RawMessage // the expected output when WantErr is nil
	WantErr *WantError
}

// WantError is an expected error answer: the category (empty: any) and a
// substring of the message (informative, see Check).
type WantError struct {
	Category string `json:"category"`
	Message  string `json:"message,omitempty"`
}

// LoadError is a vector file that could not be read; it counts as a failed
// vector.
type LoadError struct {
	Suite, Name, Err string
}

// errNoError is the failure of a vector that expects an error.
var errNoError = errors.New("expected an error")

// Cases reads every vector family under dir (a conformance/v2 directory).
func Cases(dir string) ([]Case, []LoadError) {
	l := &loader{dir: dir}
	canon, _ := filepath.Glob(filepath.Join(dir, "canonical", "*.json"))
	sort.Strings(canon)
	if len(canon) == 0 {
		l.fail("canonical", "files", fmt.Errorf("no canonical/*.json under %s", dir))
	}
	for _, f := range canon {
		l.canonical(f)
	}
	l.vulnerabilityID()
	l.locationKey()
	l.preferredID()
	l.fingerprint()
	l.secretDigest()
	l.correlation()
	l.webURL()
	l.decode()
	l.documents()
	l.mapping()
	l.interop()
	return l.cases, l.errs
}

type loader struct {
	dir   string
	cases []Case
	errs  []LoadError
}

func (l *loader) fail(suite, name string, err error) {
	l.errs = append(l.errs, LoadError{Suite: suite, Name: name, Err: err.Error()})
}

func (l *loader) add(suite, name, op string, input any, want any, wantErr *WantError) {
	in, err := json.Marshal(input)
	if err != nil {
		l.fail(suite, name, err)
		return
	}
	c := Case{Suite: suite, Name: name, Op: op, Input: in, WantErr: wantErr}
	if wantErr == nil {
		w, err := json.Marshal(want)
		if err != nil {
			l.fail(suite, name, err)
			return
		}
		c.Want = w
	}
	l.cases = append(l.cases, c)
}

// file loads a vector file of dir into v and reports a failure when it
// cannot.
func (l *loader) file(suite string, v any) bool {
	if err := load(filepath.Join(l.dir, filepath.FromSlash(suite)), v); err != nil {
		l.fail(suite, "load", err)
		return false
	}
	return true
}

func rel(dir, f string) string {
	r, err := filepath.Rel(dir, f)
	if err != nil {
		return f
	}
	return filepath.ToSlash(r)
}

func load(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// strict decodes raw into v with unknown members refused, so a vector that
// uses a member name the implementation does not know fails loudly.
func strict(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func errWant(b bool, category string) *WantError {
	if !b {
		return nil
	}
	return &WantError{Category: category}
}

// Canonical applies a canonical-form function named by a vector file to the
// vector's input and returns the result (a string, or an object for
// CanonicalPurl).
func Canonical(fn string, in json.RawMessage) (any, error) {
	var s string
	str := func() (string, error) {
		if err := json.Unmarshal(in, &s); err != nil {
			return "", fmt.Errorf("%s: input is not a string: %s", fn, in)
		}
		return s, nil
	}
	one := func(f func(string) (string, error)) (any, error) {
		v, err := str()
		if err != nil {
			return nil, err
		}
		return f(v)
	}
	switch fn {
	case "CanonicalDomain":
		return one(ctis.CanonicalDomain)
	case "CanonicalIP":
		return one(ctis.CanonicalIP)
	case "CanonicalCIDR":
		return one(ctis.CanonicalCIDR)
	case "CanonicalOrigin":
		return one(ctis.CanonicalOrigin)
	case "CanonicalURL":
		return one(ctis.CanonicalURL)
	case "CanonicalCPE":
		return one(ctis.CanonicalCPE)
	case "CanonicalARN":
		return one(ctis.CanonicalARN)
	case "CanonicalAzureResourceID":
		return one(ctis.CanonicalAzureResourceID)
	case "CanonicalGCPResourceName":
		return one(ctis.CanonicalGCPResourceName)
	case "CanonicalImage":
		return one(ctis.CanonicalImage)
	case "CanonicalCertificateFingerprint":
		return one(ctis.CanonicalCertificateFingerprint)
	case "CanonicalRepository":
		return one(ctis.CanonicalRepository)
	case "CanonicalPurl":
		v, err := str()
		if err != nil {
			return nil, err
		}
		id, ver, err := ctis.CanonicalPurl(v)
		return map[string]string{"identity": id, "version": ver}, err
	case "CanonicalService":
		var v struct {
			Host      string `json:"host"`
			Port      int    `json:"port"`
			Transport string `json:"transport"`
		}
		if err := strict(in, &v); err != nil {
			return nil, err
		}
		return ctis.CanonicalService(v.Host, v.Port, v.Transport)
	case "CanonicalAssetValue":
		var v struct {
			Type  ctis.AssetType `json:"type"`
			Value string         `json:"value"`
		}
		if err := strict(in, &v); err != nil {
			return nil, err
		}
		return ctis.CanonicalAssetValue(v.Type, v.Value)
	case "AssetKey":
		var v struct {
			Type  ctis.AssetType `json:"type"`
			Value string         `json:"value"`
		}
		if err := strict(in, &v); err != nil {
			return nil, err
		}
		return ctis.AssetKey(v.Type, v.Value), nil
	}
	return nil, fmt.Errorf("unknown function %q", fn)
}

func (l *loader) canonical(file string) {
	suite := rel(l.dir, file)
	var f struct {
		Function string `json:"function"`
		Vectors  []struct {
			Function string          `json:"function"`
			Input    json.RawMessage `json:"input"`
			Output   json.RawMessage `json:"output"`
			Error    bool            `json:"error"`
		} `json:"vectors"`
	}
	if !l.file(suite, &f) {
		return
	}
	if len(f.Vectors) == 0 {
		l.fail(suite, "vectors", fmt.Errorf("no vectors"))
	}
	for i, v := range f.Vectors {
		fn := v.Function
		if fn == "" {
			fn = f.Function
		}
		name := fmt.Sprintf("%d %s %s", i, fn, v.Input)
		if fn == "AssetKey" {
			// The asset key takes {type, value} as given.
			l.add(suite, name, "asset_key", v.Input, v.Output, errWant(v.Error, CategoryCanonical))
			continue
		}
		l.add(suite, name, "canonical", map[string]any{"function": fn, "value": v.Input}, v.Output, errWant(v.Error, CategoryCanonical))
	}
}

func (l *loader) vulnerabilityID() {
	const suite = "vulnerability-id.json"
	var f struct {
		Cases []struct {
			Name     string          `json:"name"`
			ID       string          `json:"id"`
			Expected json.RawMessage `json:"expected"`
		} `json:"cases"`
	}
	if !l.file(suite, &f) {
		return
	}
	for _, c := range f.Cases {
		l.add(suite, c.Name, "vulnerability_id", map[string]any{"id": c.ID}, c.Expected, nil)
	}
}

func (l *loader) locationKey() {
	const suite = "location-key.json"
	var f struct {
		Cases []struct {
			Name     string          `json:"name"`
			Finding  json.RawMessage `json:"finding"`
			Expected string          `json:"expected"`
		} `json:"cases"`
	}
	if !l.file(suite, &f) {
		return
	}
	for _, c := range f.Cases {
		l.add(suite, c.Name, "location_key", map[string]any{"finding": c.Finding}, c.Expected, nil)
	}
}

func (l *loader) preferredID() {
	const suite = "preferred-id.json"
	var f struct {
		Cases []struct {
			Name          string          `json:"name"`
			Vulnerability json.RawMessage `json:"vulnerability"`
			Expected      json.RawMessage `json:"expected"`
		} `json:"cases"`
	}
	if !l.file(suite, &f) {
		return
	}
	for _, c := range f.Cases {
		l.add(suite, c.Name, "preferred_id", map[string]any{"vulnerability": c.Vulnerability}, c.Expected, nil)
	}
}

func (l *loader) fingerprint() {
	const suite = "fingerprint/fingerprint.json"
	var f struct {
		Cases []struct {
			Name     string          `json:"name"`
			Type     string          `json:"type"`
			Detect   bool            `json:"detect"`
			Input    json.RawMessage `json:"input"`
			Parts    []string        `json:"parts"`
			Expected string          `json:"expected"`
			Error    bool            `json:"error"`
		} `json:"cases"`
	}
	if !l.file(suite, &f) {
		return
	}
	for _, c := range f.Cases {
		in := map[string]any{"input": c.Input}
		if c.Detect {
			in["detect"] = true
		}
		parts := c.Parts
		if parts == nil {
			parts = []string{}
		}
		l.add(suite, c.Name, "fingerprint", in, map[string]any{"recipe": c.Type, "parts": parts, "value": c.Expected}, errWant(c.Error, CategoryFingerprint))
	}
}

func (l *loader) secretDigest() {
	const suite = "fingerprint/secret-digest.json"
	var f struct {
		KeyHex string `json:"key_hex"`
		Cases  []struct {
			Secret   string `json:"secret"`
			Expected string `json:"expected"`
		} `json:"cases"`
	}
	if !l.file(suite, &f) {
		return
	}
	for i, c := range f.Cases {
		l.add(suite, fmt.Sprint(i), "secret_digest", map[string]any{"key_hex": f.KeyHex, "secret": c.Secret}, c.Expected, nil)
	}
}

func (l *loader) correlation() {
	const suite = "correlation/correlation.json"
	var f struct {
		Cases []struct {
			Name            string          `json:"name"`
			AssetKey        string          `json:"asset_key"`
			Tool            string          `json:"tool"`
			Finding         json.RawMessage `json:"finding"`
			VulnerabilityID string          `json:"vulnerability_id"`
			LocationKey     string          `json:"location_key"`
			Expected        string          `json:"expected"`
		} `json:"cases"`
	}
	if !l.file(suite, &f) {
		return
	}
	for _, c := range f.Cases {
		l.add(suite, c.Name, "correlation_key",
			map[string]any{"asset_key": c.AssetKey, "tool": c.Tool, "finding": c.Finding},
			map[string]any{"vulnerability_id": c.VulnerabilityID, "location_key": c.LocationKey, "key": c.Expected}, nil)
	}
}

func (l *loader) webURL() {
	const suite = "weburl/urls.json"
	var f struct {
		Cases []struct {
			In       string   `json:"in"`
			Origin   string   `json:"origin"`
			Path     string   `json:"path"`
			Template string   `json:"template"`
			Params   []string `json:"params"`
			Error    bool     `json:"error"`
		} `json:"cases"`
	}
	if !l.file(suite, &f) {
		return
	}
	for i, c := range f.Cases {
		params := c.Params
		if params == nil {
			params = []string{}
		}
		l.add(suite, fmt.Sprintf("%d %q", i, c.In), "web_url", map[string]any{"url": c.In},
			map[string]any{"origin": c.Origin, "path": c.Path, "template": c.Template, "params": params}, errWant(c.Error, CategoryWebURL))
	}
}

func (l *loader) decode() {
	const suite = "decode/decode.json"
	var f struct {
		Cases []struct {
			Name     string          `json:"name"`
			Document json.RawMessage `json:"document"`
			Text     *string         `json:"text"`
			Expected json.RawMessage `json:"expected"`
			Error    *WantError      `json:"error"`
		} `json:"cases"`
	}
	if !l.file(suite, &f) {
		return
	}
	for _, c := range f.Cases {
		in := map[string]any{}
		if c.Text != nil {
			in["text"] = *c.Text
		} else {
			in["document"] = c.Document
		}
		l.add(suite, c.Name, "decode", in, c.Expected, c.Error)
	}
}

// manifestEntry is one line of documents/manifest.json.
type manifestEntry struct {
	File   string `json:"file"`
	Result string `json:"result"` // "valid" or "invalid"
	// Category and Error say why an invalid document is refused: the problem
	// category (decode, version, validate) and a substring of its message.
	Category string `json:"category,omitempty"`
	Error    string `json:"error,omitempty"`
	// SchemaLevel is false when only semantic validation (Report.Validate)
	// refuses the document and schemas/v2 alone accepts it.
	SchemaLevel *bool `json:"schema_level,omitempty"`
	// Rule is the id of the validation rule (docs/validation-rules.md) the
	// document breaks.
	Rule string `json:"rule,omitempty"`
}

func (l *loader) documents() {
	const suite = "documents"
	base := filepath.Join(l.dir, "documents")
	var m struct {
		Documents []manifestEntry `json:"documents"`
	}
	if err := load(filepath.Join(base, "manifest.json"), &m); err != nil {
		l.fail(suite, "manifest", err)
		return
	}
	if len(m.Documents) == 0 {
		l.fail(suite, "manifest", fmt.Errorf("no documents"))
	}
	for _, e := range m.Documents {
		raw, err := os.ReadFile(filepath.Join(base, filepath.FromSlash(e.File)))
		if err != nil {
			l.fail(suite, e.File, err)
			continue
		}
		in := map[string]any{"text": string(raw)}
		switch e.Result {
		case "valid":
			l.add(suite, e.File, "validate", in, map[string]any{"valid": true}, nil)
		case "invalid":
			l.add(suite, e.File, "validate", in, nil, &WantError{Category: e.Category, Message: e.Error})
		default:
			l.fail(suite, e.File, fmt.Errorf("manifest result %q is neither valid nor invalid", e.Result))
		}
	}
}

// readRef returns the value of a vector member that is inline (inline) or
// names a file relative to the vector file (file): JSON is parsed, text is
// returned as a JSON string.
func (l *loader) readRef(suiteDir string, inline json.RawMessage, file string, asText bool) (json.RawMessage, error) {
	if file == "" {
		if inline == nil {
			return nil, errors.New("missing value")
		}
		return inline, nil
	}
	raw, err := os.ReadFile(filepath.Join(l.dir, filepath.FromSlash(suiteDir), filepath.FromSlash(file)))
	if err != nil {
		return nil, err
	}
	if asText {
		return json.Marshal(string(raw))
	}
	if !json.Valid(raw) {
		return nil, fmt.Errorf("%s is not JSON", file)
	}
	return raw, nil
}

func (l *loader) mapping() {
	const suite = "mapping/vectors.json"
	var f struct {
		Cases []struct {
			Name           string          `json:"name"`
			Mapping        json.RawMessage `json:"mapping"`
			MappingFile    string          `json:"mapping_file"`
			Input          json.RawMessage `json:"input"`
			InputFile      string          `json:"input_file"`
			Options        json.RawMessage `json:"options"`
			ExpectedReport json.RawMessage `json:"expected_report"`
			ReportFile     string          `json:"expected_report_file"`
			ExpectedStats  json.RawMessage `json:"expected_stats"`
			Error          *WantError      `json:"error"`
		} `json:"cases"`
	}
	if !l.file(suite, &f) {
		return
	}
	for _, c := range f.Cases {
		m, err := l.readRef("mapping", c.Mapping, c.MappingFile, false)
		if err != nil {
			l.fail(suite, c.Name, fmt.Errorf("mapping: %w", err))
			continue
		}
		in, err := l.readRef("mapping", c.Input, c.InputFile, true)
		if err != nil {
			l.fail(suite, c.Name, fmt.Errorf("input: %w", err))
			continue
		}
		req := map[string]json.RawMessage{"mapping": m, "input": in}
		if c.Options != nil {
			req["options"] = c.Options
		}
		if c.Error != nil {
			l.add(suite, c.Name, "mapping_apply", req, nil, c.Error)
			continue
		}
		rep, err := l.readRef("mapping", c.ExpectedReport, c.ReportFile, false)
		if err != nil {
			l.fail(suite, c.Name, fmt.Errorf("expected report: %w", err))
			continue
		}
		l.add(suite, c.Name, "mapping_apply", req, map[string]json.RawMessage{"report": rep, "stats": c.ExpectedStats}, nil)
	}
}

func (l *loader) interop() {
	{
		const suite = "interop-engine/path.json"
		var f struct {
			Cases []struct {
				Pattern string `json:"pattern"`
				Path    string `json:"path"`
				Match   bool   `json:"match"`
			} `json:"cases"`
		}
		if l.file(suite, &f) {
			for _, c := range f.Cases {
				l.add(suite, c.Pattern+" ~ "+c.Path, "interop_path_match", map[string]any{"pattern": c.Pattern, "path": c.Path}, c.Match, nil)
			}
		}
	}
	{
		const suite = "interop-engine/select.json"
		var f struct {
			Mappings []json.RawMessage `json:"mappings"`
			Cases    []struct {
				Name     string          `json:"name"`
				Document json.RawMessage `json:"document"`
				Expected json.RawMessage `json:"expected"`
				Error    *WantError      `json:"error"`
			} `json:"cases"`
		}
		if l.file(suite, &f) {
			for _, c := range f.Cases {
				l.add(suite, c.Name, "interop_select", map[string]any{"mappings": f.Mappings, "document": c.Document}, c.Expected, c.Error)
			}
		}
	}
	{
		const suite = "interop-engine/collect.json"
		var f struct {
			Cases []struct {
				Name     string          `json:"name"`
				Mapping  json.RawMessage `json:"mapping"`
				Document json.RawMessage `json:"document"`
				Records  []string        `json:"records"`
				Expected json.RawMessage `json:"expected"`
				Error    *WantError      `json:"error"`
			} `json:"cases"`
		}
		if l.file(suite, &f) {
			for _, c := range f.Cases {
				records := c.Records
				if records == nil {
					records = []string{}
				}
				l.add(suite, c.Name, "interop_collect", map[string]any{"mapping": c.Mapping, "document": c.Document, "records": records}, c.Expected, c.Error)
			}
		}
	}
}
