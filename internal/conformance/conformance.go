// Package conformance runs the CTIS conformance vectors (conformance/v2)
// against this implementation. The same vectors let any other implementation
// check itself: they are plain JSON, see conformance/README.md.
package conformance

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/fingerprint"
	"github.com/openctemio/ctis/v2/internal/validatedoc"
)

// Result is the outcome of one vector.
type Result struct {
	Suite string // for example "canonical/domain.json" or "documents"
	Name  string
	Err   string // empty when the vector passed
}

// Run executes every vector under dir (a conformance/v2 directory) and
// returns one Result per vector. It returns an error only when dir cannot be
// read at all.
func Run(dir string) ([]Result, error) {
	if _, err := os.Stat(dir); err != nil {
		return nil, err
	}
	var out []Result
	add := func(suite, name string, err error) {
		r := Result{Suite: suite, Name: name}
		if err != nil {
			r.Err = err.Error()
		}
		out = append(out, r)
	}

	canon, _ := filepath.Glob(filepath.Join(dir, "canonical", "*.json"))
	sort.Strings(canon)
	if len(canon) == 0 {
		add("canonical", "files", fmt.Errorf("no canonical/*.json under %s", dir))
	}
	for _, f := range canon {
		runCanonical(dir, f, add)
	}
	runLocationKey(dir, add)
	runPreferredID(dir, add)
	runFingerprint(dir, add)
	runSecretDigest(dir, add)
	runCorrelation(dir, add)
	runDocuments(dir, add)
	return out, nil
}

type adder func(suite, name string, err error)

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

func mismatch(got, want string) error {
	return fmt.Errorf("got %q, want %q", got, want)
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

// errNoError is the failure of a vector that expects an error.
var errNoError = errors.New("expected an error")

func runCanonical(dir, file string, add adder) {
	suite := rel(dir, file)
	var f struct {
		Function string `json:"function"`
		Vectors  []struct {
			Function string          `json:"function"`
			Input    json.RawMessage `json:"input"`
			Output   json.RawMessage `json:"output"`
			Error    bool            `json:"error"`
		} `json:"vectors"`
	}
	if err := load(file, &f); err != nil {
		add(suite, "load", err)
		return
	}
	if len(f.Vectors) == 0 {
		add(suite, "vectors", fmt.Errorf("no vectors"))
	}
	for i, v := range f.Vectors {
		fn := v.Function
		if fn == "" {
			fn = f.Function
		}
		name := fmt.Sprintf("%d %s %s", i, fn, v.Input)
		got, err := Canonical(fn, v.Input)
		switch {
		case v.Error:
			if err == nil {
				err = fmt.Errorf("%w, got %v", errNoError, got)
			} else {
				err = nil
			}
		case err == nil:
			gotJSON, _ := json.Marshal(got)
			var a, b any
			_ = json.Unmarshal(gotJSON, &a)
			_ = json.Unmarshal(v.Output, &b)
			ga, _ := json.Marshal(a)
			gb, _ := json.Marshal(b)
			if !bytes.Equal(ga, gb) {
				err = mismatch(string(ga), string(gb))
			}
		}
		add(suite, name, err)
	}
}

func runLocationKey(dir string, add adder) {
	const suite = "location-key.json"
	var f struct {
		Cases []struct {
			Name     string          `json:"name"`
			Finding  json.RawMessage `json:"finding"`
			Expected string          `json:"expected"`
		} `json:"cases"`
	}
	if err := load(filepath.Join(dir, suite), &f); err != nil {
		add(suite, "load", err)
		return
	}
	for _, c := range f.Cases {
		var fi ctis.Finding
		err := strict(c.Finding, &fi)
		if err == nil {
			if got := ctis.LocationKey(&fi); got != c.Expected {
				err = mismatch(got, c.Expected)
			}
		}
		add(suite, c.Name, err)
	}
}

func runPreferredID(dir string, add adder) {
	const suite = "preferred-id.json"
	var f struct {
		Cases []struct {
			Name          string          `json:"name"`
			Vulnerability json.RawMessage `json:"vulnerability"`
			Expected      *struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"expected"`
		} `json:"cases"`
	}
	if err := load(filepath.Join(dir, suite), &f); err != nil {
		add(suite, "load", err)
		return
	}
	for i := range f.Cases {
		c := &f.Cases[i]
		var v ctis.VulnerabilityDetails
		if err := strict(c.Vulnerability, &v); err != nil {
			add(suite, c.Name, err)
			continue
		}
		got, ok := ctis.PreferredVulnerabilityID(&v)
		var err error
		switch {
		case c.Expected == nil && ok:
			err = fmt.Errorf("got %s %q, want none", got.Type, got.ID)
		case c.Expected != nil && !ok:
			err = fmt.Errorf("got none, want %s %q", c.Expected.Type, c.Expected.ID)
		case c.Expected != nil && (string(got.Type) != c.Expected.Type || got.ID != c.Expected.ID):
			err = mismatch(string(got.Type)+" "+got.ID, c.Expected.Type+" "+c.Expected.ID)
		}
		add(suite, c.Name, err)
	}
}

func runFingerprint(dir string, add adder) {
	const suite = "fingerprint/fingerprint.json"
	var f struct {
		Recipe string `json:"recipe"`
		Cases  []struct {
			Name     string          `json:"name"`
			Type     string          `json:"type"`
			Input    json.RawMessage `json:"input"`
			Parts    []string        `json:"parts"`
			Expected string          `json:"expected"`
			Error    bool            `json:"error"`
		} `json:"cases"`
	}
	if err := load(filepath.Join(dir, filepath.FromSlash(suite)), &f); err != nil {
		add(suite, "load", err)
		return
	}
	for _, c := range f.Cases {
		var in fingerprint.V2Input
		if err := strict(c.Input, &in); err != nil {
			add(suite, c.Name, err)
			continue
		}
		recipe, parts, perr := fingerprint.V2Parts(in)
		got, gerr := fingerprint.V2Generate(in)
		var err error
		switch {
		case c.Error:
			if perr == nil || gerr == nil {
				err = errNoError
			}
		case perr != nil || gerr != nil:
			err = errors.Join(perr, gerr)
		case recipe != c.Type || strings.Join(parts, "\x00") != strings.Join(c.Parts, "\x00") || len(parts) != len(c.Parts):
			err = fmt.Errorf("parts %q, want %q", parts, c.Parts)
		case got != c.Expected:
			err = mismatch(got, c.Expected)
		}
		add(suite, c.Name, err)
	}
}

func runSecretDigest(dir string, add adder) {
	const suite = "fingerprint/secret-digest.json"
	var f struct {
		KeyHex string `json:"key_hex"`
		Cases  []struct {
			Secret   string `json:"secret"`
			Expected string `json:"expected"`
		} `json:"cases"`
	}
	if err := load(filepath.Join(dir, filepath.FromSlash(suite)), &f); err != nil {
		add(suite, "load", err)
		return
	}
	key, err := hex.DecodeString(f.KeyHex)
	if err != nil {
		add(suite, "key", err)
		return
	}
	for i, c := range f.Cases {
		d, err := fingerprint.NewSecretDigest(key, []byte(c.Secret))
		if err == nil && d.String() != c.Expected {
			err = mismatch(d.String(), c.Expected)
		}
		add(suite, fmt.Sprintf("%d", i), err)
	}
}

func runCorrelation(dir string, add adder) {
	const suite = "correlation/correlation.json"
	var f struct {
		Cases []struct {
			Name        string          `json:"name"`
			AssetKey    string          `json:"asset_key"`
			Tool        string          `json:"tool"`
			Finding     json.RawMessage `json:"finding"`
			LocationKey string          `json:"location_key"`
			Expected    string          `json:"expected"`
		} `json:"cases"`
	}
	if err := load(filepath.Join(dir, filepath.FromSlash(suite)), &f); err != nil {
		add(suite, "load", err)
		return
	}
	for _, c := range f.Cases {
		var fi ctis.Finding
		err := strict(c.Finding, &fi)
		if err == nil {
			switch {
			case ctis.LocationKey(&fi) != c.LocationKey:
				err = fmt.Errorf("location key %q, want %q", ctis.LocationKey(&fi), c.LocationKey)
			case ctis.CorrelationKeyForTool(c.AssetKey, c.Tool, &fi) != c.Expected:
				err = mismatch(ctis.CorrelationKeyForTool(c.AssetKey, c.Tool, &fi), c.Expected)
			}
		}
		add(suite, c.Name, err)
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
}

func runDocuments(dir string, add adder) {
	const suite = "documents"
	base := filepath.Join(dir, "documents")
	var m struct {
		Documents []manifestEntry `json:"documents"`
	}
	if err := load(filepath.Join(base, "manifest.json"), &m); err != nil {
		add(suite, "manifest", err)
		return
	}
	if len(m.Documents) == 0 {
		add(suite, "manifest", fmt.Errorf("no documents"))
	}
	for _, e := range m.Documents {
		raw, err := os.ReadFile(filepath.Join(base, filepath.FromSlash(e.File)))
		if err != nil {
			add(suite, e.File, err)
			continue
		}
		add(suite, e.File, checkEntry(e, validatedoc.Check(raw)))
	}
}

func checkEntry(e manifestEntry, p *validatedoc.Problem) error {
	switch e.Result {
	case "valid":
		if p != nil {
			return fmt.Errorf("expected valid, got %s", p)
		}
	case "invalid":
		if p == nil {
			return fmt.Errorf("expected invalid, got valid")
		}
		if e.Category != "" && p.Category != e.Category {
			return fmt.Errorf("category %s, want %s (%s)", p.Category, e.Category, p.Message)
		}
		if e.Error != "" && !strings.Contains(p.Message, e.Error) {
			return fmt.Errorf("message %q does not contain %q", p.Message, e.Error)
		}
	default:
		return fmt.Errorf("manifest result %q is neither valid nor invalid", e.Result)
	}
	return nil
}

// Failures returns the results that did not pass.
func Failures(rs []Result) []Result {
	var out []Result
	for _, r := range rs {
		if r.Err != "" {
			out = append(out, r)
		}
	}
	return out
}
