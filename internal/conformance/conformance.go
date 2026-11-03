// Package conformance runs the CTIS conformance vectors (the conformance/
// directory) against this implementation. The same vectors let any other
// implementation check itself: they are plain JSON, see conformance/README.md.
package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/fingerprint"
	"github.com/openctemio/ctis/internal/validatedoc"
)

// Result is the outcome of one vector.
type Result struct {
	Suite string // for example "canonical/domain.json" or "documents"
	Name  string
	Err   string // empty when the vector passed
}

// Run executes every vector under dir and returns one Result per vector. It
// returns an error only when dir cannot be read at all.
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

func mismatch(got, want string) error {
	return fmt.Errorf("got %q, want %q", got, want)
}

func runCanonical(dir, file string, add adder) {
	suite := rel(dir, file)
	var f struct {
		Cases []struct {
			Type     string `json:"type"`
			Input    string `json:"input"`
			Expected string `json:"expected"`
		} `json:"cases"`
	}
	if err := load(file, &f); err != nil {
		add(suite, "load", err)
		return
	}
	if len(f.Cases) == 0 {
		add(suite, "cases", fmt.Errorf("no cases"))
	}
	for _, c := range f.Cases {
		got := ctis.NormalizeAssetName(ctis.AssetType(c.Type), c.Input)
		var err error
		if got != c.Expected {
			err = mismatch(got, c.Expected)
		}
		add(suite, c.Type+" "+c.Input, err)
	}
}

func runLocationKey(dir string, add adder) {
	const suite = "location-key.json"
	var f struct {
		Cases []struct {
			Name     string       `json:"name"`
			Finding  ctis.Finding `json:"finding"`
			Expected string       `json:"expected"`
		} `json:"cases"`
	}
	if err := load(filepath.Join(dir, suite), &f); err != nil {
		add(suite, "load", err)
		return
	}
	for i := range f.Cases {
		c := &f.Cases[i]
		var err error
		if got := ctis.LocationKey(&c.Finding); got != c.Expected {
			err = mismatch(got, c.Expected)
		}
		add(suite, c.Name, err)
	}
}

func runPreferredID(dir string, add adder) {
	const suite = "preferred-id.json"
	var f struct {
		Cases []struct {
			Name          string                    `json:"name"`
			Vulnerability ctis.VulnerabilityDetails `json:"vulnerability"`
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
		got, ok := ctis.PreferredVulnerabilityID(&c.Vulnerability)
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
	const suite = "fingerprint.json"
	var f struct {
		Cases []struct {
			Name  string `json:"name"`
			Type  string `json:"type"`
			Input struct {
				RuleID            string `json:"rule_id"`
				FilePath          string `json:"file_path"`
				Message           string `json:"message"`
				StartLine         int    `json:"start_line"`
				EndLine           int    `json:"end_line"`
				PackageName       string `json:"package_name"`
				PackageVersion    string `json:"package_version"`
				VulnerabilityID   string `json:"vulnerability_id"`
				Snippet           string `json:"snippet"`
				LogicalLocation   string `json:"logical_location"`
				SecretValue       string `json:"secret_value"`
				ResourceType      string `json:"resource_type"`
				ResourceName      string `json:"resource_name"`
				TargetHost        string `json:"target_host"`
				TargetPath        string `json:"target_path"`
				Parameter         string `json:"parameter"`
				ImageTarget       string `json:"image_target"`
				ContractAddress   string `json:"contract_address"`
				ChainID           int    `json:"chain_id"`
				SWCID             string `json:"swc_id"`
				FunctionSignature string `json:"function_signature"`
			} `json:"input"`
			Expected string `json:"expected"`
		} `json:"cases"`
	}
	if err := load(filepath.Join(dir, suite), &f); err != nil {
		add(suite, "load", err)
		return
	}
	for _, c := range f.Cases {
		in := fingerprint.Input{
			Type: fingerprint.Type(c.Type), RuleID: c.Input.RuleID, FilePath: c.Input.FilePath,
			Message: c.Input.Message, StartLine: c.Input.StartLine, EndLine: c.Input.EndLine,
			PackageName: c.Input.PackageName, PackageVersion: c.Input.PackageVersion,
			VulnerabilityID: c.Input.VulnerabilityID, Snippet: c.Input.Snippet,
			LogicalLocation: c.Input.LogicalLocation, SecretValue: c.Input.SecretValue,
			ResourceType: c.Input.ResourceType, ResourceName: c.Input.ResourceName,
			TargetHost: c.Input.TargetHost, TargetPath: c.Input.TargetPath, Parameter: c.Input.Parameter,
			ImageTarget: c.Input.ImageTarget, ContractAddress: c.Input.ContractAddress,
			ChainID: c.Input.ChainID, SWCID: c.Input.SWCID, FunctionSignature: c.Input.FunctionSignature,
		}
		var err error
		if got := fingerprint.Generate(in); got != c.Expected {
			err = mismatch(got, c.Expected)
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
	// refuses the document and schemas/v1 alone accepts it.
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
