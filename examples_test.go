package ctis

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// decodeStrict decodes like OpenCTEM's ingest does: unknown members fail.
func decodeStrict(data []byte) (*Report, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var r Report
	if err := dec.Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Every example must validate against the schema, decode strictly into the
// Go types and pass Validate: the three views of the contract agree on it.
func TestExamples(t *testing.T) {
	s := loadSchemaSet(t)
	files, err := filepath.Glob("examples/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no examples: %v", err)
	}
	findingTypes := map[FindingType]bool{}
	for _, name := range files {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if errs := s.validateJSON(raw, "report.json"); len(errs) > 0 {
			t.Errorf("%s: schema: %s", name, strings.Join(errs, "; "))
		}
		r, err := decodeStrict(raw)
		if err != nil {
			t.Errorf("%s: strict decode: %v", name, err)
			continue
		}
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		for _, f := range r.Findings {
			findingTypes[f.Type] = true
		}
	}
	for _, ft := range AllFindingTypes() {
		if !findingTypes[ft] {
			t.Errorf("no example has a %s finding", ft)
		}
	}
}

// The invalid examples document mistakes the schema must catch.
func TestInvalidExamples(t *testing.T) {
	s := loadSchemaSet(t)
	files, _ := filepath.Glob("examples/invalid/*.json")
	if len(files) == 0 {
		t.Fatal("no invalid examples")
	}
	for _, name := range files {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if errs := s.validateJSON(raw, "report.json"); len(errs) == 0 {
			t.Errorf("%s: the schema accepts it", name)
		}
		r, err := decodeStrict(raw)
		if err == nil && r.Validate() == nil {
			t.Errorf("%s: strict decode and Validate both accept it", name)
		}
	}
}
