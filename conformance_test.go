package ctis_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/openctemio/ctis/v2/internal/conformance"
)

// TestConformanceVectors runs every vector under conformance/ against this
// implementation. Other implementations run the same files.
func TestConformanceVectors(t *testing.T) {
	results, err := conformance.Run("conformance/v1")
	if err != nil {
		t.Fatal(err)
	}
	suites := map[string]int{}
	for _, r := range results {
		suites[r.Suite]++
		if r.Err != "" {
			t.Errorf("%s: %s: %s", r.Suite, r.Name, r.Err)
		}
	}
	for _, want := range []string{
		"canonical/domain.json", "canonical/ip.json", "canonical/host.json", "canonical/repository.json",
		"canonical/url.json", "canonical/other.json", "location-key.json", "preferred-id.json",
		"fingerprint.json", "documents",
	} {
		if suites[want] == 0 {
			t.Errorf("suite %s ran no vectors", want)
		}
	}
}

// Every example, valid or not, must be listed in the manifest, so a new
// example cannot slip in without its expected result.
func TestConformanceManifestListsEveryExample(t *testing.T) {
	raw, err := os.ReadFile("conformance/v1/documents/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Documents []struct {
			File string `json:"file"`
		} `json:"documents"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, d := range m.Documents {
		listed[filepath.Clean(filepath.Join("conformance", "v1", "documents", d.File))] = true
	}
	for _, pat := range []string{
		"examples/*.json", "examples/invalid/*.json",
		"conformance/v1/documents/valid/*.json", "conformance/v1/documents/invalid/*.json",
	} {
		files, _ := filepath.Glob(pat)
		if len(files) == 0 {
			t.Errorf("no files match %s", pat)
		}
		for _, f := range files {
			if !listed[filepath.Clean(f)] {
				t.Errorf("%s is not in conformance/v1/documents/manifest.json", f)
			}
		}
	}
}
