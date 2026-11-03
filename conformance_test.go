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
	results, err := conformance.Run("conformance/v2")
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
		"canonical/asset-key.json", "canonical/asset-value.json", "canonical/domain.json", "canonical/ip.json",
		"canonical/cidr.json", "canonical/service.json", "canonical/origin.json", "canonical/url.json",
		"canonical/purl.json", "canonical/image.json", "canonical/cloud.json", "canonical/certificate.json", "canonical/cpe.json",
		"location-key.json", "preferred-id.json", "fingerprint/fingerprint.json", "fingerprint/secret-digest.json",
		"correlation/correlation.json", "documents", "canonical/repository.json", "vulnerability-id.json",
		"weburl/urls.json", "decode/decode.json", "mapping/vectors.json", "interop-engine/path.json",
		"interop-engine/select.json", "interop-engine/collect.json",
	} {
		if suites[want] == 0 {
			t.Errorf("suite %s ran no vectors", want)
		}
	}
}

// Every example, valid or not, must be listed in the manifest, so a new
// example cannot slip in without its expected result.
func TestConformanceManifestListsEveryExample(t *testing.T) {
	raw, err := os.ReadFile("conformance/v2/documents/manifest.json")
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
		listed[filepath.Clean(filepath.Join("conformance", "v2", "documents", d.File))] = true
	}
	for _, pat := range []string{
		"examples/*.json", "examples/invalid/*.json",
		"conformance/v2/documents/valid/*.json", "conformance/v2/documents/invalid/*.json",
	} {
		files, _ := filepath.Glob(pat)
		if len(files) == 0 {
			t.Errorf("no files match %s", pat)
		}
		for _, f := range files {
			if !listed[filepath.Clean(f)] {
				t.Errorf("%s is not in conformance/v2/documents/manifest.json", f)
			}
		}
	}
}
