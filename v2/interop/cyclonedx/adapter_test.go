package cyclonedx

import (
	"reflect"
	"testing"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/importer"
	"github.com/openctemio/ctis/v2/internal/interoptest"
)

const importerFixtures = "testdata/importers"

// TestImporters_Golden pins the output of importer.Parse for every fixture
// (the format is detected; this adapter registers it).
func TestImporters_Golden(t *testing.T) {
	interoptest.ImporterGolden(t, importerFixtures, importer.FormatCycloneDX)
}

// TestImporters_FieldCoverage: every field of every fixture is listed in
// 1.6/import.json, and every mapped field occurs in a fixture.
func TestImporters_FieldCoverage(t *testing.T) {
	interoptest.FieldCoverage(t, importerFixtures, importer.FormatCycloneDX)
}

// TestMappingDocs keeps docs/importers/cyclonedx.md in step with the mapping.
func TestMappingDocs(t *testing.T) {
	interoptest.CompareText(t, "../../../docs/importers/cyclonedx.md", importSpec().Markdown())
}

// TestExportMappingCoverage: 1.6/export.json lists every member the
// exporter can write.
func TestExportMappingCoverage(t *testing.T) {
	interoptest.ExportCoverage(t, exp, reflect.TypeOf(cdxOutBOM{}))
}

func TestRegistered(t *testing.T) {
	if !importer.Registered(importer.FormatCycloneDX) {
		t.Fatal("the adapter did not register sarif")
	}
	if got := Versions(); len(got) != 2 || got[0] != "1.5" || got[1] != "1.6" {
		t.Fatalf("Versions() = %v", got)
	}
}

// TestConformanceVectors runs conformance/interop/cyclonedx/<version>: the upstream
// samples, their CTIS golden files and the passthrough.
func TestConformanceVectors(t *testing.T) {
	for _, v := range Versions() {
		t.Run(v, func(t *testing.T) {
			interoptest.ImportVectors(t, "../../../conformance/interop/cyclonedx/"+v, importer.FormatCycloneDX, v, Namespace, func(r *ctis.Report) ([]byte, error) { return Export(r, nil) })
		})
	}
}
