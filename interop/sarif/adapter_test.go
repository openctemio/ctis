package sarif

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
	interoptest.ImporterGolden(t, importerFixtures, importer.FormatSARIF)
}

// TestImporters_FieldCoverage: every field of every fixture is listed in
// 2.1.0/import.json, and every mapped field occurs in a fixture.
func TestImporters_FieldCoverage(t *testing.T) {
	interoptest.FieldCoverage(t, importerFixtures, importer.FormatSARIF)
}

// TestMappingDocs keeps docs/importers/sarif.md in step with the mapping.
func TestMappingDocs(t *testing.T) {
	interoptest.CompareText(t, "../../docs/importers/sarif.md", importSpec().Markdown())
}

// TestExportMappingCoverage: 2.1.0/export.json lists every member the
// exporter can write.
func TestExportMappingCoverage(t *testing.T) {
	interoptest.ExportCoverage(t, exp, reflect.TypeOf(sarifOutLog{}))
}

func TestRegistered(t *testing.T) {
	if !importer.Registered(importer.FormatSARIF) {
		t.Fatal("the adapter did not register sarif")
	}
	if got := Versions(); len(got) != 1 || got[0] != "2.1.0" {
		t.Fatalf("Versions() = %v", got)
	}
}

// TestConformanceVectors runs conformance/interop/sarif/<version>: the
// upstream samples, their CTIS golden files, the round trips with their
// accepted losses and the passthrough.
func TestConformanceVectors(t *testing.T) {
	for _, v := range Versions() {
		t.Run(v, func(t *testing.T) {
			interoptest.ImportVectors(t, "../../conformance/interop/sarif/"+v, importer.FormatSARIF, v, Namespace,
				func(r *ctis.Report) ([]byte, error) { return Export(r, nil) })
		})
	}
}
