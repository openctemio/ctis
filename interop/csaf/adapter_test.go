package csaf

import (
	"testing"

	"github.com/openctemio/ctis/v2/importer"
	"github.com/openctemio/ctis/v2/internal/interoptest"
)

const importerFixtures = "testdata/importers"

// TestImporters_Golden pins the output of importer.Parse for every fixture
// (the format is detected; this adapter registers it).
func TestImporters_Golden(t *testing.T) {
	interoptest.ImporterGolden(t, importerFixtures, importer.FormatCSAF)
}

// TestImporters_FieldCoverage: every field of every fixture is listed in
// 2.0/import.json, and every mapped field occurs in a fixture.
func TestImporters_FieldCoverage(t *testing.T) {
	interoptest.FieldCoverage(t, importerFixtures, importer.FormatCSAF)
}

// TestMappingDocs keeps docs/importers/csaf.md in step with the mapping.
func TestMappingDocs(t *testing.T) {
	interoptest.CompareText(t, "../../docs/importers/csaf.md", importSpec().Markdown())
}

func TestRegistered(t *testing.T) {
	if !importer.Registered(importer.FormatCSAF) {
		t.Fatal("the adapter did not register sarif")
	}
	if got := Versions(); len(got) != 1 || got[0] != "2.0" {
		t.Fatalf("Versions() = %v", got)
	}
}
