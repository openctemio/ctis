package openvex

import (
	"testing"

	"github.com/openctemio/ctis/v2/importer"
	"github.com/openctemio/ctis/v2/internal/interoptest"
)

const importerFixtures = "testdata/importers"

// TestImporters_Golden pins the output of importer.Parse for every fixture
// (the format is detected; this adapter registers it).
func TestImporters_Golden(t *testing.T) {
	interoptest.ImporterGolden(t, importerFixtures, importer.FormatOpenVEX)
}

// TestImporters_FieldCoverage: every field of every fixture is listed in
// 0.2.0/import.json, and every mapped field occurs in a fixture.
func TestImporters_FieldCoverage(t *testing.T) {
	interoptest.FieldCoverage(t, importerFixtures, importer.FormatOpenVEX)
}

// TestMappingDocs keeps docs/importers/openvex.md in step with the mapping.
func TestMappingDocs(t *testing.T) {
	interoptest.CompareText(t, "../../../docs/importers/openvex.md", importSpec().Markdown())
}

func TestRegistered(t *testing.T) {
	if !importer.Registered(importer.FormatOpenVEX) {
		t.Fatal("the adapter did not register sarif")
	}
	if got := Versions(); len(got) != 1 || got[0] != "0.2.0" {
		t.Fatalf("Versions() = %v", got)
	}
}

// TestConformanceVectors runs conformance/interop/openvex/<version>: the upstream
// samples, their CTIS golden files and the passthrough.
func TestConformanceVectors(t *testing.T) {
	for _, v := range Versions() {
		t.Run(v, func(t *testing.T) {
			interoptest.ImportVectors(t, "../../../conformance/interop/openvex/"+v, importer.FormatOpenVEX, v, Namespace, nil)
		})
	}
}
