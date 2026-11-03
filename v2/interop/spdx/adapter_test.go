package spdx

import (
	"testing"

	"github.com/openctemio/ctis/v2/importer"
	"github.com/openctemio/ctis/v2/internal/interoptest"
)

const importerFixtures = "testdata/importers"

// TestImporters_Golden pins the output of importer.Parse for every fixture
// (the format is detected; this adapter registers it).
func TestImporters_Golden(t *testing.T) {
	interoptest.ImporterGolden(t, importerFixtures, importer.FormatSPDX)
}

// TestImporters_FieldCoverage: every field of every fixture is listed in
// 2.3/import.json, and every mapped field occurs in a fixture.
func TestImporters_FieldCoverage(t *testing.T) {
	interoptest.FieldCoverage(t, importerFixtures, importer.FormatSPDX)
}

// TestMappingDocs keeps docs/importers/spdx.md in step with the mapping.
func TestMappingDocs(t *testing.T) {
	interoptest.CompareText(t, "../../../docs/importers/spdx.md", importSpec().Markdown())
}

func TestRegistered(t *testing.T) {
	if !importer.Registered(importer.FormatSPDX) {
		t.Fatal("the adapter did not register sarif")
	}
	if got := Versions(); len(got) != 1 || got[0] != "2.3" {
		t.Fatalf("Versions() = %v", got)
	}
}

// TestConformanceVectors runs conformance/interop/spdx/<version>: the upstream
// samples, their CTIS golden files and the passthrough.
func TestConformanceVectors(t *testing.T) {
	for _, v := range Versions() {
		t.Run(v, func(t *testing.T) {
			interoptest.ImportVectors(t, "../../../conformance/interop/spdx/"+v, importer.FormatSPDX, v, Namespace, nil)
		})
	}
}
