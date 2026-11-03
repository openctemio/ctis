package ocsf

import (
	"reflect"
	"testing"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/internal/interoptest"
)

// TestExportMappingCoverage: 1.3.0/export.json lists every member the
// exporter can write.
func TestExportMappingCoverage(t *testing.T) {
	interoptest.ExportCoverage(t, exp, reflect.TypeOf([]Event{}))
}

// TestConformanceVectors runs conformance/interop/ocsf/1.3.0: CTIS documents
// and the OCSF events they export to.
func TestConformanceVectors(t *testing.T) {
	interoptest.ExportVectors(t, "../../conformance/interop/ocsf/"+Version, "ocsf", Version,
		func(r *ctis.Report) ([]byte, error) { return Export(r, nil) })
}
