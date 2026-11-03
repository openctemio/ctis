package ocsf

import (
	"reflect"
	"testing"

	"github.com/openctemio/ctis/v2/internal/interoptest"
)

// TestExportMappingCoverage: 1.3.0/export.json lists every member the
// exporter can write.
func TestExportMappingCoverage(t *testing.T) {
	interoptest.ExportCoverage(t, exp, reflect.TypeOf([]Event{}))
}
