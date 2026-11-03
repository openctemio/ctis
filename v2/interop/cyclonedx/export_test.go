package cyclonedx

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/importer"
	"github.com/openctemio/ctis/v2/internal/interoptest"
)

var cdxNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func importCycloneDX(t *testing.T, data []byte) *importer.Result {
	t.Helper()
	res, err := importer.Parse(context.Background(), bytes.NewReader(data), importer.Options{Format: importer.FormatCycloneDX, Now: cdxNow})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// TestExportCycloneDXRoundTrip: fixture -> importer -> Export ->
// importer gives the same report and VEX statements, less the accepted
// losses of the sidecar.
func TestExportCycloneDXRoundTrip(t *testing.T) {
	data, err := os.ReadFile("testdata/export/vdr.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	first := importCycloneDX(t, data)
	if len(first.Report.Findings) < 4 || len(first.Report.Dependencies) != 3 {
		t.Fatalf("fixture imported %d findings, %d dependencies", len(first.Report.Findings), len(first.Report.Dependencies))
	}
	out, err := Export(first.Report, nil)
	if err != nil {
		t.Fatal(err)
	}
	interoptest.CheckGolden(t, "export/vdr.golden.cdx.json", out)
	second := importCycloneDX(t, out)
	want := map[string]any{"report": first.Report, "vex": first.VEX, "unmapped": first.Unmapped}
	got := map[string]any{"report": second.Report, "vex": second.VEX, "unmapped": second.Unmapped}
	for _, d := range interoptest.RoundTripDiff(t, want, got, "vdr.losses.json") {
		t.Error(d)
	}
	again, err := Export(first.Report, nil)
	if err != nil || !bytes.Equal(again, out) {
		t.Fatalf("second export differs (err %v)", err)
	}
}

// TestExportCycloneDXFromCTIS exports a CTIS example and reads it back.
func TestExportCycloneDXFromCTIS(t *testing.T) {
	data, err := os.ReadFile("../../../examples/vulnerability-sca.json")
	if err != nil {
		t.Fatal(err)
	}
	var r ctis.Report
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	out, err := Export(&r, &ExportOptions{SerialNumber: "urn:uuid:00000000-0000-4000-8000-000000000001", Timestamp: cdxNow})
	if err != nil {
		t.Fatal(err)
	}
	interoptest.CheckGolden(t, "export/vulnerability-sca.golden.cdx.json", out)
	back := importCycloneDX(t, out)
	var vulns []ctis.Finding
	for _, f := range r.Findings {
		if f.Type == ctis.FindingTypeVulnerability {
			vulns = append(vulns, f)
		}
	}
	want := map[string]any{"findings": vulns, "dependencies": r.Dependencies}
	got := map[string]any{"findings": back.Report.Findings, "dependencies": back.Report.Dependencies}
	for _, d := range interoptest.RoundTripDiff(t, want, got, "ctis-vulnerability-sca.losses.json") {
		t.Error(d)
	}
}
