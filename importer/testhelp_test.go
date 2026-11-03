package importer

import (
	"strings"

	"github.com/openctemio/ctis/v2"
)

// evidenceText is the text of every raw_text evidence item of a finding.
func evidenceText(f ctis.Finding) string {
	var parts []string
	for _, it := range f.EvidenceItems {
		if it.Kind == ctis.EvidenceKindRawText {
			parts = append(parts, it.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// testReportID is the fixed UUIDv7 of the deterministic tests.
const testReportID = "0192f0a0-0000-7000-8000-000000000001"
