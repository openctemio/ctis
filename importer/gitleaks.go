package importer

import (
	"io"

	"github.com/openctemio/ctis"
)

// gitleaks JSON report: an array of leak records. gitleaks and every
// gitleaks-compatible scanner (betterleaks) write the same shape, so one
// parser (parseLeaks, leaks.go) reads them all; Detect names the shape
// gitleaks, and the betterleaks format is the same parser under the
// betterleaks tool name, chosen explicitly. The mapping is spec_gitleaks.go.

func init() {
	parsers[FormatGitleaks] = parseGitleaks
	tools[FormatGitleaks] = ctis.Tool{Name: "gitleaks", Vendor: "Gitleaks", InfoURL: "https://github.com/gitleaks/gitleaks", Capabilities: []string{"secret"}}
}

func parseGitleaks(b *builder, r io.Reader) error {
	return parseLeaks(b, r, FormatGitleaks, "gitleaks")
}
