package importer

import (
	"io"

	"github.com/openctemio/ctis/v2"
)

// opengrep JSON output (opengrep scan --json): the semgrep JSON shape, read
// by the semgrep parser under the opengrep tool name. The mapping is
// spec_opengrep.go.

var opengrepEngine = sgEngine{format: FormatOpengrep, name: "opengrep"}

func init() {
	parsers[FormatOpengrep] = parseOpengrep
	tools[FormatOpengrep] = ctis.Tool{Name: "opengrep", Vendor: "Opengrep", InfoURL: "https://github.com/opengrep/opengrep", Techniques: []ctis.Technique{ctis.TechniqueSAST}}
}

func parseOpengrep(b *Builder, r io.Reader) error { return parseSemgrepShape(b, r, opengrepEngine) }
