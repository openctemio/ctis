package sarif

import (
	"embed"

	"github.com/openctemio/ctis/v2/importer"
	"github.com/openctemio/ctis/v2/interop/engine"
)

// The mapping files of this adapter, one directory per upstream version
// (docs/interop.md).
//
//go:embed [0-9]*/*.json
var mappingFiles embed.FS

// Hooks are the Go functions of this adapter that the mapping files name for
// the members that are not field to field.
var (
	importHooks = []string{
		"sarif.results", "sarif.severity", "sarif.rule_lookup", "sarif.rule_taxonomy", "sarif.rule_catalog",
		"sarif.fingerprint", "sarif.suppressions", "sarif.web_exchange", "sarif.code_flows",
		"sarif.provenance",
	}
	exportHooks = []string{
		"sarif.run", "sarif.rules", "sarif.result", "sarif.location", "sarif.suppressions",
		"sarif.code_flow", "sarif.web_exchange", "sarif.provenance",
	}
	importTables = []string{"level_severity", "precision_confidence"}
	exportTables = []string{"severity_level", "severity_score", "confidence_precision", "kind_out"}
)

var (
	// imp and exp are the mappings of the one upstream version.
	imp = importSet.Latest()
	exp = exportSet.Latest()
)

var (
	importSet = engine.MustLoadFS(mappingFiles, engine.Import, engine.LoadOptions{Hooks: importHooks, Tables: importTables})
	exportSet = engine.MustLoadFS(mappingFiles, engine.Export, engine.LoadOptions{Hooks: exportHooks, Tables: exportTables})
)

// Versions lists the upstream SARIF versions this adapter reads.
func Versions() []string { return importSet.Versions() }

// Namespace is the extensions namespace of the members this adapter keeps
// without mapping them.
const Namespace = "org.ctis.interop.sarif"

func importSpec() importer.Spec { return importer.SpecFromMapping(imp) }
