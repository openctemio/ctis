package sarif

import (
	"embed"

	"github.com/openctemio/ctis/v2/importer"
	"github.com/openctemio/ctis/v2/interop/engine"
)

// The mapping files of this adapter, one directory per upstream version
// (docs/interop.md).
//
//go:embed 2.1.0/*.json
var mappingFiles embed.FS

// Hooks are the Go functions of this adapter that the mapping files name for
// the members that are not field to field.
var (
	importHooks = []string{
		"sarif.results", "sarif.severity", "sarif.rule_lookup", "sarif.rule_taxonomy",
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
	importSet = engine.MustSet(load("2.1.0/import.json", importHooks, importTables))
	exportSet = engine.MustSet(load("2.1.0/export.json", exportHooks, exportTables))
	// imp and exp are the mappings of the one upstream version.
	imp = importSet.Latest()
	exp = exportSet.Latest()
)

func load(name string, hooks, tables []string) *engine.Mapping {
	data, err := mappingFiles.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return engine.MustLoad(data, engine.LoadOptions{Hooks: hooks, Tables: tables})
}

// Versions lists the upstream SARIF versions this adapter reads.
func Versions() []string { return importSet.Versions() }

// Namespace is the extensions namespace of the members this adapter keeps
// without mapping them.
const Namespace = "org.ctis.interop.sarif"

func importSpec() importer.Spec { return importer.SpecFromMapping(imp) }
