package cyclonedx

import (
	"embed"

	"github.com/openctemio/ctis/v2/importer"
	"github.com/openctemio/ctis/v2/interop/engine"
)

// The mapping files of this adapter, one directory per upstream version
// (docs/interop.md).
//
//go:embed 1.5/*.json 1.6/*.json
var mappingFiles embed.FS

// Hooks are the Go functions of this adapter that the mapping files name for
// the members that are not field to field.
var (
	importHooks = []string{
		"cyclonedx.document", "cyclonedx.components", "cyclonedx.graph",
		"cyclonedx.vulnerabilities", "cyclonedx.vex",
	}
	exportHooks = []string{
		"cyclonedx.document", "cyclonedx.components", "cyclonedx.graph",
		"cyclonedx.vulnerabilities", "cyclonedx.vex",
	}
	exportTables = []string{"hash_alg", "justification", "justification_of_ctis", "vex_state", "cvss_method", "rating_severity"}
)

var (
	importSet = engine.MustSet(
		load("1.5/import.json", importHooks, nil),
		load("1.6/import.json", importHooks, nil),
	)
	exportSet = engine.MustSet(load("1.6/export.json", exportHooks, exportTables))
	// exp is the mapping the exporter writes (the latest version).
	exp = exportSet.Latest()
)

func load(name string, hooks, tables []string) *engine.Mapping {
	data, err := mappingFiles.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return engine.MustLoad(data, engine.LoadOptions{Hooks: hooks, Tables: tables})
}

// Versions lists the upstream CycloneDX versions this adapter reads.
func Versions() []string { return importSet.Versions() }

// ExportVersion is the CycloneDX version Export writes.
const ExportVersion = "1.6"

// Namespace is the extensions namespace of the members this adapter keeps
// without mapping them.
const Namespace = "org.ctis.interop.cyclonedx"

func importSpec() importer.Spec { return importer.SpecFromMapping(importSet.Latest()) }
