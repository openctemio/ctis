package cyclonedx

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
	// exp is the mapping the exporter writes (the latest version).
	exp = exportSet.Latest()
)

var (
	importSet = engine.MustLoadFS(mappingFiles, engine.Import, engine.LoadOptions{Hooks: importHooks})
	exportSet = engine.MustLoadFS(mappingFiles, engine.Export, engine.LoadOptions{Hooks: exportHooks, Tables: exportTables})
)

// Versions lists the upstream CycloneDX versions this adapter reads.
func Versions() []string { return importSet.Versions() }

// ExportVersion is the CycloneDX version Export writes.
const ExportVersion = "1.6"

// Namespace is the extensions namespace of the members this adapter keeps
// without mapping them.
const Namespace = "org.ctis.interop.cyclonedx"

func importSpec() importer.Spec { return importer.SpecFromMapping(importSet.Latest()) }
