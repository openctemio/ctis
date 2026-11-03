package ocsf

import (
	"embed"

	"github.com/openctemio/ctis/v2/interop/engine"
)

// The mapping files of this adapter, one directory per upstream version
// (docs/interop.md). OCSF has an export mapping only: this module reads no
// OCSF events.
//
//go:embed 1.3.0/*.json
var mappingFiles embed.FS

// exportHooks are the Go functions of this adapter that the mapping file
// names for the members that are not field to field.
var (
	exportHooks  = []string{"ocsf.event", "ocsf.finding_info", "ocsf.resource", "ocsf.vulnerabilities", "ocsf.compliance", "ocsf.remediation"}
	exportTables = []string{"severity", "status"}
)

var (
	exportSet = engine.MustSet(load("1.3.0/export.json", exportHooks, exportTables))
	exp       = exportSet.Latest()
)

func load(name string, hooks, tables []string) *engine.Mapping {
	data, err := mappingFiles.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return engine.MustLoad(data, engine.LoadOptions{Hooks: hooks, Tables: tables})
}

// Namespace is the extensions namespace of this adapter.
const Namespace = "org.ctis.interop.ocsf"
