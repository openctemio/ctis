package ocsf

import (
	"embed"

	"github.com/openctemio/ctis/v2/interop/engine"
)

// The mapping files of this adapter, one directory per upstream version
// (docs/interop.md). OCSF has an export mapping only: this module reads no
// OCSF events.
//
//go:embed [0-9]*/*.json
var mappingFiles embed.FS

// exportHooks are the Go functions of this adapter that the mapping file
// names for the members that are not field to field.
var (
	exportHooks  = []string{"ocsf.event", "ocsf.finding_info", "ocsf.resource", "ocsf.vulnerabilities", "ocsf.compliance", "ocsf.remediation"}
	exportTables = []string{"severity", "status"}
)

var (
	exp = exportSet.Latest()
)

var (
	exportSet = engine.MustLoadFS(mappingFiles, engine.Export, engine.LoadOptions{Hooks: exportHooks, Tables: exportTables})
)

// Namespace is the extensions namespace of this adapter.
const Namespace = "org.ctis.interop.ocsf"
