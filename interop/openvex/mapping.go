package openvex

import (
	"bytes"
	"context"
	"embed"

	"github.com/openctemio/ctis/v2/importer"
	"github.com/openctemio/ctis/v2/interop/engine"
)

// The mapping files of this adapter, one directory per upstream version
// (docs/interop.md).
//
//go:embed [0-9]*/*.json
var mappingFiles embed.FS

// importHooks are the Go functions of this adapter that the mapping files
// name for the members that are not field to field.
var importHooks = []string{"openvex.document", "openvex.statements"}

var importSet = engine.MustLoadFS(mappingFiles, engine.Import, engine.LoadOptions{Hooks: importHooks})

// Versions lists the upstream OpenVEX versions this adapter reads.
func Versions() []string { return importSet.Versions() }

// Namespace is the extensions namespace of the members this adapter keeps
// without mapping them.
const Namespace = "org.ctis.interop.openvex"

func importSpec() importer.Spec { return importer.SpecFromMapping(importSet.Latest()) }

// Import reads a OpenVEX JSON document through importer.Parse (the limits,
// the minimum severity and the secret masking apply): the report, the VEX
// statements, the counts and the issues. A nil opts uses the defaults.
func Import(data []byte, opts *importer.Options) (*importer.Result, error) {
	o := importer.Options{}
	if opts != nil {
		o = *opts
	}
	o.Format = importer.FormatOpenVEX
	return importer.Parse(context.Background(), bytes.NewReader(data), o)
}

// collect selects the mapping of the document's version and keeps the
// members it does not list under the report's extensions.
func collect(b *importer.Builder, data []byte) error {
	m, err := importSet.Select(data)
	if err != nil {
		return &importer.ParseError{Format: importer.FormatOpenVEX, Msg: err.Error(), Err: importer.ErrUnknownFormat}
	}
	if b.Options().NoPassthrough {
		return nil
	}
	pt, err := m.Collect(data)
	if err != nil {
		return &importer.ParseError{Format: importer.FormatOpenVEX, Msg: err.Error(), Err: importer.ErrMalformed}
	}
	m.Store(&b.Result().Report.Extensions, pt.DocExtension())
	return nil
}
